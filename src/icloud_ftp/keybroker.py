"""OS-neutral Key Broker API and provider adapters.

The gateway uses only :class:`KeyBrokerClient`. Hardware access remains in a
host process. Linux Unix sockets and Windows localhost mTLS share the same JSON
envelope and HTTP endpoints.
"""

from __future__ import annotations

import abc
import base64
from collections import deque
import hashlib
import hmac
import http.client
import json
import logging
import os
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AUDIT = logging.getLogger("icloud_ftp.keybroker.audit")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected base64 string")
    return base64.b64decode(value, validate=True)


@dataclass(frozen=True)
class ProviderCapabilities:
    tier: int
    tpm: bool
    hardware_kek: bool
    pcr_sealing: bool
    attestation: str
    key_exportable_to_broker_memory: bool


class KeyProvider(abc.ABC):
    name: str
    key_id: str
    capabilities: ProviderCapabilities

    @abc.abstractmethod
    def wrap(self, plaintext_key: bytes, context: bytes) -> dict[str, Any]: ...

    @abc.abstractmethod
    def unwrap(self, envelope: dict[str, Any], context: bytes) -> bytes: ...

    @abc.abstractmethod
    def sign(self, message: bytes) -> dict[str, Any]: ...

    def attest(self, nonce: bytes) -> dict[str, Any]:
        raise NotImplementedError("attestation is not supported by this provider")


class SoftwareProvider(KeyProvider):
    """Development/recovery provider, never the production default."""

    name = "software"
    capabilities = ProviderCapabilities(0, False, False, False, "none", True)

    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise ValueError("software KEK must be 32 bytes")
        self._kek = kek
        self.key_id = "sw-" + hashlib.sha256(kek).hexdigest()[:24]

    def wrap(self, plaintext_key: bytes, context: bytes) -> dict[str, Any]:
        nonce = os.urandom(12)
        return {
            "version": 1,
            "key_id": self.key_id,
            "algorithm": "AES-256-GCM",
            "provider": self.name,
            "nonce": _b64(nonce),
            "wrapped_key": _b64(AESGCM(self._kek).encrypt(nonce, plaintext_key, context)),
            "metadata": {},
        }

    def unwrap(self, envelope: dict[str, Any], context: bytes) -> bytes:
        if envelope.get("key_id") != self.key_id:
            raise ValueError("wrapped key belongs to another KEK")
        return AESGCM(self._kek).decrypt(
            _unb64(envelope["nonce"]), _unb64(envelope["wrapped_key"]), context
        )

    def sign(self, message: bytes) -> dict[str, Any]:
        # Development-only symmetric audit signature. Production providers
        # should return a hardware-backed asymmetric signature.
        return {
            "key_id": self.key_id,
            "algorithm": "HMAC-SHA-256",
            "signature": _b64(hmac.digest(self._kek, message, "sha256")),
        }


class LinuxTpmUnsealProvider(SoftwareProvider):
    """Linux reference adapter: TPM-unseal a KEK into broker-only memory.

    This adapter deliberately does not claim that the KEK remains
    non-exportable: it exists in this host broker's memory after unseal. A true
    non-exportable TPM/HSM provider can implement :class:`KeyProvider` without
    changing the gateway protocol or envelope format.
    """

    name = "linux-tpm-unseal"

    def __init__(
        self,
        context_file: Path,
        *,
        tpm2_unseal: str = "tpm2_unseal",
        pcr_policy: bool = True,
    ):
        result = subprocess.run(
            [tpm2_unseal, "-c", str(context_file)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        kek = result.stdout
        if len(kek) != 32:
            raise RuntimeError("TPM unsealed value must be exactly 32 bytes")
        super().__init__(kek)
        self.key_id = "tpm-" + hashlib.sha256(kek).hexdigest()[:24]
        self.capabilities = ProviderCapabilities(
            1, True, True, pcr_policy, "limited", True
        )


class LinuxTpmRsaProvider(KeyProvider):
    """Non-exportable Linux TPM RSA-OAEP wrapping adapter.

    The TPM private key never enters broker memory. The expected public PEM is
    compared with ``tpm2_readpublic`` at startup so a replaced persistent
    handle is rejected.
    """

    name = "linux-tpm"
    capabilities = ProviderCapabilities(1, True, True, False, "none", False)

    def __init__(
        self,
        key_context: str,
        expected_public_key: Path,
        *,
        rsaencrypt: str = "tpm2_rsaencrypt",
        rsadecrypt: str = "tpm2_rsadecrypt",
        readpublic: str = "tpm2_readpublic",
    ):
        self.key_context = key_context
        self.rsaencrypt = rsaencrypt
        self.rsadecrypt = rsadecrypt
        expected = expected_public_key.resolve().read_bytes()
        with tempfile.TemporaryDirectory() as temporary_directory:
            actual = Path(temporary_directory) / "observed-public.pem"
            subprocess.run(
                [readpublic, "-c", key_context, "-f", "pem", "-o", str(actual)],
                check=True,
                capture_output=True,
                timeout=30,
            )
            observed = actual.read_bytes()
        if observed.strip() != expected.strip():
            raise RuntimeError("TPM key context does not match expected public key")
        self.key_id = "tpm-rsa-" + hashlib.sha256(expected).hexdigest()[:24]

    @staticmethod
    def _label(context: bytes) -> str:
        return hashlib.sha256(context).hexdigest()

    def wrap(self, plaintext_key: bytes, context: bytes) -> dict[str, Any]:
        result = subprocess.run(
            [
                self.rsaencrypt,
                "-c",
                self.key_context,
                "-s",
                "oaep",
                "-g",
                "sha256",
                "-l",
                self._label(context),
            ],
            input=plaintext_key,
            check=True,
            capture_output=True,
            timeout=30,
        )
        return {
            "version": 1,
            "key_id": self.key_id,
            "algorithm": "RSA-OAEP-SHA256",
            "provider": self.name,
            "wrapped_key": _b64(result.stdout),
            "metadata": {"context_sha256": self._label(context)},
        }

    def unwrap(self, envelope: dict[str, Any], context: bytes) -> bytes:
        if envelope.get("key_id") != self.key_id:
            raise ValueError("wrapped key belongs to another TPM key")
        if envelope.get("metadata", {}).get("context_sha256") != self._label(context):
            raise ValueError("wrapped key context mismatch")
        result = subprocess.run(
            [
                self.rsadecrypt,
                "-c",
                self.key_context,
                "-s",
                "oaep",
                "-g",
                "sha256",
                "-l",
                self._label(context),
            ],
            input=_unb64(envelope["wrapped_key"]),
            check=True,
            capture_output=True,
            timeout=30,
        )
        if len(result.stdout) != 32:
            raise RuntimeError("TPM returned an invalid DEK length")
        return result.stdout

    def sign(self, message: bytes) -> dict[str, Any]:
        raise NotImplementedError(
            "this wrapping key is decrypt-only; configure a separate TPM signing provider"
        )


class ExternalProvider(KeyProvider):
    """Adapter for Windows CNG or HSM helpers speaking JSON over stdio."""

    def __init__(self, executable: Path, provider_name: str):
        self.executable = executable
        self.name = provider_name
        health = self._call("health", {})
        self.key_id = health["key_id"]
        self.capabilities = ProviderCapabilities(**health["capabilities"])

    def _call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = json.dumps({"operation": operation, **payload}).encode("utf-8")
        result = subprocess.run(
            [str(self.executable)],
            input=request,
            capture_output=True,
            check=True,
            timeout=30,
        )
        response = json.loads(result.stdout.decode("utf-8"))
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "external key provider failed"))
        return response["result"]

    def wrap(self, plaintext_key: bytes, context: bytes) -> dict[str, Any]:
        return self._call(
            "wrap", {"plaintext_key": _b64(plaintext_key), "context": _b64(context)}
        )

    def unwrap(self, envelope: dict[str, Any], context: bytes) -> bytes:
        result = self._call(
            "unwrap", {"envelope": envelope, "context": _b64(context)}
        )
        return _unb64(result["plaintext_key"])

    def sign(self, message: bytes) -> dict[str, Any]:
        return self._call("sign", {"message": _b64(message)})

    def attest(self, nonce: bytes) -> dict[str, Any]:
        return self._call("attest", {"nonce": _b64(nonce)})


class WindowsCngProvider(ExternalProvider):
    def __init__(self, executable: Path):
        super().__init__(executable, "windows-cng")


class HsmProvider(ExternalProvider):
    def __init__(self, executable: Path):
        super().__init__(executable, "hsm")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class KeyBrokerClient:
    def __init__(
        self,
        endpoint: str,
        *,
        cafile: Path | None = None,
        certfile: Path | None = None,
        keyfile: Path | None = None,
    ):
        self.endpoint = endpoint
        self.cafile, self.certfile, self.keyfile = cafile, certfile, keyfile
        health = self.health()
        self.key_id = health["key_id"]
        self.provider = health["provider"]
        self.capabilities = health["capabilities"]

    def _connection(self):
        if self.endpoint.startswith("unix://"):
            return UnixHTTPConnection(self.endpoint.removeprefix("unix://"))
        parsed = urlsplit(self.endpoint)
        if parsed.scheme != "https" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
            "host.docker.internal",
        }:
            raise ValueError(
                "TCP Key Broker must use local-host HTTPS with mTLS"
            )
        context = ssl.create_default_context(cafile=self.cafile)
        if not self.certfile or not self.keyfile:
            raise ValueError("TCP Key Broker requires a client certificate and key")
        context.load_cert_chain(self.certfile, self.keyfile)
        return http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 9443, context=context, timeout=30
        )

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        connection = self._connection()
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
            )
            response = connection.getresponse()
            data = response.read()
            if response.status >= 400:
                raise RuntimeError(f"Key Broker {response.status}: {data.decode('utf-8', 'replace')}")
            return json.loads(data.decode("utf-8"))
        finally:
            connection.close()

    def health(self) -> dict:
        return self._call("GET", "/v1/health")

    def wrap(self, plaintext_key: bytes, context: bytes) -> dict:
        return self._call(
            "POST",
            "/v1/keys/wrap",
            {"plaintext_key": _b64(plaintext_key), "context": _b64(context)},
        )["envelope"]

    def unwrap(self, envelope: dict, context: bytes) -> bytes:
        result = self._call(
            "POST",
            "/v1/keys/unwrap",
            {"envelope": envelope, "context": _b64(context)},
        )
        return _unb64(result["plaintext_key"])

    def sign(self, message: bytes) -> dict:
        return self._call("POST", "/v1/sign", {"message": _b64(message)})

    def attest(self, nonce: bytes) -> dict:
        return self._call("POST", "/v1/attest", {"nonce": _b64(nonce)})


class KeyBrokerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "iCloudKeyBroker/1"

    @property
    def provider(self) -> KeyProvider:
        return self.server.provider

    def _json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024 * 1024:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/v1/health":
            self._send(404, {"error": "not found"})
            return
        self._send(
            200,
            {
                "status": "ok",
                "provider": self.provider.name,
                "key_id": self.provider.key_id,
                "capabilities": self.provider.capabilities.__dict__,
            },
        )

    def do_POST(self) -> None:
        started = time.time()
        context_hash = None
        success = False
        if not self.server.admit_request():
            self._send(429, {"error": "key broker rate or concurrency limit exceeded"})
            AUDIT.warning(
                json.dumps(
                    {
                        "event": "key_broker_call",
                        "path": self.path,
                        "provider": self.provider.name,
                        "key_id": self.provider.key_id,
                        "success": False,
                        "reason": "rate_limited",
                    },
                    sort_keys=True,
                )
            )
            return
        try:
            request = self._json()
            if "context" in request:
                context_hash = hashlib.sha256(_unb64(request["context"])).hexdigest()
            if self.path == "/v1/keys/wrap":
                result = {
                    "envelope": self.provider.wrap(
                        _unb64(request["plaintext_key"]), _unb64(request["context"])
                    )
                }
            elif self.path == "/v1/keys/unwrap":
                result = {
                    "plaintext_key": _b64(
                        self.provider.unwrap(request["envelope"], _unb64(request["context"]))
                    )
                }
            elif self.path == "/v1/sign":
                result = self.provider.sign(_unb64(request["message"]))
            elif self.path == "/v1/attest":
                result = self.provider.attest(_unb64(request["nonce"]))
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(200, result)
            success = True
        except NotImplementedError as error:
            self._send(501, {"error": str(error)})
            success = False
        except Exception as error:
            self._send(400, {"error": str(error)})
            success = False
        finally:
            self.server.release_request()
            AUDIT.info(
                json.dumps(
                    {
                        "event": "key_broker_call",
                        "path": self.path,
                        "provider": self.provider.name,
                        "key_id": self.provider.key_id,
                        "context_sha256": context_hash,
                        "success": success,
                        "duration_ms": int((time.time() - started) * 1000),
                    },
                    sort_keys=True,
                )
            )

    def log_message(self, format: str, *args) -> None:
        pass


class KeyBrokerPolicy:
    """Shared bounded-work and sliding-window policy for all transports."""

    def _init_policy(
        self, *, max_concurrent: int = 8, max_requests_per_minute: int = 600
    ) -> None:
        if max_concurrent < 1 or max_requests_per_minute < 1:
            raise ValueError("Key Broker limits must be positive")
        self._operation_slots = threading.BoundedSemaphore(max_concurrent)
        self._request_times: deque[float] = deque()
        self._request_times_lock = threading.Lock()
        self._max_requests_per_minute = max_requests_per_minute

    def admit_request(self) -> bool:
        now = time.monotonic()
        with self._request_times_lock:
            cutoff = now - 60
            while self._request_times and self._request_times[0] <= cutoff:
                self._request_times.popleft()
            if len(self._request_times) >= self._max_requests_per_minute:
                return False
            if not self._operation_slots.acquire(blocking=False):
                return False
            self._request_times.append(now)
            return True

    def release_request(self) -> None:
        self._operation_slots.release()


if hasattr(socketserver, "UnixStreamServer"):
    class UnixKeyBrokerServer(  # type: ignore[misc]
        KeyBrokerPolicy, socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        daemon_threads = True

        def __init__(
            self,
            path: Path,
            provider: KeyProvider,
            *,
            mode: int = 0o660,
            max_concurrent: int = 8,
            max_requests_per_minute: int = 600,
        ):
            path = path.resolve()
            if path.exists():
                path.unlink()
            path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            self.provider = provider
            self.socket_path = path
            self._init_policy(
                max_concurrent=max_concurrent,
                max_requests_per_minute=max_requests_per_minute,
            )
            super().__init__(str(path), KeyBrokerHandler)
            path.chmod(mode)

        def server_close(self) -> None:
            super().server_close()
            self.socket_path.unlink(missing_ok=True)
else:
    class UnixKeyBrokerServer:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("Unix Key Broker sockets are unavailable on Windows")


class TcpKeyBrokerServer(KeyBrokerPolicy, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address,
        provider: KeyProvider,
        *,
        cafile: Path,
        certfile: Path,
        keyfile: Path,
        max_concurrent: int = 8,
        max_requests_per_minute: int = 600,
    ):
        host = address[0]
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("TCP Key Broker may only bind to localhost")
        self.provider = provider
        self._init_policy(
            max_concurrent=max_concurrent,
            max_requests_per_minute=max_requests_per_minute,
        )
        super().__init__(address, KeyBrokerHandler)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile, keyfile)
        context.load_verify_locations(cafile)
        context.verify_mode = ssl.CERT_REQUIRED
        self.socket = context.wrap_socket(self.socket, server_side=True)
