"""Post-quantum, chunked encrypted storage for a plaintext virtual drive."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import posixpath
import sqlite3
import struct
import tempfile
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .backend import DriveBackend, Entry
from .state import StateDatabase

LEGACY_MAGIC = b"ICFTP01\0"
CAS_MAGIC = b"ICCAS03\0"
HEADER = struct.Struct(">8s12s16s")
METADATA_LENGTH = struct.Struct(">I")
IO_CHUNK_SIZE = 1024 * 1024
SUPPORTED_KEMS = {"ML-KEM-768", "ML-KEM-1024"}


def _derive_recovery_private(root_secret: bytes, kem_name: str):
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b"icloud-webdav-root-v3",
        info=b"ml-kem-seed-v1/" + kem_name.encode("ascii"),
    ).derive(root_secret)
    key_type = (
        mlkem.MLKEM768PrivateKey
        if kem_name == "ML-KEM-768"
        else mlkem.MLKEM1024PrivateKey
    )
    return key_type.from_seed_bytes(seed)


def create_recovery_public_bundle(path: Path, *, kem: str = "ML-KEM-768") -> str:
    """Create public recovery material and return the one-time offline secret.

    Secret splitting is intentionally not implemented here. The returned hex
    value must be split on an air-gapped system using an independently audited
    organizational recovery tool.
    """
    if kem not in SUPPORTED_KEMS:
        raise ValueError(f"unsupported KEM: {kem}")
    path = path.expanduser().resolve()
    if path.exists():
        raise FileExistsError(path)
    root = os.urandom(32)
    private = _derive_recovery_private(root, kem)
    x_private = x25519.X25519PrivateKey.from_private_bytes(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"icloud-webdav-root-v3",
            info=b"x25519-static-v1",
        ).derive(root)
    )
    bundle = {
        "version": 1,
        "kem": kem,
        "ml_kem_public": _b64(private.public_key().public_bytes_raw()),
        "x25519_public": _b64(x_private.public_key().public_bytes_raw()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return root.hex()


def load_recovery_public_bundle(path: Path) -> dict[str, Any]:
    bundle = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    if bundle.get("version") != 1 or bundle.get("kem") not in SUPPORTED_KEMS:
        raise ValueError("invalid recovery public bundle")
    kem_name = bundle["kem"]
    key_type = (
        mlkem.MLKEM768PublicKey
        if kem_name == "ML-KEM-768"
        else mlkem.MLKEM1024PublicKey
    )
    return {
        "kem": kem_name,
        "ml_kem_public": key_type.from_public_bytes(_unb64(bundle["ml_kem_public"])),
        "x25519_public": x25519.X25519PublicKey.from_public_bytes(
            _unb64(bundle["x25519_public"])
        ),
    }


def initialize_key(path: Path) -> Path:
    """Create a 256-bit root secret without overwriting an existing key."""
    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"encryption key already exists: {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if os.name != "nt":
        path.chmod(0o600)
    return path


def load_key(path: Path) -> bytes:
    try:
        key = path.expanduser().resolve().read_bytes()
    except FileNotFoundError as error:
        raise FileNotFoundError(
            f"encryption key not found: {path}; run `icloud-webdav encryption-init`"
        ) from error
    if len(key) != 32:
        raise ValueError(f"encryption root secret must be exactly 32 bytes: {path}")
    return key


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid key capsule field")
    return base64.b64decode(value, validate=True)


class EncryptedBackend:
    """Expose plaintext paths while iCloud stores encrypted CAS objects.

    Plaintext is buffered one chunk at a time in memory and is never written
    to disk. Each unique chunk and each version manifest has a random
    AES-256-GCM DEK. ML-KEM wraps every DEK; an optional X25519 shared secret
    can be combined with ML-KEM through HKDF-SHA256.
    """

    def __init__(
        self,
        backend: DriveBackend,
        *,
        key: bytes | None,
        key_broker=None,
        recovery_public: dict[str, Any] | None = None,
        database: str | Path,
        vault_folder: str = ".icloud-ftp-vault",
        strict_plaintext: bool = True,
        kem: str = "ML-KEM-768",
        hybrid_x25519: bool = False,
        chunk_size: int = 8 * 1024 * 1024,
        retention_days: int = 30,
        small_versions: int = 10,
        medium_versions: int = 5,
        large_versions: int = 3,
        medium_threshold: int = 100 * 1024 * 1024,
        large_threshold: int = 1024 * 1024 * 1024,
        capacity_limit: int = 0,
        gc_interval: int = 24 * 60 * 60,
        orphan_grace: int = 24 * 60 * 60,
        reconcile_interval: int = 60,
        missing_grace: int = 60,
        missing_observations: int = 2,
    ):
        if key is not None and len(key) != 32:
            raise ValueError("recovery root secret must be 32 bytes")
        if key is None and key_broker is None:
            raise ValueError("a Key Broker is required outside recovery/test mode")
        if key is None and recovery_public is None:
            raise ValueError("normal mode requires a recovery public bundle")
        if kem not in SUPPORTED_KEMS:
            raise ValueError(f"unsupported KEM: {kem}")
        if not vault_folder or "/" in vault_folder or "\\" in vault_folder:
            raise ValueError("vault_folder must be one path component")
        if not 4 * 1024 * 1024 <= chunk_size <= 16 * 1024 * 1024:
            raise ValueError("chunk_size must be between 4 MiB and 16 MiB")
        if min(retention_days, small_versions, medium_versions, large_versions) < 0:
            raise ValueError("retention values cannot be negative")
        if medium_threshold <= 0 or large_threshold <= medium_threshold:
            raise ValueError("retention size thresholds are invalid")
        self.backend = backend
        self.root_secret = key
        self.key_broker = key_broker
        self.vault_folder = vault_folder
        self.vault_path = f"/{vault_folder}"
        self.objects_path = f"{self.vault_path}/objects"
        self.manifests_path = f"{self.vault_path}/manifests"
        self.keys_path = f"{self.vault_path}/keys"
        self.metadata_path = f"{self.vault_path}/metadata"
        self.strict_plaintext = strict_plaintext
        self.kem = recovery_public["kem"] if recovery_public else kem
        self.hybrid_x25519 = hybrid_x25519
        self.chunk_size = chunk_size
        self.retention_days = retention_days
        self.small_versions = small_versions
        self.medium_versions = medium_versions
        self.large_versions = large_versions
        self.medium_threshold = medium_threshold
        self.large_threshold = large_threshold
        self.capacity_limit = max(0, capacity_limit)
        self.gc_interval = max(60, gc_interval)
        self.orphan_grace = max(60, orphan_grace)
        self.reconcile_interval = max(0, reconcile_interval)
        self.missing_grace = max(0, missing_grace)
        self.missing_observations = max(1, missing_observations)
        self._last_reconcile = 0.0
        self._lock = threading.RLock()
        self._kem_private = (
            _derive_recovery_private(key, self.kem) if key is not None else None
        )
        self._kem_public = (
            recovery_public["ml_kem_public"]
            if recovery_public
            else self._kem_private.public_key()
        )
        self._x25519_private = (
            x25519.X25519PrivateKey.from_private_bytes(
                self._derive(b"x25519-static-v1", 32)
            )
            if key is not None
            else None
        )
        self._x25519_public = (
            recovery_public["x25519_public"]
            if recovery_public
            else self._x25519_private.public_key()
        )
        self.db = StateDatabase(database)
        self._create_schema()
        self._check_key()
        self._migrate_legacy_database()
        self._ready = False

    def _create_schema(self) -> None:
        with self.db.transaction():
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS cas_directories (
                    path TEXT PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS cas_chunks (
                    id TEXT PRIMARY KEY,
                    remote_name TEXT NOT NULL UNIQUE,
                    key_name TEXT NOT NULL UNIQUE,
                    size BIGINT NOT NULL,
                    stored_size BIGINT NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    created DOUBLE PRECISION NOT NULL,
                    UNIQUE(size, sha256, sha512)
                );
                CREATE TABLE IF NOT EXISTS cas_manifests (
                    id TEXT PRIMARY KEY,
                    remote_name TEXT NOT NULL UNIQUE,
                    key_name TEXT,
                    format_version INTEGER NOT NULL,
                    size BIGINT NOT NULL,
                    stored_size BIGINT NOT NULL,
                    sha256 TEXT NOT NULL,
                    sha512 TEXT NOT NULL,
                    created DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cas_manifest_chunks (
                    manifest_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    chunk_id TEXT NOT NULL,
                    plain_size BIGINT NOT NULL,
                    PRIMARY KEY(manifest_id, position)
                );
                CREATE TABLE IF NOT EXISTS cas_files (
                    path TEXT PRIMARY KEY,
                    current_manifest TEXT NOT NULL UNIQUE,
                    modified DOUBLE PRECISION NOT NULL,
                    version INTEGER NOT NULL,
                    origin TEXT NOT NULL,
                    generation TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cas_versions (
                    path TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    manifest_id TEXT NOT NULL UNIQUE,
                    modified DOUBLE PRECISION NOT NULL,
                    archived DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY(path, version)
                );
                CREATE TABLE IF NOT EXISTS cas_deleted (
                    path TEXT PRIMARY KEY,
                    deleted DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cas_uploads (
                    id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    sha512 TEXT NOT NULL DEFAULT '',
                    manifest_id TEXT,
                    error TEXT,
                    created DOUBLE PRECISION NOT NULL,
                    updated DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cas_upload_chunks (
                    upload_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    chunk_id TEXT NOT NULL,
                    PRIMARY KEY(upload_id, position)
                );
                CREATE TABLE IF NOT EXISTS cas_key_rewrap (
                    object_id TEXT NOT NULL,
                    new_key_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    updated DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY(object_id, new_key_id)
                );
                CREATE TABLE IF NOT EXISTS cas_missing_observations (
                    path TEXT PRIMARY KEY,
                    first_seen DOUBLE PRECISION NOT NULL,
                    observations INTEGER NOT NULL,
                    last_seen DOUBLE PRECISION NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def _check_key(self) -> None:
        fingerprint = "recovery:" + hashlib.sha256(
            self._kem_public.public_bytes_raw()
        ).hexdigest()
        legacy_fingerprint = (
            hashlib.sha256(self.root_secret).hexdigest()
            if self.root_secret is not None
            else None
        )
        row = self.db.execute(
            "SELECT value FROM metadata WHERE key='key_fingerprint'"
        ).fetchone()
        if row and row[0] not in {fingerprint, legacy_fingerprint}:
            raise ValueError("encryption key does not match the gateway database")
        with self.db.transaction():
            self.db.execute(
                "INSERT INTO metadata(key, value) VALUES('key_fingerprint', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (fingerprint,),
            )

    def _migrate_legacy_database(self) -> None:
        """Import v1 pathname mappings without rewriting their ciphertext."""
        done = self.db.execute(
            "SELECT value FROM metadata WHERE key='cas_legacy_imported'"
        ).fetchone()
        if done:
            return
        if not self.db.is_sqlite:
            with self.db.transaction():
                self.db.execute(
                    "INSERT INTO metadata(key, value) VALUES('cas_legacy_imported', '1') "
                    "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value"
                )
            return
        tables = {
            row[0]
            for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        with self.db.transaction():
            if "directories" in tables:
                self.db.execute(
                    "INSERT OR IGNORE INTO cas_directories(path) SELECT path FROM directories"
                )
            if "files" in tables:
                columns = {
                    row[1]
                    for row in self.db.execute("PRAGMA table_info(files)").fetchall()
                }
                checksum_expr = "checksum" if "checksum" in columns else "''"
                version_expr = "version" if "version" in columns else "1"
                query = (
                    "SELECT path, remote_name, size, modified, generation, "
                    f"{checksum_expr} AS checksum, {version_expr} AS version FROM files"
                )
                for row in self.db.execute(query).fetchall():
                    manifest_id = "legacy-" + str(row["generation"])
                    self.db.execute(
                        """
                        INSERT OR IGNORE INTO cas_manifests(
                            id, remote_name, key_name, format_version, size,
                            stored_size, sha256, sha512, created
                        ) VALUES(?, ?, NULL, 1, ?, ?, ?, '', ?)
                        """,
                        (
                            manifest_id,
                            row["remote_name"],
                            row["size"],
                            row["size"],
                            row["checksum"],
                            row["modified"],
                        ),
                    )
                    self.db.execute(
                        """
                        INSERT OR IGNORE INTO cas_files(
                            path, current_manifest, modified, version, origin, generation
                        ) VALUES(?, ?, ?, ?, 'legacy', ?)
                        """,
                        (
                            row["path"],
                            manifest_id,
                            row["modified"],
                            row["version"],
                            row["generation"],
                        ),
                    )
            self.db.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('cas_legacy_imported', '1')"
            )

    def _derive(self, purpose: bytes, length: int) -> bytes:
        if self.root_secret is None:
            raise RuntimeError("recovery secret is not loaded in normal operation")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=b"icloud-webdav-root-v3",
            info=purpose,
        ).derive(self.root_secret)

    def _derive_kem_private(self, name: str):
        if self.root_secret is None:
            raise RuntimeError("recovery secret is required for recovery unwrap")
        seed = self._derive(b"ml-kem-seed-v1/" + name.encode("ascii"), 64)
        key_type = (
            mlkem.MLKEM768PrivateKey
            if name == "ML-KEM-768"
            else mlkem.MLKEM1024PrivateKey
        )
        return key_type.from_seed_bytes(seed)

    @staticmethod
    def _path(path: str) -> str:
        normalized = posixpath.normpath("/" + path.replace("\\", "/").lstrip("/"))
        return "/" if normalized == "/." else normalized

    @staticmethod
    def _parent(path: str) -> str:
        return posixpath.dirname(path) or "/"

    @staticmethod
    def _name(path: str) -> str:
        return PurePosixPath(path).name

    def _ensure_remote_directory(self, parent: str, name: str) -> None:
        entries = self.backend.list(parent)
        found = next((entry for entry in entries if entry.name == name), None)
        full_path = f"{parent.rstrip('/')}/{name}"
        if found is None:
            self.backend.mkdir(full_path)
        elif not found.is_dir:
            raise RuntimeError(f"vault path is not a directory: {full_path}")

    def _ensure_ready(self) -> None:
        if self._ready:
            return
        root_entries = self.backend.list("/")
        other_entries = [entry for entry in root_entries if entry.name != self.vault_folder]
        vault = next((entry for entry in root_entries if entry.name == self.vault_folder), None)
        if self.strict_plaintext and other_entries:
            names = ", ".join(entry.name for entry in other_entries[:5])
            raise RuntimeError(
                "encrypted mode refuses an iCloud Drive containing plaintext "
                f"items ({names}); move or migrate them before enabling encryption"
            )
        if vault is None:
            self.backend.mkdir(self.vault_path)
        elif not vault.is_dir:
            raise RuntimeError(f"vault path is not a directory: {self.vault_path}")
        for name in ("objects", "manifests", "keys", "metadata"):
            self._ensure_remote_directory(self.vault_path, name)
        self._ready = True

    def _directory_exists(self, path: str) -> bool:
        if path == "/":
            return True
        return self.db.execute(
            "SELECT 1 FROM cas_directories WHERE path=?", (path,)
        ).fetchone() is not None

    def _file_row(self, path: str):
        return self.db.execute(
            """
            SELECT f.*, m.size, m.sha256, m.sha512, m.format_version,
                   m.remote_name, m.key_name
            FROM cas_files f JOIN cas_manifests m ON m.id=f.current_manifest
            WHERE f.path=?
            """,
            (path,),
        ).fetchone()

    def _set_upload_status(
        self,
        operation_id: str,
        status: str,
        *,
        sha256: str | None = None,
        sha512: str | None = None,
        manifest_id: str | None = None,
        error: str | None = None,
    ) -> None:
        with self.db.transaction():
            self.db.execute(
                """
                UPDATE cas_uploads SET
                    status=?,
                    sha256=COALESCE(?, sha256),
                    sha512=COALESCE(?, sha512),
                    manifest_id=COALESCE(?, manifest_id),
                    error=?,
                    updated=?
                WHERE id=?
                """,
                (
                    status,
                    sha256,
                    sha512,
                    manifest_id,
                    error,
                    time.time(),
                    operation_id,
                ),
            )

    def _exists(self, path: str) -> bool:
        return self._directory_exists(path) or self._file_row(path) is not None

    @staticmethod
    def _capsule_aad(
        object_id: str, kem_name: str, hybrid: bool, ciphertext: bytes, ephemeral: bytes
    ) -> bytes:
        return b"ICCAS-KEM1\0" + b"\0".join(
            (
                object_id.encode("ascii"),
                kem_name.encode("ascii"),
                b"1" if hybrid else b"0",
                ciphertext,
                ephemeral,
            )
        )

    def _wrapping_key(
        self, shared: bytes, object_id: str, ciphertext: bytes, ephemeral: bytes
    ) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(ciphertext + ephemeral).digest(),
            info=b"icloud-webdav-cas-key-v1/" + object_id.encode("ascii"),
        ).derive(shared)

    def _make_capsule(self, object_id: str, dek: bytes) -> bytes:
        context = b"icloud-webdav/dek/" + object_id.encode("ascii")
        primary = [self.key_broker.wrap(dek, context)] if self.key_broker else []
        kem_shared, ciphertext = self._kem_public.encapsulate()
        ephemeral = b""
        shared = kem_shared
        if self.hybrid_x25519:
            private = x25519.X25519PrivateKey.generate()
            ephemeral = private.public_key().public_bytes_raw()
            shared += private.exchange(self._x25519_public)
        wrapping_key = self._wrapping_key(shared, object_id, ciphertext, ephemeral)
        nonce = os.urandom(12)
        aad = self._capsule_aad(
            object_id, self.kem, self.hybrid_x25519, ciphertext, ephemeral
        )
        capsule = {
            "v": 1,
            "primary": primary,
            "kem": self.kem,
            "hybrid_x25519": self.hybrid_x25519,
            "ciphertext": _b64(ciphertext),
            "ephemeral_public": _b64(ephemeral),
            "nonce": _b64(nonce),
            "wrapped_dek": _b64(AESGCM(wrapping_key).encrypt(nonce, dek, aad)),
        }
        return json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode("ascii")

    def _unwrap_capsule(self, object_id: str, data: bytes) -> bytes:
        try:
            capsule = json.loads(data.decode("ascii"))
            if capsule.get("v") != 1:
                raise ValueError("unsupported key capsule version")
            primary = capsule.get("primary", [])
            if isinstance(primary, dict):
                primary = [primary]
            if not isinstance(primary, list):
                raise ValueError("invalid primary key envelope list")
            if self.key_broker is not None:
                for envelope in primary:
                    if not isinstance(envelope, dict):
                        continue
                    if envelope.get("key_id") != self.key_broker.key_id:
                        continue
                    try:
                        return self.key_broker.unwrap(
                            envelope,
                            b"icloud-webdav/dek/" + object_id.encode("ascii"),
                        )
                    except Exception:
                        if self.root_secret is None:
                            raise
            kem_name = capsule["kem"]
            hybrid = capsule["hybrid_x25519"]
            if kem_name not in SUPPORTED_KEMS or not isinstance(hybrid, bool):
                raise ValueError("invalid key capsule algorithm")
            ciphertext = _unb64(capsule["ciphertext"])
            ephemeral = _unb64(capsule["ephemeral_public"])
            nonce = _unb64(capsule["nonce"])
            wrapped = _unb64(capsule["wrapped_dek"])
            private_key = self._derive_kem_private(kem_name)
            shared = private_key.decapsulate(ciphertext)
            if hybrid:
                if len(ephemeral) != 32:
                    raise ValueError("invalid X25519 public key")
                shared += self._x25519_private.exchange(
                    x25519.X25519PublicKey.from_public_bytes(ephemeral)
                )
            elif ephemeral:
                raise ValueError("unexpected X25519 public key")
            wrapping_key = self._wrapping_key(
                shared, object_id, ciphertext, ephemeral
            )
            aad = self._capsule_aad(
                object_id, kem_name, hybrid, ciphertext, ephemeral
            )
            dek = AESGCM(wrapping_key).decrypt(nonce, wrapped, aad)
            if len(dek) != 32:
                raise ValueError("unwrapped DEK has an invalid length")
            return dek
        except (KeyError, TypeError, json.JSONDecodeError, InvalidTag) as error:
            raise ValueError("key capsule authentication failed") from error

    @staticmethod
    def _encrypt_blob(
        plaintext: bytes, metadata: dict, output: BinaryIO, dek: bytes
    ) -> None:
        encoded_metadata = json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        nonce = os.urandom(12)
        output.write(HEADER.pack(CAS_MAGIC, nonce, bytes(16)))
        encryptor = Cipher(algorithms.AES(dek), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(CAS_MAGIC)
        output.write(encryptor.update(METADATA_LENGTH.pack(len(encoded_metadata))))
        output.write(encryptor.update(encoded_metadata))
        output.write(encryptor.update(plaintext))
        output.write(encryptor.finalize())
        end = output.tell()
        output.seek(HEADER.size - 16)
        output.write(encryptor.tag)
        output.seek(end)

    @staticmethod
    def _decrypt_blob(encrypted: BinaryIO, dek: bytes) -> tuple[dict, bytes]:
        header = encrypted.read(HEADER.size)
        if len(header) != HEADER.size:
            raise ValueError("encrypted object header is truncated")
        magic, nonce, tag = HEADER.unpack(header)
        if magic != CAS_MAGIC:
            raise ValueError("encrypted object has an unknown CAS format")
        decryptor = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(CAS_MAGIC)
        length_encrypted = encrypted.read(METADATA_LENGTH.size)
        if len(length_encrypted) != METADATA_LENGTH.size:
            raise ValueError("encrypted metadata length is truncated")
        metadata_size = METADATA_LENGTH.unpack(decryptor.update(length_encrypted))[0]
        if metadata_size > 1024 * 1024:
            raise ValueError("encrypted metadata is unreasonably large")
        metadata_encrypted = encrypted.read(metadata_size)
        if len(metadata_encrypted) != metadata_size:
            raise ValueError("encrypted metadata is truncated")
        metadata_plain = decryptor.update(metadata_encrypted)
        content = bytearray()
        while chunk := encrypted.read(IO_CHUNK_SIZE):
            content.extend(decryptor.update(chunk))
        try:
            content.extend(decryptor.finalize())
        except InvalidTag as error:
            raise ValueError("encrypted object authentication failed") from error
        return json.loads(metadata_plain.decode("utf-8")), bytes(content)

    def _store_blob(
        self, kind: str, object_id: str, plaintext: bytes, metadata: dict
    ) -> tuple[str, str, int]:
        directory = self.objects_path if kind == "chunk" else self.manifests_path
        suffix = ".dat" if kind == "chunk" else ".manifest"
        remote_name = object_id + suffix
        key_name = object_id + ".kem"
        dek = os.urandom(32)
        fd, encrypted_name = tempfile.mkstemp(prefix="icloud-webdav-cas-")
        os.close(fd)
        encrypted_path = Path(encrypted_name)
        capsule_path = encrypted_path.with_suffix(".kem")
        uploaded_object = False
        try:
            with encrypted_path.open("w+b") as output:
                self._encrypt_blob(plaintext, metadata, output, dek)
            capsule_path.write_bytes(self._make_capsule(object_id, dek))
            self.backend.upload(f"{directory}/{remote_name}", encrypted_path)
            uploaded_object = True
            self.backend.upload(f"{self.keys_path}/{key_name}", capsule_path)
            return remote_name, key_name, encrypted_path.stat().st_size
        except Exception:
            if uploaded_object:
                try:
                    self.backend.delete(f"{directory}/{remote_name}", directory=False)
                except Exception:
                    pass
            try:
                self.backend.delete(f"{self.keys_path}/{key_name}", directory=False)
            except Exception:
                pass
            raise
        finally:
            encrypted_path.unlink(missing_ok=True)
            capsule_path.unlink(missing_ok=True)

    def _load_blob(
        self, kind: str, object_id: str, remote_name: str, key_name: str
    ) -> tuple[dict, bytes]:
        directory = self.objects_path if kind == "chunk" else self.manifests_path
        capsule = io.BytesIO()
        self.backend.download(f"{self.keys_path}/{key_name}", capsule)
        dek = self._unwrap_capsule(object_id, capsule.getvalue())
        with tempfile.TemporaryFile("w+b") as encrypted:
            self.backend.download(f"{directory}/{remote_name}", encrypted)
            encrypted.seek(0)
            return self._decrypt_blob(encrypted, dek)

    def _get_or_create_chunk(self, content: bytes) -> tuple[sqlite3.Row, bool]:
        sha256 = hashlib.sha256(content).hexdigest()
        sha512 = hashlib.sha512(content).hexdigest()
        existing = self.db.execute(
            "SELECT * FROM cas_chunks WHERE size=? AND sha256=? AND sha512=?",
            (len(content), sha256, sha512),
        ).fetchone()
        if existing is not None:
            return existing, False
        chunk_id = uuid.uuid4().hex
        remote_name, key_name, stored_size = self._store_blob(
            "chunk",
            chunk_id,
            content,
            {
                "type": "chunk",
                "id": chunk_id,
                "size": len(content),
                "sha256": sha256,
                "sha512": sha512,
            },
        )
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO cas_chunks(
                    id, remote_name, key_name, size, stored_size,
                    sha256, sha512, created
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk_id,
                    remote_name,
                    key_name,
                    len(content),
                    stored_size,
                    sha256,
                    sha512,
                    time.time(),
                ),
            )
        return self.db.execute(
            "SELECT * FROM cas_chunks WHERE id=?", (chunk_id,)
        ).fetchone(), True

    @staticmethod
    def _read_exact(source: BinaryIO, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = source.read(size - len(result))
            if not chunk:
                break
            result.extend(chunk)
        return bytes(result)

    def _legacy_download(
        self, row: sqlite3.Row, destination: BinaryIO, expected_path: str
    ) -> None:
        with tempfile.TemporaryFile("w+b") as encrypted:
            self.backend.download(f"{self.vault_path}/{row['remote_name']}", encrypted)
            encrypted.seek(0)
            header = encrypted.read(HEADER.size)
            if len(header) != HEADER.size:
                raise ValueError("legacy encrypted object header is truncated")
            magic, nonce, tag = HEADER.unpack(header)
            if magic != LEGACY_MAGIC:
                raise ValueError("legacy encrypted object has an unknown format")
            decryptor = Cipher(
                algorithms.AES(self.root_secret), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(LEGACY_MAGIC)
            length = decryptor.update(encrypted.read(METADATA_LENGTH.size))
            metadata_size = METADATA_LENGTH.unpack(length)[0]
            metadata = json.loads(
                decryptor.update(encrypted.read(metadata_size)).decode("utf-8")
            )
            if int(metadata.get("size", -1)) != int(row["size"]):
                raise ValueError(
                    f"legacy object size does not match the database for {expected_path}"
                )
            written = 0
            while chunk := encrypted.read(IO_CHUNK_SIZE):
                plain = decryptor.update(chunk)
                destination.write(plain)
                written += len(plain)
            try:
                tail = decryptor.finalize()
            except InvalidTag as error:
                raise ValueError("encrypted object authentication failed") from error
            destination.write(tail)
            written += len(tail)
            if written != int(row["size"]):
                raise ValueError("legacy decrypted size mismatch")

    def _manifest_chunks(self, manifest_id: str) -> list[sqlite3.Row]:
        return self.db.execute(
            """
            SELECT mc.position, mc.plain_size, c.*
            FROM cas_manifest_chunks mc
            JOIN cas_chunks c ON c.id=mc.chunk_id
            WHERE mc.manifest_id=? ORDER BY mc.position
            """,
            (manifest_id,),
        ).fetchall()

    def _reconcile(self) -> None:
        """Hide current files whose encrypted iCloud components were removed."""
        self._ensure_ready()
        now = time.time()
        if now - self._last_reconcile < self.reconcile_interval:
            return
        legacy = {
            entry.name for entry in self.backend.list(self.vault_path) if not entry.is_dir
        }
        objects = {
            entry.name for entry in self.backend.list(self.objects_path) if not entry.is_dir
        }
        manifests = {
            entry.name
            for entry in self.backend.list(self.manifests_path)
            if not entry.is_dir
        }
        keys = {
            entry.name for entry in self.backend.list(self.keys_path) if not entry.is_dir
        }
        missing: list[str] = []
        for file_row in self.db.execute("SELECT * FROM cas_files").fetchall():
            manifest = self.db.execute(
                "SELECT * FROM cas_manifests WHERE id=?",
                (file_row["current_manifest"],),
            ).fetchone()
            if manifest is None:
                missing.append(file_row["path"])
                continue
            if int(manifest["format_version"]) == 1:
                present = manifest["remote_name"] in legacy
            else:
                present = (
                    manifest["remote_name"] in manifests
                    and manifest["key_name"] in keys
                )
                if present:
                    for chunk in self._manifest_chunks(manifest["id"]):
                        if chunk["remote_name"] not in objects or chunk["key_name"] not in keys:
                            present = False
                            break
            if not present:
                missing.append(file_row["path"])
        missing_set = set(missing)
        with self.db.transaction():
            for observation in self.db.execute(
                "SELECT path FROM cas_missing_observations"
            ).fetchall():
                if observation["path"] not in missing_set:
                    self.db.execute(
                        "DELETE FROM cas_missing_observations WHERE path=?",
                        (observation["path"],),
                    )
            for path in missing:
                self.db.execute(
                    """
                    INSERT INTO cas_missing_observations(
                        path, first_seen, observations, last_seen
                    ) VALUES(?, ?, 1, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        observations=cas_missing_observations.observations + 1,
                        last_seen=EXCLUDED.last_seen
                    """,
                    (path, now, now),
                )
            confirmed = self.db.execute(
                "SELECT path FROM cas_missing_observations "
                "WHERE observations>=? AND first_seen<=?",
                (self.missing_observations, now - self.missing_grace),
            ).fetchall()
            for confirmed_row in confirmed:
                path = confirmed_row["path"]
                row = self.db.execute(
                    "SELECT * FROM cas_files WHERE path=?", (path,)
                ).fetchone()
                if row:
                    self.db.execute(
                        """
                        INSERT INTO cas_versions(
                            path, version, manifest_id, modified, archived
                        ) VALUES(?, ?, ?, ?, ?)
                        ON CONFLICT(path, version) DO NOTHING
                        """,
                        (
                            path,
                            row["version"],
                            row["current_manifest"],
                            row["modified"],
                            now,
                        ),
                    )
                    self.db.execute("DELETE FROM cas_files WHERE path=?", (path,))
                    self.db.execute(
                        "INSERT INTO cas_deleted(path, deleted) VALUES(?, ?) "
                        "ON CONFLICT(path) DO UPDATE SET deleted=EXCLUDED.deleted",
                        (path, now),
                    )
                self.db.execute(
                    "DELETE FROM cas_missing_observations WHERE path=?", (path,)
                )
        self._last_reconcile = now

    def list(self, path: str) -> list[Entry]:
        with self._lock:
            self._reconcile()
            path = self._path(path)
            if not self._directory_exists(path):
                raise NotADirectoryError(path)
            prefix = "/" if path == "/" else path + "/"
            entries: dict[str, Entry] = {}
            for row in self.db.execute(
                "SELECT path FROM cas_directories WHERE path LIKE ?", (prefix + "%",)
            ):
                remainder = row["path"][len(prefix) :]
                if remainder and "/" not in remainder:
                    entries[remainder] = Entry(remainder, True, 0, 0.0)
            for row in self.db.execute(
                """
                SELECT f.path, f.modified, m.size
                FROM cas_files f JOIN cas_manifests m ON m.id=f.current_manifest
                WHERE f.path LIKE ?
                """,
                (prefix + "%",),
            ):
                remainder = row["path"][len(prefix) :]
                if remainder and "/" not in remainder:
                    entries[remainder] = Entry(
                        remainder, False, int(row["size"]), float(row["modified"])
                    )
            return sorted(
                entries.values(), key=lambda entry: (not entry.is_dir, entry.name.casefold())
            )

    def stat(self, path: str) -> Entry:
        with self._lock:
            self._ensure_ready()
            path = self._path(path)
            if self._directory_exists(path):
                return Entry(self._name(path) or "/", True, 0, 0.0)
            row = self._file_row(path)
            if row is None:
                raise KeyError(path)
            return Entry(
                self._name(path), False, int(row["size"]), float(row["modified"])
            )

    def checksum(self, path: str) -> str | None:
        with self._lock:
            row = self._file_row(self._path(path))
            return None if row is None or not row["sha256"] else str(row["sha256"])

    def version(self, path: str) -> int | None:
        with self._lock:
            row = self._file_row(self._path(path))
            return None if row is None else int(row["version"])

    def download(self, path: str, destination: BinaryIO) -> None:
        with self._lock:
            self._ensure_ready()
            path = self._path(path)
            row = self._file_row(path)
            if row is None:
                raise KeyError(path)
            if int(row["format_version"]) == 1:
                self._legacy_download(row, destination, path)
                return
            descriptor_metadata, descriptor_bytes = self._load_blob(
                "manifest",
                row["current_manifest"],
                row["remote_name"],
                row["key_name"],
            )
            descriptor = json.loads(descriptor_bytes.decode("utf-8"))
            if descriptor_metadata.get("type") != "manifest":
                raise ValueError("encrypted manifest has an invalid type")
            chunks = self._manifest_chunks(row["current_manifest"])
            if descriptor.get("chunks") != [chunk["id"] for chunk in chunks]:
                raise ValueError("encrypted manifest does not match the local database")
            full256 = hashlib.sha256()
            full512 = hashlib.sha512()
            total = 0
            for chunk in chunks:
                metadata, plaintext = self._load_blob(
                    "chunk",
                    chunk["id"],
                    chunk["remote_name"],
                    chunk["key_name"],
                )
                if (
                    metadata.get("id") != chunk["id"]
                    or len(plaintext) != int(chunk["plain_size"])
                    or hashlib.sha256(plaintext).hexdigest() != chunk["sha256"]
                    or hashlib.sha512(plaintext).hexdigest() != chunk["sha512"]
                ):
                    raise ValueError("decrypted chunk failed integrity verification")
                destination.write(plaintext)
                full256.update(plaintext)
                full512.update(plaintext)
                total += len(plaintext)
            if (
                total != int(row["size"])
                or full256.hexdigest() != row["sha256"]
                or full512.hexdigest() != row["sha512"]
            ):
                raise ValueError("reconstructed file failed checksum verification")

    def upload(self, path: str, source: Path) -> None:
        with source.open("rb") as stream:
            self.upload_stream(path, stream, source.stat().st_size)

    def upload_stream(self, path: str, source: BinaryIO, size: int) -> bool:
        """Store changed chunks and return False when the full checksum matches."""
        with self._lock:
            self._ensure_ready()
            path = self._path(path)
            if size < 0:
                raise ValueError("upload size cannot be negative")
            if path == "/" or not self._directory_exists(self._parent(path)):
                raise FileNotFoundError(self._parent(path))
            if self._directory_exists(path):
                raise IsADirectoryError(path)
            old = self._file_row(path)
            expected_current = None if old is None else old["current_manifest"]
            if old is not None:
                new_version = int(old["version"]) + 1
            else:
                previous = self.db.execute(
                    "SELECT MAX(version) FROM cas_versions WHERE path=?", (path,)
                ).fetchone()[0]
                new_version = int(previous or 0) + 1
            operation_id = uuid.uuid4().hex
            now = time.time()
            with self.db.transaction():
                self.db.execute(
                    """
                    INSERT INTO cas_uploads(
                        id, path, version, status, size, created, updated
                    ) VALUES(?, ?, ?, 'PENDING', ?, ?, ?)
                    """,
                    (operation_id, path, new_version, size, now, now),
                )
            self._set_upload_status(operation_id, "UPLOADING")
            full256 = hashlib.sha256()
            full512 = hashlib.sha512()
            chunk_rows: list[sqlite3.Row] = []
            remaining = size
            manifest_id: str | None = None
            try:
                while remaining:
                    expected = min(self.chunk_size, remaining)
                    plaintext = self._read_exact(source, expected)
                    if len(plaintext) != expected:
                        raise EOFError(
                            f"upload ended early ({size - remaining + len(plaintext)} "
                            f"of {size} bytes received)"
                        )
                    full256.update(plaintext)
                    full512.update(plaintext)
                    chunk, _ = self._get_or_create_chunk(plaintext)
                    chunk_rows.append(chunk)
                    with self.db.transaction():
                        self.db.execute(
                            "INSERT INTO cas_upload_chunks(upload_id, position, chunk_id) "
                            "VALUES(?, ?, ?)",
                            (operation_id, len(chunk_rows) - 1, chunk["id"]),
                        )
                    remaining -= expected
                sha256 = full256.hexdigest()
                sha512 = full512.hexdigest()
                if (
                    old is not None
                    and int(old["size"]) == size
                    and old["sha256"] == sha256
                    and old["sha512"] == sha512
                ):
                    self._set_upload_status(
                        operation_id,
                        "ACTIVE",
                        sha256=sha256,
                        sha512=sha512,
                        manifest_id=old["current_manifest"],
                        error="UNCHANGED",
                    )
                    with self.db.transaction():
                        self.db.execute(
                            "DELETE FROM cas_upload_chunks WHERE upload_id=?",
                            (operation_id,),
                        )
                    return False

                now = time.time()
                manifest_id = uuid.uuid4().hex
                descriptor = {
                    "v": 1,
                    "path": path,
                    "size": size,
                    "sha256": sha256,
                    "sha512": sha512,
                    "modified": now,
                    "chunks": [row["id"] for row in chunk_rows],
                }
                descriptor_bytes = json.dumps(
                    descriptor,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                remote_name, key_name, stored_size = self._store_blob(
                    "manifest",
                    manifest_id,
                    descriptor_bytes,
                    {
                        "type": "manifest",
                        "id": manifest_id,
                        "file_size": size,
                        "chunk_count": len(chunk_rows),
                    },
                )
                # iCloud objects exist before any current-version change.
                with self.db.transaction():
                    self.db.execute(
                        """
                        INSERT INTO cas_manifests(
                            id, remote_name, key_name, format_version, size,
                            stored_size, sha256, sha512, created
                        ) VALUES(?, ?, ?, 3, ?, ?, ?, ?, ?)
                        """,
                        (
                            manifest_id,
                            remote_name,
                            key_name,
                            size,
                            stored_size,
                            sha256,
                            sha512,
                            now,
                        ),
                    )
                    for position, chunk in enumerate(chunk_rows):
                        self.db.execute(
                            """
                            INSERT INTO cas_manifest_chunks(
                                manifest_id, position, chunk_id, plain_size
                            ) VALUES(?, ?, ?, ?)
                            """,
                            (manifest_id, position, chunk["id"], chunk["size"]),
                        )
                    self.db.execute(
                        """
                        UPDATE cas_uploads SET
                            status='VERIFYING', sha256=?, sha512=?, manifest_id=?, updated=?
                        WHERE id=?
                        """,
                        (sha256, sha512, manifest_id, time.time(), operation_id),
                    )
                # Verify every newly selected component is visible in iCloud.
                self.backend.stat(f"{self.manifests_path}/{remote_name}")
                self.backend.stat(f"{self.keys_path}/{key_name}")
                for chunk in chunk_rows:
                    self.backend.stat(f"{self.objects_path}/{chunk['remote_name']}")
                    self.backend.stat(f"{self.keys_path}/{chunk['key_name']}")
                try:
                    with self.db.transaction():
                        locked = self.db.select_current_for_update(path)
                        actual_current = None if locked is None else locked["current_manifest"]
                        if actual_current != expected_current:
                            raise RuntimeError(
                                "concurrent update won the PostgreSQL current-version race"
                            )
                        if old is not None:
                            self.db.execute(
                                """
                                INSERT INTO cas_versions(
                                    path, version, manifest_id, modified, archived
                                ) VALUES(?, ?, ?, ?, ?)
                                ON CONFLICT(path, version) DO UPDATE SET
                                    manifest_id=EXCLUDED.manifest_id,
                                    modified=EXCLUDED.modified,
                                    archived=EXCLUDED.archived
                                """,
                                (
                                    path,
                                    old["version"],
                                    old["current_manifest"],
                                    old["modified"],
                                    now,
                                ),
                            )
                        self.db.execute(
                            """
                            INSERT INTO cas_files(
                                path, current_manifest, modified, version, origin, generation
                            ) VALUES(?, ?, ?, ?, 'webdav', ?)
                            ON CONFLICT(path) DO UPDATE SET
                                current_manifest=excluded.current_manifest,
                                modified=excluded.modified,
                                version=excluded.version,
                                origin=excluded.origin,
                                generation=excluded.generation
                            """,
                            (path, manifest_id, now, new_version, uuid.uuid4().hex),
                        )
                        self.db.execute("DELETE FROM cas_deleted WHERE path=?", (path,))
                        self.db.execute(
                            "UPDATE cas_uploads SET status='ACTIVE', updated=? WHERE id=?",
                            (time.time(), operation_id),
                        )
                        self.db.execute(
                            "DELETE FROM cas_upload_chunks WHERE upload_id=?",
                            (operation_id,),
                        )
                except Exception:
                    raise
                return True
            except Exception as error:
                self._set_upload_status(
                    operation_id,
                    "FAILED",
                    manifest_id=manifest_id,
                    error=str(error)[:1000],
                )
                with self.db.transaction():
                    self.db.execute(
                        "DELETE FROM cas_upload_chunks WHERE upload_id=?", (operation_id,)
                    )
                try:
                    self._collect_garbage(scan_remote=False)
                except Exception:
                    pass
                raise

    def mkdir(self, path: str) -> None:
        with self._lock:
            self._ensure_ready()
            path = self._path(path)
            if path == "/" or self._exists(path):
                raise FileExistsError(path)
            if not self._directory_exists(self._parent(path)):
                raise FileNotFoundError(self._parent(path))
            with self.db.transaction():
                self.db.execute("INSERT INTO cas_directories(path) VALUES(?)", (path,))

    def delete(self, path: str, *, directory: bool) -> None:
        with self._lock:
            self._ensure_ready()
            path = self._path(path)
            if directory:
                if path == "/":
                    raise PermissionError("root cannot be deleted")
                if not self._directory_exists(path):
                    raise NotADirectoryError(path)
                prefix = path + "/%"
                if self.db.execute(
                    "SELECT 1 FROM cas_directories WHERE path LIKE ? "
                    "UNION SELECT 1 FROM cas_files WHERE path LIKE ? LIMIT 1",
                    (prefix, prefix),
                ).fetchone():
                    raise OSError("directory is not empty")
                with self.db.transaction():
                    self.db.execute("DELETE FROM cas_directories WHERE path=?", (path,))
                return
            row = self._file_row(path)
            if row is None:
                raise FileNotFoundError(path)
            with self.db.transaction():
                self.db.execute(
                    """
                    INSERT INTO cas_versions(
                        path, version, manifest_id, modified, archived
                    ) VALUES(?, ?, ?, ?, ?)
                    ON CONFLICT(path, version) DO UPDATE SET
                        manifest_id=EXCLUDED.manifest_id,
                        modified=EXCLUDED.modified,
                        archived=EXCLUDED.archived
                    """,
                    (
                        path,
                        row["version"],
                        row["current_manifest"],
                        row["modified"],
                        time.time(),
                    ),
                )
                self.db.execute("DELETE FROM cas_files WHERE path=?", (path,))
                self.db.execute(
                    "INSERT INTO cas_deleted(path, deleted) VALUES(?, ?) "
                    "ON CONFLICT(path) DO UPDATE SET deleted=EXCLUDED.deleted",
                    (path, time.time()),
                )

    def rename(self, source: str, destination: str) -> None:
        with self._lock:
            self._ensure_ready()
            source, destination = self._path(source), self._path(destination)
            if self._exists(destination):
                raise FileExistsError(destination)
            if not self._directory_exists(self._parent(destination)):
                raise FileNotFoundError(self._parent(destination))
            if self.db.execute(
                "SELECT 1 FROM cas_deleted WHERE path=?", (destination,)
            ).fetchone():
                self._purge_deleted_path(destination)
                self._collect_garbage(scan_remote=False)
            file_row = self._file_row(source)
            if file_row is not None:
                with self.db.transaction():
                    self.db.execute(
                        "UPDATE cas_files SET path=?, generation=? WHERE path=?",
                        (destination, uuid.uuid4().hex, source),
                    )
                    self.db.execute(
                        "UPDATE cas_versions SET path=? WHERE path=?", (destination, source)
                    )
                return
            if not self._directory_exists(source):
                raise FileNotFoundError(source)
            old_prefix, new_prefix = source + "/", destination + "/"
            directories = self.db.execute(
                "SELECT path FROM cas_directories WHERE path=? OR path LIKE ? "
                "ORDER BY length(path) DESC",
                (source, old_prefix + "%"),
            ).fetchall()
            files = self.db.execute(
                "SELECT path FROM cas_files WHERE path LIKE ?", (old_prefix + "%",)
            ).fetchall()
            with self.db.transaction():
                for row in files:
                    old_path = row["path"]
                    new_path = new_prefix + old_path[len(old_prefix) :]
                    self.db.execute(
                        "UPDATE cas_files SET path=?, generation=? WHERE path=?",
                        (new_path, uuid.uuid4().hex, old_path),
                    )
                    self.db.execute(
                        "UPDATE cas_versions SET path=? WHERE path=?", (new_path, old_path)
                    )
                for row in directories:
                    old_path = row["path"]
                    replacement = (
                        destination
                        if old_path == source
                        else new_prefix + old_path[len(old_prefix) :]
                    )
                    self.db.execute(
                        "UPDATE cas_directories SET path=? WHERE path=?",
                        (replacement, old_path),
                    )

    def _version_limit(self, size: int) -> int:
        if size < self.medium_threshold:
            return self.small_versions
        if size <= self.large_threshold:
            return self.medium_versions
        return self.large_versions

    def _apply_retention_for_path(self, path: str) -> None:
        current = self._file_row(path)
        if current is None:
            return
        # The configured count includes the current version.
        keep_history = max(0, self._version_limit(int(current["size"])) - 1)
        rows = self.db.execute(
            "SELECT version FROM cas_versions WHERE path=? ORDER BY version DESC",
            (path,),
        ).fetchall()
        with self.db.transaction():
            for row in rows[keep_history:]:
                self.db.execute(
                    "DELETE FROM cas_versions WHERE path=? AND version=?",
                    (path, row["version"]),
                )

    def _purge_deleted_path(self, path: str) -> None:
        with self.db.transaction():
            self.db.execute("DELETE FROM cas_versions WHERE path=?", (path,))
            self.db.execute("DELETE FROM cas_deleted WHERE path=?", (path,))

    def _stored_usage(self) -> int:
        row = self.db.execute(
            """
            WITH refs(id) AS (
                SELECT current_manifest FROM cas_files
                UNION SELECT manifest_id FROM cas_versions
            ), used_chunks(id) AS (
                SELECT DISTINCT mc.chunk_id
                FROM cas_manifest_chunks mc JOIN refs ON refs.id=mc.manifest_id
            )
            SELECT
                COALESCE((SELECT SUM(stored_size) FROM cas_manifests
                          WHERE id IN (SELECT id FROM refs)), 0)
              + COALESCE((SELECT SUM(stored_size) FROM cas_chunks
                          WHERE id IN (SELECT id FROM used_chunks)), 0)
            """
        ).fetchone()
        return int(row[0] or 0)

    def _delete_remote_manifest(self, row) -> None:
        if int(row["format_version"]) == 1:
            object_path = f"{self.vault_path}/{row['remote_name']}"
            key_path = None
        else:
            object_path = f"{self.manifests_path}/{row['remote_name']}"
            key_path = f"{self.keys_path}/{row['key_name']}"
        try:
            self.backend.delete(object_path, directory=False)
        except (FileNotFoundError, KeyError):
            pass
        if key_path:
            try:
                self.backend.delete(key_path, directory=False)
            except (FileNotFoundError, KeyError):
                pass

    def _delete_remote_chunk(self, row) -> None:
        try:
            self.backend.delete(
                f"{self.objects_path}/{row['remote_name']}", directory=False
            )
        except (FileNotFoundError, KeyError):
            pass
        try:
            self.backend.delete(f"{self.keys_path}/{row['key_name']}", directory=False)
        except (FileNotFoundError, KeyError):
            pass

    def _collect_garbage(self, *, scan_remote: bool) -> None:
        manifests = self.db.execute(
            """
            SELECT * FROM cas_manifests m
            WHERE NOT EXISTS(
                SELECT 1 FROM cas_files f WHERE f.current_manifest=m.id
            ) AND NOT EXISTS(
                SELECT 1 FROM cas_versions v WHERE v.manifest_id=m.id
            ) AND NOT EXISTS(
                SELECT 1 FROM cas_uploads u
                WHERE u.manifest_id=m.id AND u.status IN ('PENDING','UPLOADING','VERIFYING')
            )
            """
        ).fetchall()
        for manifest in manifests:
            try:
                self._delete_remote_manifest(manifest)
            except Exception:
                continue
            with self.db.transaction():
                self.db.execute(
                    "DELETE FROM cas_manifest_chunks WHERE manifest_id=?",
                    (manifest["id"],),
                )
                self.db.execute("DELETE FROM cas_manifests WHERE id=?", (manifest["id"],))
        chunks = self.db.execute(
            """
            SELECT * FROM cas_chunks c WHERE NOT EXISTS(
                SELECT 1 FROM cas_manifest_chunks mc WHERE mc.chunk_id=c.id
            ) AND NOT EXISTS(
                SELECT 1 FROM cas_upload_chunks uc WHERE uc.chunk_id=c.id
            )
            """
        ).fetchall()
        for chunk in chunks:
            try:
                self._delete_remote_chunk(chunk)
            except Exception:
                continue
            with self.db.transaction():
                self.db.execute("DELETE FROM cas_chunks WHERE id=?", (chunk["id"],))
        if scan_remote:
            self._remove_unknown_remote_objects()

    def _remove_unknown_remote_objects(self) -> None:
        # A concurrent uploader may have put an object into iCloud immediately
        # before committing its DB row. A grace window keeps remote scanning
        # from turning that normal ordering into data loss. Unknown entries
        # without a trustworthy timestamp are retained for manual inspection.
        cutoff = time.time() - self.orphan_grace
        known_objects = {
            row[0] for row in self.db.execute("SELECT remote_name FROM cas_chunks")
        }
        known_manifests = {
            row[0]
            for row in self.db.execute(
                "SELECT remote_name FROM cas_manifests WHERE format_version>1"
            )
        }
        known_keys = {
            row[0]
            for row in self.db.execute(
                "SELECT key_name FROM cas_chunks UNION SELECT key_name FROM cas_manifests "
                "WHERE key_name IS NOT NULL"
            )
        }
        for base, known in (
            (self.objects_path, known_objects),
            (self.manifests_path, known_manifests),
            (self.keys_path, known_keys),
        ):
            for entry in self.backend.list(base):
                if (
                    not entry.is_dir
                    and entry.name not in known
                    and entry.modified > 0
                    and entry.modified <= cutoff
                ):
                    try:
                        self.backend.delete(f"{base}/{entry.name}", directory=False)
                    except Exception:
                        pass

    def gc(self, *, force: bool = False) -> dict[str, int]:
        """Apply retention and collect unreferenced encrypted objects."""
        with self._lock:
            self._ensure_ready()
            now = time.time()
            last_row = self.db.execute(
                "SELECT value FROM metadata WHERE key='last_gc'"
            ).fetchone()
            last = float(last_row[0]) if last_row else 0.0
            if not force and now - last < self.gc_interval:
                return {"ran": 0, "stored_bytes": self._stored_usage()}

            # 1. Expired history.
            cutoff = now - self.retention_days * 86400
            with self.db.transaction():
                if self.retention_days == 0:
                    self.db.execute("DELETE FROM cas_versions")
                else:
                    self.db.execute(
                        "DELETE FROM cas_versions WHERE archived < ?", (cutoff,)
                    )

            # 2. Per-size generation limits.
            for row in self.db.execute("SELECT path FROM cas_files").fetchall():
                self._apply_retention_for_path(row["path"])

            # 3. Histories for files deleted through WebDAV or iCloud Web.
            for row in self.db.execute("SELECT path FROM cas_deleted").fetchall():
                self._purge_deleted_path(row["path"])

            # 4. Capacity pressure deletes only oldest historical versions.
            if self.capacity_limit:
                while self._stored_usage() > self.capacity_limit:
                    oldest = self.db.execute(
                        "SELECT path, version FROM cas_versions "
                        "ORDER BY archived ASC LIMIT 1"
                    ).fetchone()
                    if oldest is None:
                        break
                    with self.db.transaction():
                        self.db.execute(
                            "DELETE FROM cas_versions WHERE path=? AND version=?",
                            (oldest["path"], oldest["version"]),
                        )

            # 5. Manifests and chunks no longer referenced by current/history.
            self._collect_garbage(scan_remote=True)
            stored = self._stored_usage()
            with self.db.transaction():
                self.db.execute(
                    "INSERT INTO metadata(key, value) VALUES('last_gc', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    (str(now),),
                )
            return {"ran": 1, "stored_bytes": stored}

    def gc_if_due(self) -> dict[str, int]:
        return self.gc(force=False)

    def _capsule_rows(self) -> list[sqlite3.Row]:
        return self.db.execute(
            """
            SELECT id, key_name FROM cas_chunks
            UNION
            SELECT id, key_name FROM cas_manifests
            WHERE format_version>1 AND key_name IS NOT NULL
            ORDER BY id
            """
        ).fetchall()

    def rewrap_primary_keys(self, new_broker, *, finalize: bool = False) -> dict[str, int]:
        """Resumably add a new primary wrap, then optionally remove old wraps.

        Appending first makes a crash harmless: each processed capsule remains
        readable by both KEKs. Finalization is refused until every live capsule
        has a verified envelope for ``new_broker.key_id``.
        """
        with self._lock:
            self._ensure_ready()
            rows = self._capsule_rows()
            changed = 0
            for row in rows:
                object_id, key_name = row["id"], row["key_name"]
                capsule_stream = io.BytesIO()
                self.backend.download(f"{self.keys_path}/{key_name}", capsule_stream)
                capsule = json.loads(capsule_stream.getvalue().decode("ascii"))
                envelopes = capsule.get("primary", [])
                if isinstance(envelopes, dict):
                    envelopes = [envelopes]
                existing = next(
                    (
                        envelope
                        for envelope in envelopes
                        if isinstance(envelope, dict)
                        and envelope.get("key_id") == new_broker.key_id
                    ),
                    None,
                )
                try:
                    dek = self._unwrap_capsule(object_id, capsule_stream.getvalue())
                    context = b"icloud-webdav/dek/" + object_id.encode("ascii")
                    if existing is None:
                        existing = new_broker.wrap(dek, context)
                        envelopes.append(existing)
                        capsule["primary"] = envelopes
                        self._upload_capsule(key_name, capsule)
                        changed += 1
                    if new_broker.unwrap(existing, context) != dek:
                        raise ValueError("new Key Broker failed wrap verification")
                    with self.db.transaction():
                        self.db.execute(
                            """
                            INSERT INTO cas_key_rewrap(
                                object_id, new_key_id, status, error, updated
                            ) VALUES(?, ?, 'VERIFIED', NULL, ?)
                            ON CONFLICT(object_id, new_key_id) DO UPDATE SET
                                status=EXCLUDED.status,
                                error=EXCLUDED.error,
                                updated=EXCLUDED.updated
                            """,
                            (object_id, new_broker.key_id, time.time()),
                        )
                except Exception as error:
                    with self.db.transaction():
                        self.db.execute(
                            """
                            INSERT INTO cas_key_rewrap(
                                object_id, new_key_id, status, error, updated
                            ) VALUES(?, ?, 'FAILED', ?, ?)
                            ON CONFLICT(object_id, new_key_id) DO UPDATE SET
                                status=EXCLUDED.status,
                                error=EXCLUDED.error,
                                updated=EXCLUDED.updated
                            """,
                            (object_id, new_broker.key_id, str(error)[:1000], time.time()),
                        )
                    raise
            if finalize:
                verified = self.db.execute(
                    "SELECT COUNT(*) FROM cas_key_rewrap "
                    "WHERE new_key_id=? AND status='VERIFIED'",
                    (new_broker.key_id,),
                ).fetchone()[0]
                if int(verified) < len(rows):
                    raise RuntimeError("not every live capsule has a verified new wrap")
                for row in rows:
                    stream = io.BytesIO()
                    self.backend.download(f"{self.keys_path}/{row['key_name']}", stream)
                    capsule = json.loads(stream.getvalue().decode("ascii"))
                    envelopes = capsule.get("primary", [])
                    if isinstance(envelopes, dict):
                        envelopes = [envelopes]
                    selected = [
                        envelope
                        for envelope in envelopes
                        if envelope.get("key_id") == new_broker.key_id
                    ]
                    if len(selected) != 1:
                        raise RuntimeError("new primary envelope is missing or duplicated")
                    dek = self._unwrap_capsule(row["id"], stream.getvalue())
                    context = b"icloud-webdav/dek/" + row["id"].encode("ascii")
                    if new_broker.unwrap(selected[0], context) != dek:
                        raise RuntimeError("new primary envelope failed final verification")
                    capsule["primary"] = selected
                    self._upload_capsule(row["key_name"], capsule)
                self.key_broker = new_broker
            return {"capsules": len(rows), "changed": changed, "finalized": int(finalize)}

    def _upload_capsule(self, key_name: str, capsule: dict) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix="icloud-webdav-rewrap-")
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            temporary.write_text(
                json.dumps(capsule, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            self.backend.upload(f"{self.keys_path}/{key_name}", temporary)
        finally:
            temporary.unlink(missing_ok=True)

    def close(self) -> None:
        with self._lock:
            self.db.close()
