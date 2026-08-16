"""Small RFC 4918 WebDAV surface for the encrypted virtual backend."""

from __future__ import annotations

import base64
import contextlib
import email.utils
import hashlib
import hmac
import ipaddress
import logging
import mimetypes
import posixpath
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

from .backend import DriveBackend, Entry
from .coordination import ValkeyCoordinator

LOGGER = logging.getLogger(__name__)
DAV = "DAV:"
ET.register_namespace("D", DAV)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _SliceWriter:
    def __init__(self, output, start: int, end: int):
        self.output = output
        self.start = start
        self.end = end
        self.position = 0

    def write(self, data: bytes) -> int:
        data_start = self.position
        data_end = self.position + len(data) - 1
        left = max(self.start, data_start)
        right = min(self.end, data_end)
        if left <= right:
            offset = left - data_start
            self.output.write(data[offset : offset + right - left + 1])
        self.position += len(data)
        return len(data)


class WebDAVServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address,
        handler,
        *,
        backend: DriveBackend,
        username: str,
        password: str,
        coordinator: ValkeyCoordinator,
        read_only: bool,
    ):
        self.backend = backend
        self.webdav_username = username
        self.webdav_password = password
        self.coordinator = coordinator
        self.read_only = read_only
        self._next_gc_check = 0.0
        super().__init__(address, handler)

    def service_actions(self) -> None:
        now = time.monotonic()
        if now < self._next_gc_check:
            return
        self._next_gc_check = now + 60
        if self.read_only or self.coordinator.safe_mode() or not hasattr(self.backend, "gc_if_due"):
            return
        try:
            with self.coordinator.file_lock("__daily_gc__"):
                self.backend.gc_if_due()
        except BlockingIOError:
            pass
        except Exception:
            LOGGER.exception("Scheduled encrypted-storage GC failed")


class WebDAVHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "iCloudEncryptedWebDAV/0.2"

    @property
    def backend(self):
        return self.server.backend

    @property
    def coordinator(self) -> ValkeyCoordinator:
        return self.server.coordinator

    def _authenticated(self) -> bool:
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError):
                pass
            else:
                return hmac.compare_digest(username, self.server.webdav_username) and hmac.compare_digest(
                    password, self.server.webdav_password
                )
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="iCloud encrypted WebDAV"')
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        return False

    def _path(self) -> str:
        raw = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if "\x00" in raw or "\\" in raw:
            raise ValueError("invalid WebDAV path")
        normalized = posixpath.normpath("/" + raw.lstrip("/"))
        return "/" if normalized == "/." else normalized

    def _destination(self) -> str:
        value = self.headers.get("Destination")
        if not value:
            raise ValueError("Destination header is required")
        parsed = urllib.parse.urlsplit(value)
        if parsed.netloc and parsed.netloc != self.headers.get("Host"):
            raise PermissionError("cross-server MOVE is not supported")
        raw = urllib.parse.unquote(parsed.path)
        normalized = posixpath.normpath("/" + raw.lstrip("/"))
        return "/" if normalized == "/." else normalized

    def _discard_body(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        while length:
            chunk = self.rfile.read(min(length, 64 * 1024))
            if not chunk:
                break
            length -= len(chunk)

    def _require_writable(self) -> None:
        if self.server.read_only:
            raise PermissionError("read-only recovery mode blocks all mutations and GC")

    def _empty(self, status: int, **headers: str) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _error(self, error: Exception) -> None:
        if isinstance(error, BlockingIOError):
            status = HTTPStatus.LOCKED
        elif isinstance(error, PermissionError):
            status = HTTPStatus.FORBIDDEN
        elif isinstance(error, (KeyError, FileNotFoundError)):
            status = HTTPStatus.NOT_FOUND
        elif isinstance(error, FileExistsError):
            status = HTTPStatus.PRECONDITION_FAILED
        elif isinstance(error, IsADirectoryError):
            status = HTTPStatus.METHOD_NOT_ALLOWED
        elif isinstance(error, NotADirectoryError):
            status = HTTPStatus.CONFLICT
        elif isinstance(error, ValueError):
            status = HTTPStatus.BAD_REQUEST
        elif isinstance(error, OSError) and "not empty" in str(error):
            status = HTTPStatus.CONFLICT
        else:
            LOGGER.exception("WebDAV request failed", exc_info=error)
            status = HTTPStatus.BAD_GATEWAY
        message = str(error).encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(message)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(message)

    def _etag(self, path: str, entry: Entry) -> str:
        checksum = self.backend.checksum(path) if hasattr(self.backend, "checksum") else None
        version = self.backend.version(path) if hasattr(self.backend, "version") else None
        value = checksum or f"{entry.modified}:{entry.size}:{version or 0}"
        return '"' + hashlib.sha256(value.encode("utf-8")).hexdigest() + '"'

    @staticmethod
    def _href(path: str, is_dir: bool) -> str:
        parts = [urllib.parse.quote(part, safe="") for part in PurePosixPath(path).parts if part != "/"]
        href = "/" + "/".join(parts)
        if is_dir and not href.endswith("/"):
            href += "/"
        return href

    def _property_response(self, path: str, entry: Entry) -> ET.Element:
        response = ET.Element(f"{{{DAV}}}response")
        ET.SubElement(response, f"{{{DAV}}}href").text = self._href(path, entry.is_dir)
        propstat = ET.SubElement(response, f"{{{DAV}}}propstat")
        prop = ET.SubElement(propstat, f"{{{DAV}}}prop")
        ET.SubElement(prop, f"{{{DAV}}}displayname").text = entry.name or "/"
        resource_type = ET.SubElement(prop, f"{{{DAV}}}resourcetype")
        if entry.is_dir:
            ET.SubElement(resource_type, f"{{{DAV}}}collection")
        else:
            ET.SubElement(prop, f"{{{DAV}}}getcontentlength").text = str(entry.size)
            ET.SubElement(prop, f"{{{DAV}}}getcontenttype").text = (
                mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
            )
        ET.SubElement(prop, f"{{{DAV}}}getlastmodified").text = email.utils.formatdate(
            entry.modified or 0, usegmt=True
        )
        ET.SubElement(prop, f"{{{DAV}}}getetag").text = self._etag(path, entry)
        ET.SubElement(propstat, f"{{{DAV}}}status").text = "HTTP/1.1 200 OK"
        return response

    def do_OPTIONS(self) -> None:
        if not self._authenticated():
            return
        allow = "OPTIONS, PROPFIND, HEAD, GET" if self.server.read_only else (
            "OPTIONS, PROPFIND, HEAD, GET, PUT, DELETE, MOVE, MKCOL"
        )
        self._empty(
            HTTPStatus.NO_CONTENT,
            DAV="1",
            Allow=allow,
            MS_Author_Via="DAV",
        )

    def do_PROPFIND(self) -> None:
        if not self._authenticated():
            return
        try:
            self._discard_body()
            depth = self.headers.get("Depth", "infinity").lower()
            if depth not in {"0", "1"}:
                raise PermissionError("only PROPFIND Depth 0 and 1 are supported")
            path = self._path()
            entry = self.backend.stat(path)
            multistatus = ET.Element(f"{{{DAV}}}multistatus")
            multistatus.append(self._property_response(path, entry))
            if depth == "1" and entry.is_dir:
                for child in self.backend.list(path):
                    child_path = posixpath.join(path.rstrip("/"), child.name)
                    multistatus.append(self._property_response(child_path, child))
            body = ET.tostring(multistatus, encoding="utf-8", xml_declaration=True)
            self.send_response(HTTPStatus.MULTI_STATUS)
            self.send_header("DAV", "1")
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as error:
            self._error(error)

    def _send_file(self, *, head: bool) -> None:
        if not self._authenticated():
            return
        headers_sent = False
        try:
            path = self._path()
            entry = self.backend.stat(path)
            if entry.is_dir:
                raise IsADirectoryError(path)
            start, end = 0, max(0, entry.size - 1)
            status = HTTPStatus.OK
            range_header = self.headers.get("Range")
            if range_header:
                if not range_header.startswith("bytes=") or "," in range_header:
                    raise ValueError("only one byte range is supported")
                left, right = range_header[6:].split("-", 1)
                if left:
                    start = int(left)
                    end = int(right) if right else entry.size - 1
                else:
                    length = int(right)
                    start, end = max(0, entry.size - length), entry.size - 1
                if start < 0 or end < start or end >= entry.size:
                    self._empty(
                        HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                        Content_Range=f"bytes */{entry.size}",
                    )
                    return
                status = HTTPStatus.PARTIAL_CONTENT
            length = 0 if entry.size == 0 else end - start + 1
            self.send_response(status)
            self.send_header(
                "Content-Type", mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
            )
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", self._etag(path, entry))
            if status == HTTPStatus.PARTIAL_CONTENT:
                self.send_header("Content-Range", f"bytes {start}-{end}/{entry.size}")
            self.end_headers()
            headers_sent = True
            if not head and entry.size:
                self.backend.download(path, _SliceWriter(self.wfile, start, end))
        except Exception as error:
            if headers_sent:
                self.close_connection = True
                LOGGER.exception("WebDAV GET stream failed after headers", exc_info=error)
            else:
                self._error(error)

    def do_GET(self) -> None:
        self._send_file(head=False)

    def do_HEAD(self) -> None:
        self._send_file(head=True)

    def do_PUT(self) -> None:
        if not self._authenticated():
            return
        try:
            self._require_writable()
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("chunked HTTP transfer is not supported; send Content-Length")
            if "Content-Length" not in self.headers:
                self._empty(HTTPStatus.LENGTH_REQUIRED)
                return
            size = int(self.headers["Content-Length"])
            path = self._path()
            try:
                existed = not self.backend.stat(path).is_dir
            except (KeyError, FileNotFoundError):
                existed = False
            with self.coordinator.file_lock(path):
                changed = self.backend.upload_stream(path, self.rfile, size)
                self.coordinator.record_change("upload")
            headers = {"X_iCloud_Version_Unchanged": "true"} if not changed else {}
            self._empty(HTTPStatus.NO_CONTENT if existed else HTTPStatus.CREATED, **headers)
        except Exception as error:
            self.close_connection = True
            self._error(error)

    def do_MKCOL(self) -> None:
        if not self._authenticated():
            return
        try:
            self._require_writable()
            if int(self.headers.get("Content-Length", "0") or 0):
                raise ValueError("MKCOL request body is not supported")
            path = self._path()
            with self.coordinator.file_lock(path):
                self.backend.mkdir(path)
                self.coordinator.record_change("move")
            self._empty(HTTPStatus.CREATED)
        except Exception as error:
            self._error(error)

    def do_DELETE(self) -> None:
        if not self._authenticated():
            return
        try:
            self._require_writable()
            if self.coordinator.safe_mode():
                raise BlockingIOError("safe mode blocks DELETE and GC")
            path = self._path()
            with self.coordinator.file_lock(path):
                entry = self.backend.stat(path)
                self.backend.delete(path, directory=entry.is_dir)
                self.coordinator.record_change("delete")
            self._empty(HTTPStatus.NO_CONTENT)
        except Exception as error:
            self._error(error)

    def do_MOVE(self) -> None:
        if not self._authenticated():
            return
        try:
            self._require_writable()
            source, destination = self._path(), self._destination()
            overwrite = self.headers.get("Overwrite", "T").upper() != "F"
            destination_exists = False
            try:
                destination_entry = self.backend.stat(destination)
                destination_exists = True
            except (KeyError, FileNotFoundError):
                destination_entry = None
            if destination_exists and not overwrite:
                raise FileExistsError(destination)
            if destination_exists and self.coordinator.safe_mode():
                raise BlockingIOError("safe mode blocks overwriting MOVE")
            with contextlib.ExitStack() as stack:
                for item in sorted({source, destination}):
                    stack.enter_context(self.coordinator.file_lock(item))
                if destination_entry is not None:
                    self.backend.delete(destination, directory=destination_entry.is_dir)
                self.backend.rename(source, destination)
                self.coordinator.record_change("move")
            self._empty(HTTPStatus.NO_CONTENT if destination_exists else HTTPStatus.CREATED)
        except Exception as error:
            self._error(error)

    def log_message(self, format: str, *args) -> None:
        LOGGER.info("%s %s", self.address_string(), format % args)


def build_server(
    backend: DriveBackend,
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    coordinator: ValkeyCoordinator | None = None,
    certfile: Path | None = None,
    keyfile: Path | None = None,
    allow_insecure_remote: bool = False,
    read_only: bool = False,
) -> WebDAVServer:
    if not username or not password:
        raise ValueError("WebDAV username and password must not be empty")
    if bool(certfile) != bool(keyfile):
        raise ValueError("--certfile and --keyfile must be supplied together")
    if not certfile and not _is_loopback(host) and not allow_insecure_remote:
        raise ValueError(
            "Plain HTTP WebDAV may only bind to loopback; configure HTTPS or an "
            "internal TLS reverse proxy"
        )
    server = WebDAVServer(
        (host, port),
        WebDAVHandler,
        backend=backend,
        username=username,
        password=password,
        coordinator=coordinator or ValkeyCoordinator(None),
        read_only=read_only,
    )
    if certfile and keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
