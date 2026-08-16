"""Small, synchronized adapter around icloudpy's Drive API."""

from __future__ import annotations

import logging
import os
import shutil
import threading
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Entry:
    name: str
    is_dir: bool
    size: int
    modified: float


class DriveBackend(Protocol):
    def list(self, path: str) -> list[Entry]: ...
    def stat(self, path: str) -> Entry: ...
    def download(self, path: str, destination: BinaryIO) -> None: ...
    def upload(self, path: str, source: Path) -> None: ...
    def mkdir(self, path: str) -> None: ...
    def delete(self, path: str, *, directory: bool) -> None: ...
    def rename(self, source: str, destination: str) -> None: ...


class _NamedReader:
    """Give a local stream the remote filename expected by icloudpy."""

    def __init__(self, raw: BinaryIO, name: str):
        self.raw = raw
        self.name = name

    def __getattr__(self, attr: str):
        return getattr(self.raw, attr)


class ICloudPyBackend:
    """Translate filesystem-like operations to ``icloudpy`` Drive nodes.

    icloudpy and requests sessions are not guaranteed to be thread-safe, so
    every operation is serialized. This still allows WebDAV network transfers to
    run independently while protecting the shared Apple session and node cache.
    """

    def __init__(self, service, *, cache_seconds: int = 5):
        self.service = service
        self.drive = service.drive
        self._lock = threading.RLock()
        self.cache_seconds = max(0, cache_seconds)
        self._cache_time = 0.0

    @staticmethod
    def _parts(path: str) -> tuple[str, ...]:
        path = path.replace("\\", "/")
        return tuple(part for part in PurePosixPath(path).parts if part not in ("/", ""))

    @staticmethod
    def _invalidate(node) -> None:
        node._children = None  # icloudpy's documented node API caches children
        node.data.pop("items", None)

    def _refresh_if_expired(self) -> None:
        now = time.monotonic()
        if self.cache_seconds == 0 or now - self._cache_time >= self.cache_seconds:
            self._invalidate(self.drive.root)
            self._cache_time = now

    def _changed(self) -> None:
        # Force the next operation to rebuild the hierarchy after a mutation.
        self._cache_time = 0.0

    def _resolve(self, path: str):
        node = self.drive.root
        for part in self._parts(path):
            node = node[part]
        return node

    def _parent(self, path: str):
        parts = self._parts(path)
        if not parts:
            raise PermissionError("iCloud Drive root cannot be modified")
        parent = self.drive.root
        for part in parts[:-1]:
            parent = parent[part]
        return parent, parts[-1]

    @staticmethod
    def _timestamp(value: datetime | None) -> float:
        if value is None:
            return 0.0
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()

    def _entry(self, node) -> Entry:
        changed = node.date_modified or node.date_changed or node.date_created
        return Entry(
            name=node.name,
            is_dir=node.type != "file",
            size=int(node.size or 0),
            modified=self._timestamp(changed),
        )

    def list(self, path: str) -> list[Entry]:
        with self._lock:
            self._refresh_if_expired()
            node = self._resolve(path)
            if node.type == "file":
                raise NotADirectoryError(path)
            return [self._entry(child) for child in node.get_children()]

    def stat(self, path: str) -> Entry:
        with self._lock:
            self._refresh_if_expired()
            if not self._parts(path):
                return Entry("/", True, 0, 0.0)
            return self._entry(self._resolve(path))

    def download(self, path: str, destination: BinaryIO) -> None:
        with self._lock:
            self._refresh_if_expired()
            node = self._resolve(path)
            if node.type != "file":
                raise IsADirectoryError(path)
            response = node.open(stream=True)
            with closing(response):
                shutil.copyfileobj(response.raw, destination, length=1024 * 1024)
            destination.seek(0)

    def upload(self, path: str, source: Path) -> None:
        """Upload using a temporary remote name, then switch names.

        Existing data is moved to iCloud's Trash only after the new object has
        uploaded successfully. If the final rename fails, the new data remains
        recoverable under its temporary name.
        """
        with self._lock:
            self._refresh_if_expired()
            parent, final_name = self._parent(path)
            old_node = None
            try:
                old_node = parent[final_name]
                if old_node.type != "file":
                    raise IsADirectoryError(path)
            except KeyError:
                pass

            suffix = PurePosixPath(final_name).suffix
            temporary_name = f".icloud-ftp-{uuid.uuid4().hex}{suffix}"
            with source.open("rb") as local_file:
                parent.upload(_NamedReader(local_file, temporary_name))

            self._invalidate(parent)
            uploaded = parent[temporary_name]
            if old_node is not None:
                old_node.delete()
                self._invalidate(parent)
                uploaded = parent[temporary_name]
            try:
                uploaded.rename(final_name)
            except Exception:
                LOGGER.exception(
                    "Final rename failed; uploaded data remains as %s", temporary_name
                )
                raise
            finally:
                self._invalidate(parent)
                self._changed()

    def mkdir(self, path: str) -> None:
        with self._lock:
            self._refresh_if_expired()
            parent, name = self._parent(path)
            try:
                parent[name]
            except KeyError:
                parent.mkdir(name)
                self._invalidate(parent)
                self._changed()
                return
            raise FileExistsError(path)

    def delete(self, path: str, *, directory: bool) -> None:
        with self._lock:
            self._refresh_if_expired()
            parent, name = self._parent(path)
            node = parent[name]
            is_dir = node.type != "file"
            if directory and not is_dir:
                raise NotADirectoryError(path)
            if not directory and is_dir:
                raise IsADirectoryError(path)
            if directory and node.get_children():
                raise OSError("directory is not empty")
            node.delete()
            self._invalidate(parent)
            self._changed()

    def rename(self, source: str, destination: str) -> None:
        with self._lock:
            self._refresh_if_expired()
            source_parent, source_name = self._parent(source)
            destination_parent, destination_name = self._parent(destination)
            if self._parts(source)[:-1] != self._parts(destination)[:-1]:
                raise OSError("icloudpy does not support moving items between folders")
            try:
                destination_parent[destination_name]
            except KeyError:
                pass
            else:
                raise FileExistsError(destination)
            source_parent[source_name].rename(destination_name)
            self._invalidate(source_parent)
            self._changed()
