"""Valkey leases and anomaly counters; correctness remains in PostgreSQL."""

from __future__ import annotations

import contextlib
import logging
import threading
import uuid
from collections.abc import Iterator

LOGGER = logging.getLogger(__name__)


class ValkeyCoordinator:
    def __init__(
        self,
        url: str | None,
        *,
        namespace: str = "default",
        lock_ttl: int = 120,
        change_limit: int = 1000,
        delete_ratio: float = 0.20,
        ratio_minimum_changes: int = 20,
    ):
        self.namespace = namespace
        self.lock_ttl = max(30, lock_ttl)
        self.change_limit = max(1, change_limit)
        self.delete_ratio = delete_ratio
        self.ratio_minimum_changes = max(1, ratio_minimum_changes)
        self.client = None
        if url:
            try:
                import redis

                self.client = redis.Redis.from_url(
                    url, decode_responses=True, socket_timeout=3
                )
                self.client.ping()
            except Exception:
                LOGGER.exception(
                    "Valkey unavailable; continuing with PostgreSQL conflict checks"
                )
                self.client = None

    def _key(self, value: str) -> str:
        return f"icloud-webdav:{self.namespace}:{value}"

    @contextlib.contextmanager
    def file_lock(self, file_id: str) -> Iterator[None]:
        if self.client is None:
            yield
            return
        key = self._key(f"lock:file:{file_id}")
        token = uuid.uuid4().hex
        try:
            acquired = self.client.set(key, token, nx=True, ex=self.lock_ttl)
        except Exception:
            LOGGER.exception(
                "Valkey lock unavailable; falling back to PostgreSQL conflict checks"
            )
            yield
            return
        if not acquired:
            raise BlockingIOError("another operation currently holds this file lock")
        stopped = threading.Event()

        def renew() -> None:
            script = (
                "if redis.call('get', KEYS[1]) == ARGV[1] then "
                "return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end"
            )
            while not stopped.wait(self.lock_ttl / 3):
                try:
                    if not self.client.eval(script, 1, key, token, self.lock_ttl):
                        LOGGER.error("Valkey file-lock lease was lost for %s", file_id)
                        return
                except Exception:
                    LOGGER.exception("Could not renew Valkey file lock")
                    return

        thread = threading.Thread(target=renew, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            script = (
                "if redis.call('get', KEYS[1]) == ARGV[1] then "
                "return redis.call('del', KEYS[1]) else return 0 end"
            )
            try:
                self.client.eval(script, 1, key, token)
            except Exception:
                LOGGER.exception("Could not release Valkey file lock")

    def record_change(self, operation: str) -> bool:
        """Increment five-minute counters and return the resulting safe mode."""
        if self.client is None:
            return False
        if operation not in {"upload", "delete", "move"}:
            raise ValueError("unknown mutation type")
        changes_key = self._key("changes:5min")
        operation_key = self._key(f"{operation}s:5min")
        try:
            pipeline = self.client.pipeline(transaction=True)
            pipeline.incr(changes_key)
            pipeline.expire(changes_key, 300)
            pipeline.incr(operation_key)
            pipeline.expire(operation_key, 300)
            results = pipeline.execute()
            changes = int(results[0])
            deletes = int(self.client.get(self._key("deletes:5min")) or 0)
            anomalous = changes >= self.change_limit or (
                changes >= self.ratio_minimum_changes
                and deletes / changes >= self.delete_ratio
            )
            if anomalous:
                self.client.set(self._key("safe_mode"), "1")
            return self.safe_mode()
        except Exception:
            LOGGER.exception("Valkey anomaly counters unavailable")
            return False

    def safe_mode(self) -> bool:
        try:
            return bool(self.client and self.client.get(self._key("safe_mode")) == "1")
        except Exception:
            LOGGER.exception("Valkey safe-mode state unavailable")
            return False

    def clear_safe_mode(self) -> None:
        if self.client:
            self.client.delete(self._key("safe_mode"))
