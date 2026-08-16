"""PostgreSQL-first state database with a SQLite test/migration fallback."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class HybridRow(dict):
    """Mapping row that also supports integer indexes like sqlite3.Row."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class CursorAdapter:
    def __init__(self, cursor, *, sqlite: bool):
        self.cursor = cursor
        self.sqlite = sqlite

    @staticmethod
    def _row(row):
        if row is None or isinstance(row, sqlite3.Row):
            return row
        return HybridRow(row)

    def fetchone(self):
        return self._row(self.cursor.fetchone())

    def fetchall(self):
        return [self._row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        for row in self.cursor:
            yield self._row(row)


class StateDatabase:
    """Tiny DB-API compatibility layer; PostgreSQL is required in production."""

    def __init__(self, target: str | Path):
        value = str(target)
        self.is_sqlite = not value.startswith(("postgresql://", "postgres://"))
        if self.is_sqlite:
            path = Path(value).expanduser().resolve()
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.connection = sqlite3.connect(
                path, check_same_thread=False, isolation_level=None
            )
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA foreign_keys=ON")
        else:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as error:
                raise RuntimeError(
                    "PostgreSQL support requires psycopg; reinstall project dependencies"
                ) from error
            self.connection = psycopg.connect(value, autocommit=True, row_factory=dict_row)

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> CursorAdapter:
        if not self.is_sqlite:
            sql = sql.replace("?", "%s")
        cursor = self.connection.execute(sql, parameters)
        return CursorAdapter(cursor, sqlite=self.is_sqlite)

    def executescript(self, script: str) -> None:
        if self.is_sqlite:
            self.connection.executescript(script)
            return
        for statement in script.split(";"):
            if statement.strip():
                self.connection.execute(statement)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self.is_sqlite:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()
        else:
            with self.connection.transaction():
                yield

    def select_current_for_update(self, path: str):
        suffix = "" if self.is_sqlite else " FOR UPDATE"
        return self.execute(
            "SELECT current_manifest, version FROM cas_files WHERE path=?" + suffix,
            (path,),
        ).fetchone()

    def close(self) -> None:
        self.connection.close()
