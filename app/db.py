from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS equipment (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    responsible_user_id TEXT,
    current_user_id TEXT,
    current_room_id TEXT,
    current_since TEXT
);
CREATE TABLE IF NOT EXISTS contracts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    parties_json TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    clauses_json TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    completion TEXT,
    sla_id TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    deployed_block TEXT,
    violation_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS slas (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    document_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    model_id TEXT,
    contract_id TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    thing_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    equipment_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    block_index INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    contract_id TEXT,
    thing_id TEXT,
    user_id TEXT,
    equipment_id TEXT,
    room_id TEXT,
    action TEXT NOT NULL,
    ts TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    leader TEXT NOT NULL,
    layer TEXT NOT NULL,
    proto_hash TEXT NOT NULL,
    votes_json TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS disputes (
    id TEXT PRIMARY KEY,
    contract_id TEXT NOT NULL,
    claimant TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    block_hash TEXT,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_equipment ON events(equipment_id, ts);
CREATE INDEX IF NOT EXISTS idx_sessions_open ON sessions(status, equipment_id);
"""

TABLES = (
    "disputes",
    "events",
    "sessions",
    "slas",
    "contracts",
    "blocks",
    "equipment",
    "rooms",
    "users",
    "meta",
)


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._local = threading.local()

    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _depth(self) -> int:
        return getattr(self._local, "depth", 0)

    def _set_depth(self, value: int) -> None:
        self._local.depth = value

    def transaction(self):
        db = self

        class _Txn:
            def __enter__(self):
                db._lock.acquire()
                db._set_depth(db._depth() + 1)
                return db

            def __exit__(self, exc_type, exc, tb):
                try:
                    if db._depth() == 1:
                        if exc_type is None:
                            db._conn.commit()
                        else:
                            db._conn.rollback()
                finally:
                    db._set_depth(db._depth() - 1)
                    db._lock.release()
                return False

        return _Txn()

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cursor = self._conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.fetchall(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            if self._depth() == 0:
                self._conn.commit()

    def meta(self, key: str) -> str | None:
        row = self.fetchone("SELECT value FROM meta WHERE key = ?", (key,))
        return None if row is None else row["value"]

    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def wipe(self) -> None:
        with self._lock:
            for table in TABLES:
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.commit()
