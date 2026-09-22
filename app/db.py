"""Small SQLite persistence layer used by the FastAPI application.

The database only stores account metadata, public keys, encrypted envelopes,
and audit metadata.  It deliberately has no column for message plaintext or
private key material.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


APP_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE = APP_ROOT / "data" / "messaging.sqlite3"


def database_path() -> Path:
    """Return the configured database path, creating its parent on demand."""

    configured = os.environ.get("MESSAGING_DATABASE") or os.environ.get("DATABASE_PATH")
    path = Path(configured).expanduser() if configured else DEFAULT_DATABASE
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    """Yield a short-lived connection with safe SQLite defaults."""

    conn = sqlite3.connect(database_path(), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize() -> None:
    """Create the schema and enable WAL for concurrent websocket clients."""

    with connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                ed25519_pub TEXT NOT NULL,
                x25519_pub TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT NOT NULL UNIQUE,
                sender TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                recipient TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                envelope TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending
                ON messages(recipient, delivered_at, id);
            CREATE INDEX IF NOT EXISTS idx_messages_sender
                ON messages(sender, id);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                event TEXT NOT NULL,
                target TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_actor_created
                ON audit_events(actor, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_target_created
                ON audit_events(target, created_at DESC);
            """
        )


def create_user(
    username: str,
    password_hash: str,
    ed25519_pub: str,
    x25519_pub: str,
    is_admin: bool = False,
) -> bool:
    with connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, ed25519_pub, x25519_pub, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, ed25519_pub, x25519_pub, int(is_admin), utc_now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def get_user(username: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT username, ed25519_pub, x25519_pub, created_at
            FROM users ORDER BY username COLLATE NOCASE
            """
        ).fetchall()
        return [dict(row) for row in rows]


def enqueue_message(
    msg_id: str,
    sender: str,
    recipient: str,
    envelope: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    """Persist an envelope; return its record and whether it was newly inserted."""

    encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
    with connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO messages (msg_id, sender, recipient, envelope, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (msg_id, sender, recipient, encoded, utc_now()),
            )
            row = conn.execute("SELECT * FROM messages WHERE msg_id = ?", (msg_id,)).fetchone()
            return dict(row), True
        except sqlite3.IntegrityError:
            row = conn.execute("SELECT * FROM messages WHERE msg_id = ?", (msg_id,)).fetchone()
            if row is None:
                raise
            return dict(row), False


def pending_messages(recipient: str) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT id, msg_id, sender, recipient, envelope, created_at, delivered_at
            FROM messages
            WHERE recipient = ? AND delivered_at IS NULL
            ORDER BY id ASC
            """,
            (recipient,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["envelope"] = json.loads(item["envelope"])
            result.append(item)
        return result

def mark_delivered(msg_id: str, recipient: str) -> bool:
    with connection() as conn:
        cur = conn.execute(
            """
            UPDATE messages
            SET delivered_at = COALESCE(delivered_at, ?)
            WHERE msg_id = ? AND recipient = ?
            """,
            (utc_now(), msg_id, recipient),
        )
        return cur.rowcount > 0


def get_message(msg_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM messages WHERE msg_id = ?", (msg_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["envelope"] = json.loads(item["envelope"])
        return item


def add_audit(
    actor: str | None,
    event: str,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    # Metadata is intentionally caller-controlled but always JSON, never an
    # envelope or plaintext payload.  Keep this function small and auditable.
    safe_metadata = metadata or {}
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (actor, event, target, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor,
                event,
                target,
                json.dumps(safe_metadata, separators=(",", ":"), ensure_ascii=False),
                utc_now(),
            ),
        )


def list_audit(username: str, is_admin: bool, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 500))
    with connection() as conn:
        if is_admin:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE actor = ? OR target = ?
                ORDER BY id DESC LIMIT ?
                """,
                (username, username, limit),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["metadata"] = json.loads(item["metadata"])
            except (TypeError, json.JSONDecodeError):
                item["metadata"] = {}
            result.append(item)
        return result
