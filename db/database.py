"""
Data access layer for the honeypot project.

SECURITY NOTE: every function in this module uses parameterized queries
(the "?" placeholders below) rather than string formatting. This is not
a style preference -- it's what prevents a malicious username/password/
command string from being interpreted as SQL. Never change a query in
this file to use f-strings or .format() to insert values.
"""
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from honeypot.config import get_config

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: Optional[str] = None) -> None:
    """
    Creates the database file and applies the schema if it doesn't exist
    yet. Also locks down file permissions on POSIX systems, since this
    file will contain captured (fake-service) credentials.

    NOTE: every other function in this module (create_session, log_event,
    get_connection, etc.) always resolves its database file from
    get_config().DB_PATH -- they do not accept a db_path override. If you
    pass a custom db_path here, make sure DB_PATH is set to the same
    value (e.g. via environment variable) *before* this module is first
    imported, or those other functions will read/write a different file
    than the one you just initialized. Tests handle this by setting the
    DB_PATH environment variable in conftest.py before any app import.
    """
    db_path = db_path or get_config().DB_PATH
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()

    # Restrict to owner read/write only (no-op on Windows, which is fine --
    # NTFS permissions default to something reasonable and differ enough
    # that we don't try to replicate this logic there).
    if os.name == "posix":
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)


@contextmanager
def get_connection(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    """Context-managed connection with row access by column name."""
    db_path = db_path or get_config().DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------

def create_session(session_id: str, source_ip: str, source_port: int) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (session_id, source_ip, source_port, started_at, event_count)
            VALUES (?, ?, ?, ?, 0)
            """,
            (session_id, source_ip, source_port, _utcnow_iso()),
        )
        conn.commit()


def close_session(session_id: str, reason: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET ended_at = ?, closed_reason = ? WHERE session_id = ?",
            (_utcnow_iso(), reason, session_id),
        )
        conn.commit()


# ---------------------------------------------------------------------
# Event logging
# ---------------------------------------------------------------------

def log_event(
    session_id: str,
    source_ip: str,
    source_port: int,
    event_type: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    command_text: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> int:
    """
    Records one event. All attacker-supplied fields (username, password,
    command_text) are passed as bound parameters -- see the module
    docstring. Returns the new event_id.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO events
                (session_id, timestamp, source_ip, source_port, event_type,
                 username, password, command_text, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                _utcnow_iso(),
                source_ip,
                source_port,
                event_type,
                username,
                password,
                command_text,
                json.dumps(metadata) if metadata else None,
            ),
        )
        conn.execute(
            "UPDATE sessions SET event_count = event_count + 1 WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()
        return cursor.lastrowid


# ---------------------------------------------------------------------
# Alert logging (used by the detection engine)
# ---------------------------------------------------------------------

def log_alert(
    source_ip: str,
    rule_name: str,
    severity: str,
    reason: str,
    session_id: Optional[str] = None,
    event_ids: Optional[list[int]] = None,
) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (created_at, source_ip, session_id, rule_name, severity, reason, event_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _utcnow_iso(),
                source_ip,
                session_id,
                rule_name,
                severity,
                reason,
                json.dumps(event_ids) if event_ids else None,
            ),
        )
        conn.commit()
        return cursor.lastrowid


# ---------------------------------------------------------------------
# Read helpers (used by detection engine + dashboard)
# ---------------------------------------------------------------------

def get_recent_events(limit: int = 200, source_ip: Optional[str] = None) -> list[sqlite3.Row]:
    query = "SELECT * FROM events"
    params: tuple = ()
    if source_ip:
        query += " WHERE source_ip = ?"
        params = (source_ip,)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params = params + (limit,)
    with get_connection() as conn:
        return conn.execute(query, params).fetchall()


def get_events_for_session(session_id: str) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY event_id ASC",
            (session_id,),
        ).fetchall()


def get_recent_alerts(limit: int = 100) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
