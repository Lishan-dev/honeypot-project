"""
Read-only aggregation queries for the dashboard. Every function here only
SELECTs -- nothing in this module writes to the database. Parameterized
queries throughout, consistent with db/database.py.
"""
from datetime import datetime, timedelta, timezone

from db.database import get_connection


def get_summary_stats() -> dict:
    with get_connection() as conn:
        total_connections = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE event_type = 'connection'"
        ).fetchone()["c"]

        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) AS c FROM events"
        ).fetchone()["c"]

        total_auth_attempts = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE event_type = 'auth_attempt'"
        ).fetchone()["c"]

        total_commands = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE event_type = 'command_attempt'"
        ).fetchone()["c"]

        total_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

        active_sessions = conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE ended_at IS NULL"
        ).fetchone()["c"]

    return {
        "total_connections": total_connections,
        "unique_ips": unique_ips,
        "total_auth_attempts": total_auth_attempts,
        "total_commands": total_commands,
        "total_alerts": total_alerts,
        "active_sessions": active_sessions,
    }


def get_top_usernames(limit: int = 10) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT username, COUNT(*) AS attempts
            FROM events
            WHERE event_type = 'auth_attempt' AND username IS NOT NULL AND username != ''
            GROUP BY username
            ORDER BY attempts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_passwords(limit: int = 10) -> list[dict]:
    """
    Returns the most frequently attempted passwords. These are fake
    credentials against a fake service with no real access -- there is
    no real secret being exposed here -- but we still mask them by
    default in the template since password-reuse patterns can be
    sensitive even when fake.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT password, COUNT(*) AS attempts
            FROM events
            WHERE event_type = 'auth_attempt' AND password IS NOT NULL AND password != ''
            GROUP BY password
            ORDER BY attempts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_commands(limit: int = 10) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT command_text, COUNT(*) AS attempts
            FROM events
            WHERE event_type = 'command_attempt' AND command_text IS NOT NULL AND command_text != ''
            GROUP BY command_text
            ORDER BY attempts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_source_ips(limit: int = 10) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) AS event_count, COUNT(DISTINCT session_id) AS session_count
            FROM events
            GROUP BY source_ip
            ORDER BY event_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_severity_distribution() -> dict:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()
    counts = {r["severity"]: r["c"] for r in rows}
    return {level: counts.get(level, 0) for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}


def get_attempts_over_time(hours: int = 24, bucket_minutes: int = 60) -> list[dict]:
    """
    Buckets connection events into fixed time windows for a time-series
    chart. Done in Python rather than SQL date-bucketing so this stays
    portable if you swap SQLite for another database later.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp FROM events WHERE event_type = 'connection' AND timestamp >= ? ORDER BY timestamp ASC",
            (cutoff.isoformat(),),
        ).fetchall()

    buckets: dict[str, int] = {}
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        bucket_start = ts - timedelta(
            minutes=ts.minute % bucket_minutes, seconds=ts.second, microseconds=ts.microsecond
        )
        key = bucket_start.strftime("%Y-%m-%d %H:%M")
        buckets[key] = buckets.get(key, 0) + 1

    return [{"bucket": k, "count": v} for k, v in sorted(buckets.items())]


def get_recent_alerts(limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_recent_sessions(limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_session_detail(session_id: str) -> dict | None:
    with get_connection() as conn:
        session = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not session:
            return None
        events = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY event_id ASC", (session_id,)
        ).fetchall()
    return {"session": dict(session), "events": [dict(e) for e in events]}
