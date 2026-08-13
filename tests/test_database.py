from db.database import (
    create_session, close_session, log_event, log_alert,
    get_recent_events, get_recent_alerts, get_events_for_session,
    get_connection,
)


def test_create_session_and_log_event(test_db):
    create_session("sess-2", "10.0.0.6", 55002)
    event_id = log_event("sess-2", "10.0.0.6", 55002, "auth_attempt", username="admin", password="admin123")
    assert event_id is not None

    events = get_events_for_session("sess-2")
    assert len(events) == 1
    assert events[0]["username"] == "admin"
    assert events[0]["password"] == "admin123"


def test_sql_injection_payload_stored_as_inert_text(test_db):
    """
    The whole point of parameterized queries: a malicious-looking string
    in the password field must be stored as plain text, and must not
    affect the database structure or other rows.
    """
    payload = "'; DROP TABLE events; --"
    create_session("sess-3", "10.0.0.7", 55003)
    log_event("sess-3", "10.0.0.7", 55003, "auth_attempt", username="root", password=payload)

    events = get_events_for_session("sess-3")
    assert len(events) == 1
    assert events[0]["password"] == payload  # stored verbatim, not executed

    # The table must still exist and be queryable.
    all_events = get_recent_events(limit=10)
    assert isinstance(all_events, list)


def test_close_session_sets_ended_at_and_reason(test_db):
    create_session("sess-4", "10.0.0.8", 55004)
    close_session("sess-4", "client_disconnect")

    with get_connection(test_db) as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", ("sess-4",)).fetchone()
    assert row["ended_at"] is not None
    assert row["closed_reason"] == "client_disconnect"


def test_log_alert_and_get_recent_alerts(test_db):
    create_session("sess-5", "10.0.0.9", 55005)
    log_alert("10.0.0.9", "test_rule", "LOW", "Test alert reason", session_id="sess-5")

    alerts = get_recent_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "test_rule"
    assert alerts[0]["severity"] == "LOW"


def test_event_count_increments_on_session(test_db):
    create_session("sess-6", "10.0.0.10", 55006)
    log_event("sess-6", "10.0.0.10", 55006, "connection")
    log_event("sess-6", "10.0.0.10", 55006, "auth_attempt", username="x", password="y")

    with get_connection(test_db) as conn:
        row = conn.execute("SELECT event_count FROM sessions WHERE session_id = ?", ("sess-6",)).fetchone()
    assert row["event_count"] == 2
