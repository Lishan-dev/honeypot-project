from db.database import create_session, log_event
from analysis.stats import (
    attacks_per_day, attempts_per_ip, most_common_usernames,
    average_attempts_per_session, detection_rate,
)


def test_attacks_per_day_counts_connections(test_db):
    create_session("s1", "10.0.0.1", 1111)
    log_event("s1", "10.0.0.1", 1111, "connection")
    create_session("s2", "10.0.0.2", 2222)
    log_event("s2", "10.0.0.2", 2222, "connection")

    result = attacks_per_day()
    assert len(result) == 1
    assert result[0]["connections"] == 2


def test_attempts_per_ip_groups_correctly(test_db):
    create_session("s1", "10.0.0.1", 1111)
    log_event("s1", "10.0.0.1", 1111, "connection")
    log_event("s1", "10.0.0.1", 1111, "auth_attempt", username="root", password="x")
    create_session("s2", "10.0.0.2", 2222)
    log_event("s2", "10.0.0.2", 2222, "connection")

    result = attempts_per_ip()
    ip_map = {r["source_ip"]: r["total_events"] for r in result}
    assert ip_map["10.0.0.1"] == 2
    assert ip_map["10.0.0.2"] == 1


def test_most_common_usernames(test_db):
    create_session("s1", "10.0.0.1", 1111)
    log_event("s1", "10.0.0.1", 1111, "auth_attempt", username="admin", password="a")
    log_event("s1", "10.0.0.1", 1111, "auth_attempt", username="admin", password="b")
    log_event("s1", "10.0.0.1", 1111, "auth_attempt", username="root", password="c")

    result = most_common_usernames()
    assert result[0]["username"] == "admin"
    assert result[0]["attempts"] == 2


def test_average_attempts_per_session_empty_db(test_db):
    result = average_attempts_per_session()
    assert result["average"] == 0.0
    assert result["session_count"] == 0


def test_detection_rate_with_no_alerts(test_db):
    create_session("s1", "10.0.0.1", 1111)
    result = detection_rate()
    assert result["total_sessions"] == 1
    assert result["alerted_sessions"] == 0
    assert result["detection_rate_percent"] == 0.0
