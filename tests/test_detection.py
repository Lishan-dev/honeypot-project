from db.database import create_session, log_event
from detection.rules import run_detection_pass


def test_single_normal_session_produces_no_alerts(test_db):
    create_session("sess-a", "10.0.0.50", 60001)
    log_event("sess-a", "10.0.0.50", 60001, "connection")
    log_event("sess-a", "10.0.0.50", 60001, "auth_attempt", username="guest", password="guest")

    alerts = run_detection_pass()
    assert alerts == []


def test_repeated_auth_failures_triggers_medium_alert(test_db):
    create_session("sess-b", "10.0.0.51", 60002)
    for i in range(6):
        log_event("sess-b", "10.0.0.51", 60002, "auth_attempt", username=f"user{i}", password="x")

    alerts = run_detection_pass()
    rule_names = [a.rule_name for a in alerts]
    assert "repeated_auth_failures" in rule_names


def test_common_username_sweep_triggers(test_db):
    create_session("sess-c", "10.0.0.52", 60003)
    for user in ["root", "admin", "test", "guest"]:
        log_event("sess-c", "10.0.0.52", 60003, "auth_attempt", username=user, password="x")

    alerts = run_detection_pass()
    rule_names = [a.rule_name for a in alerts]
    assert "common_username_sweep" in rule_names


def test_suspicious_command_triggers_high_or_critical(test_db):
    create_session("sess-d", "10.0.0.53", 60004)
    log_event("sess-d", "10.0.0.53", 60004, "auth_attempt", username="admin", password="admin")
    log_event("sess-d", "10.0.0.53", 60004, "command_attempt", command_text="cat /etc/shadow")

    alerts = run_detection_pass()
    matching = [a for a in alerts if a.rule_name == "suspicious_command"]
    assert len(matching) == 1
    assert matching[0].severity in ("HIGH", "CRITICAL")


def test_rapid_connections_triggers_high_alert(test_db):
    for i in range(5):
        create_session(f"sess-rapid-{i}", "10.0.0.54", 60010 + i)

    alerts = run_detection_pass()
    rule_names = [a.rule_name for a in alerts]
    assert "rapid_connections" in rule_names


def test_multi_signal_escalates_to_critical(test_db):
    # Trigger both rapid_connections (HIGH) and suspicious_command (HIGH)
    # from the same source in the same pass -> multi_signal_critical
    for i in range(5):
        sid = f"sess-multi-{i}"
        create_session(sid, "10.0.0.55", 60020 + i)
    log_event("sess-multi-0", "10.0.0.55", 60020, "command_attempt", command_text="rm -rf /tmp/x")

    alerts = run_detection_pass()
    rule_names = [a.rule_name for a in alerts]
    assert "multi_signal_critical" in rule_names
    critical_alert = next(a for a in alerts if a.rule_name == "multi_signal_critical")
    assert critical_alert.severity == "CRITICAL"
