"""
Detection engine: reads recent events, applies rule functions, writes
alerts. Every rule function takes a list of sqlite3.Row events (already
scoped to one source_ip's recent activity) and returns either None (rule
did not fire) or an Alert namedtuple describing what it found.

This module never touches a live socket and never executes anything from
event data -- it only reads rows and writes rows.
"""
import logging
from datetime import datetime, timedelta, timezone
from collections import namedtuple

from db import database

logger = logging.getLogger("honeypot.detection")

Alert = namedtuple("Alert", ["rule_name", "severity", "reason", "event_ids"])

# ---------------------------------------------------------------------
# Reference data used by a couple of the rules
# ---------------------------------------------------------------------

COMMON_ATTACK_USERNAMES = {
    "root", "admin", "administrator", "test", "guest", "user",
    "ubuntu", "oracle", "postgres", "pi", "support", "ftpuser",
}

SUSPICIOUS_COMMAND_KEYWORDS = {
    "wget", "curl", "nc", "netcat", "chmod +x", "base64 -d", "/etc/shadow",
    "/etc/passwd", "rm -rf", "history -c", "crontab", "scp", "python -c",
    "perl -e", "nohup", ":(){ :|:& };:",  # fork bomb pattern, string only -- never executed
}

RAPID_CONNECTION_WINDOW = timedelta(seconds=30)
RAPID_CONNECTION_THRESHOLD = 4  # 4+ new sessions from one IP within the window

# ---------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------

def rule_repeated_auth_failures(events: list, source_ip: str) -> Alert | None:
    """MEDIUM+ : many failed logins from the same source."""
    auth_events = [e for e in events if e["event_type"] == "auth_attempt"]
    if len(auth_events) < 5:
        return None

    severity = "HIGH" if len(auth_events) >= 15 else "MEDIUM"
    return Alert(
        rule_name="repeated_auth_failures",
        severity=severity,
        reason=f"{len(auth_events)} authentication attempts from {source_ip} "
               f"(threshold: 5 MEDIUM / 15 HIGH). Consistent with a scripted "
               f"credential-stuffing or brute-force attempt.",
        event_ids=[e["event_id"] for e in auth_events],
    )


def rule_common_username_sweep(events: list, source_ip: str) -> Alert | None:
    """MEDIUM : attacker tried multiple usernames from a known common-attack list."""
    auth_events = [e for e in events if e["event_type"] == "auth_attempt" and e["username"]]
    usernames_tried = {e["username"].strip().lower() for e in auth_events}
    matched = usernames_tried & COMMON_ATTACK_USERNAMES

    if len(matched) < 3:
        return None

    return Alert(
        rule_name="common_username_sweep",
        severity="MEDIUM",
        reason=f"{len(matched)} common default/attack usernames attempted "
               f"({', '.join(sorted(matched))}). Suggests use of a standard "
               f"username wordlist rather than a targeted guess.",
        event_ids=[e["event_id"] for e in auth_events if e["username"].strip().lower() in matched],
    )


def rule_rapid_connections(source_ip: str) -> Alert | None:
    """HIGH : many new sessions from the same IP in a short time window -- automation, not a human."""
    with database.get_connection() as conn:
        cutoff = (datetime.now(timezone.utc) - RAPID_CONNECTION_WINDOW).isoformat()
        rows = conn.execute(
            "SELECT session_id, started_at FROM sessions WHERE source_ip = ? AND started_at >= ?",
            (source_ip, cutoff),
        ).fetchall()

    if len(rows) < RAPID_CONNECTION_THRESHOLD:
        return None

    return Alert(
        rule_name="rapid_connections",
        severity="HIGH",
        reason=f"{len(rows)} separate connections from {source_ip} within "
               f"{int(RAPID_CONNECTION_WINDOW.total_seconds())} seconds -- "
               f"far faster than manual/interactive use, consistent with an "
               f"automated scanning or brute-force tool.",
        event_ids=[],  # this rule is session-based rather than event-based
    )


def rule_suspicious_command(events: list, source_ip: str) -> Alert | None:
    """HIGH/CRITICAL : post-login command attempts matching known attacker tooling patterns."""
    command_events = [e for e in events if e["event_type"] == "command_attempt" and e["command_text"]]
    if not command_events:
        return None

    matches = []
    for e in command_events:
        cmd_lower = e["command_text"].lower()
        hit_keywords = [kw for kw in SUSPICIOUS_COMMAND_KEYWORDS if kw in cmd_lower]
        if hit_keywords:
            matches.append((e, hit_keywords))

    if not matches:
        return None

    destructive_hit = any(
        kw in ("rm -rf", "/etc/shadow", ":(){ :|:& };:") for _, kws in matches for kw in kws
    )
    severity = "CRITICAL" if destructive_hit else "HIGH"

    examples = "; ".join(f"{kws[0]!r} in {e['command_text']!r}" for e, kws in matches[:3])
    return Alert(
        rule_name="suspicious_command",
        severity=severity,
        reason=f"{len(matches)} command attempt(s) matched known attacker-tooling "
               f"patterns (e.g. download-and-execute, credential-file access, "
               f"destructive commands). Examples: {examples}",
        event_ids=[e["event_id"] for e, _ in matches],
    )


def rule_multi_signal_critical(fired_alerts: list[Alert], source_ip: str) -> Alert | None:
    """
    CRITICAL : escalation rule -- if this source already triggered 2+
    HIGH-or-above alerts in this pass, raise one combined CRITICAL alert
    summarizing the overall picture.
    """
    high_or_above = [a for a in fired_alerts if a.severity in ("HIGH", "CRITICAL")]
    if len(high_or_above) < 2:
        return None

    rule_names = ", ".join(a.rule_name for a in high_or_above)
    all_event_ids = sorted({eid for a in high_or_above for eid in a.event_ids})
    return Alert(
        rule_name="multi_signal_critical",
        severity="CRITICAL",
        reason=f"Multiple high-severity indicators from {source_ip} in the same "
               f"pass ({rule_names}). Combination of signals suggests an active, "
               f"capable attacker rather than an isolated automated probe.",
        event_ids=all_event_ids,
    )


# ---------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------

ALL_EVENT_RULES = [rule_repeated_auth_failures, rule_common_username_sweep, rule_suspicious_command]


def _get_recent_source_ips(lookback: timedelta) -> list[str]:
    with database.get_connection() as conn:
        cutoff = (datetime.now(timezone.utc) - lookback).isoformat()
        rows = conn.execute(
            "SELECT DISTINCT source_ip FROM events WHERE timestamp >= ?", (cutoff,)
        ).fetchall()
    return [r["source_ip"] for r in rows]


def _get_latest_session_id(source_ip: str) -> str | None:
    """
    Rules operate per source IP and can span multiple sessions, so there
    isn't always one exact session an alert belongs to. We attribute the
    alert to that IP's most recent session as a best-effort link -- good
    enough for "drill into the session that likely triggered this" from
    the dashboard, and for analysis.stats.detection_rate() to have
    something meaningful to count against.
    """
    with database.get_connection() as conn:
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE source_ip = ? ORDER BY started_at DESC LIMIT 1",
            (source_ip,),
        ).fetchone()
    return row["session_id"] if row else None


def run_detection_pass(lookback_minutes: int = 15) -> list[Alert]:
    """
    Runs every rule against every source IP with recent activity, writes
    any resulting alerts to the database, and returns them (handy for
    testing and for the dashboard's "run detection now" action).
    """
    lookback = timedelta(minutes=lookback_minutes)
    all_fired: list[Alert] = []

    for source_ip in _get_recent_source_ips(lookback):
        events = database.get_recent_events(limit=500, source_ip=source_ip)

        fired_for_ip: list[Alert] = []
        for rule in ALL_EVENT_RULES:
            alert = rule(events, source_ip)
            if alert:
                fired_for_ip.append(alert)

        rapid = rule_rapid_connections(source_ip)
        if rapid:
            fired_for_ip.append(rapid)

        escalation = rule_multi_signal_critical(fired_for_ip, source_ip)
        if escalation:
            fired_for_ip.append(escalation)

        latest_session_id = _get_latest_session_id(source_ip) if fired_for_ip else None
        for alert in fired_for_ip:
            database.log_alert(
                source_ip=source_ip,
                rule_name=alert.rule_name,
                severity=alert.severity,
                reason=alert.reason,
                event_ids=alert.event_ids,
                session_id=latest_session_id,
            )
            logger.info("ALERT [%s] %s: %s", alert.severity, alert.rule_name, source_ip)

        all_fired.extend(fired_for_ip)

    return all_fired


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    found = run_detection_pass()
    print(f"Detection pass complete: {len(found)} alert(s) generated.")
