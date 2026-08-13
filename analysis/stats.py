"""
Statistical analysis over the honeypot dataset. Everything here reads
from the database (via db.database.get_connection) -- nothing here
writes to events/sessions/alerts, and nothing here touches a live socket.

Intended for after-the-fact analysis (e.g. writing up project results),
as distinct from dashboard/queries.py which serves the live dashboard.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

from db.database import get_connection


# ---------------------------------------------------------------------
# Core statistics
# ---------------------------------------------------------------------

def attacks_per_day() -> list[dict]:
    """
    Number of connection events per calendar day (UTC).

    Why it matters: attack volume over time is the first thing a SOC
    analyst looks at -- a sudden spike often means a new campaign, a scan
    sweep hitting your IP range, or a botnet picking up your address.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp FROM events WHERE event_type = 'connection' ORDER BY timestamp ASC"
        ).fetchall()

    counts = Counter()
    for row in rows:
        day = datetime.fromisoformat(row["timestamp"]).date().isoformat()
        counts[day] += 1

    return [{"date": day, "connections": count} for day, count in sorted(counts.items())]


def attempts_per_ip() -> list[dict]:
    """
    Total events attributed to each source IP, plus how many distinct
    sessions that IP opened.

    Why it matters: distinguishes "one IP hammering the honeypot
    relentlessly" (likely a dedicated scanner/bot) from "many different
    IPs each trying once or twice" (broad, low-effort internet-wide
    scanning).
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT source_ip,
                   COUNT(*) AS total_events,
                   COUNT(DISTINCT session_id) AS session_count
            FROM events
            GROUP BY source_ip
            ORDER BY total_events DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def most_common_usernames(limit: int = 15) -> list[dict]:
    """
    Why it matters: the specific usernames attackers try reveal what
    they assume about the target -- lots of 'root'/'admin' attempts
    suggests generic scanning; product-specific usernames (e.g. 'pi' for
    Raspberry Pi, 'oracle' for database servers) suggest the scanner is
    targeting a particular class of device or service.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT username, COUNT(*) AS attempts
            FROM events WHERE event_type = 'auth_attempt' AND username IS NOT NULL AND username != ''
            GROUP BY username ORDER BY attempts DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def most_common_passwords(limit: int = 15) -> list[dict]:
    """
    Why it matters: this is essentially free, passive threat intelligence
    on which weak/default passwords are actively being tried in the wild
    right now. A high hit rate on very simple passwords (123456,
    password, admin) confirms these remain effective against real
    misconfigured systems.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT password, COUNT(*) AS attempts
            FROM events WHERE event_type = 'auth_attempt' AND password IS NOT NULL AND password != ''
            GROUP BY password ORDER BY attempts DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def average_attempts_per_session() -> dict:
    """
    Why it matters: a low average (close to 1) suggests most connections
    are quick single-shot probes. A high average suggests more
    persistent, scripted brute-force behavior. Comparing the mean to the
    max is also useful: a mean of 2 with a max of 40 tells you the
    average is being dragged down by lots of one-off scans while a few
    sessions are doing the real brute-forcing.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT session_id, COUNT(*) AS attempts
            FROM events WHERE event_type = 'auth_attempt'
            GROUP BY session_id
            """
        ).fetchall()

    if not rows:
        return {"average": 0.0, "min": 0, "max": 0, "session_count": 0}

    counts = [r["attempts"] for r in rows]
    return {
        "average": round(sum(counts) / len(counts), 2),
        "min": min(counts),
        "max": max(counts),
        "session_count": len(counts),
    }


def attack_frequency(window_hours: int = 24) -> dict:
    """
    Connections per hour over the requested window, plus the busiest
    single hour.

    Why it matters: frequency (not just total volume) tells you whether
    activity is bursty (automated scan sweeps) or steady (consistent
    with a slow, low-and-slow probing style intended to stay under
    naive rate-based detection).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp FROM events WHERE event_type = 'connection' AND timestamp >= ?",
            (cutoff.isoformat(),),
        ).fetchall()

    if not rows:
        return {"connections_per_hour": 0.0, "busiest_hour": None, "busiest_hour_count": 0, "total": 0}

    hour_counts = Counter()
    for row in rows:
        ts = datetime.fromisoformat(row["timestamp"])
        hour_key = ts.strftime("%Y-%m-%d %H:00")
        hour_counts[hour_key] += 1

    busiest_hour, busiest_count = hour_counts.most_common(1)[0]
    return {
        "connections_per_hour": round(len(rows) / window_hours, 2),
        "busiest_hour": busiest_hour,
        "busiest_hour_count": busiest_count,
        "total": len(rows),
    }


def detection_rate() -> dict:
    """
    What fraction of sessions triggered at least one alert.

    Why it matters: the closest thing this project has to a "how good is
    our detection engine" metric. A very low rate might mean thresholds
    are too strict; a very high rate might mean thresholds are too loose
    (alert fatigue). There's no ground truth for false negatives here --
    every interaction with the honeypot is inherently unauthorized by
    definition -- so this measures "how much activity crossed an
    alerting threshold," not classification accuracy in the formal sense.
    """
    with get_connection() as conn:
        total_sessions = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        alerted_sessions = conn.execute(
            "SELECT COUNT(DISTINCT session_id) AS c FROM alerts WHERE session_id IS NOT NULL"
        ).fetchone()["c"]

    rate = round((alerted_sessions / total_sessions) * 100, 1) if total_sessions else 0.0
    return {
        "total_sessions": total_sessions,
        "alerted_sessions": alerted_sessions,
        "detection_rate_percent": rate,
    }


def severity_breakdown() -> dict:
    """
    Why it matters: the shape of this distribution is itself informative
    -- mostly LOW/MEDIUM with occasional HIGH/CRITICAL is a "healthy"
    profile for a honeypot that isn't being specifically targeted; a
    distribution skewed toward HIGH/CRITICAL might mean you're seeing
    more capable, deliberate attackers.
    """
    with get_connection() as conn:
        rows = conn.execute("SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity").fetchall()
    counts = {r["severity"]: r["c"] for r in rows}
    return {level: counts.get(level, 0) for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}


# ---------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------

def generate_full_report() -> dict:
    """Bundles every statistic above into one dict."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attacks_per_day": attacks_per_day(),
        "attempts_per_ip": attempts_per_ip(),
        "most_common_usernames": most_common_usernames(),
        "most_common_passwords": most_common_passwords(),
        "average_attempts_per_session": average_attempts_per_session(),
        "attack_frequency_24h": attack_frequency(24),
        "detection_rate": detection_rate(),
        "severity_breakdown": severity_breakdown(),
    }


def print_report() -> None:
    report = generate_full_report()

    print("=" * 70)
    print(f" HONEYPOT ANALYSIS REPORT -- generated {report['generated_at']}")
    print("=" * 70)

    print("\n-- Attacks Per Day --")
    for row in report["attacks_per_day"]:
        print(f"  {row['date']}: {row['connections']} connections")

    print("\n-- Top Source IPs --")
    for row in report["attempts_per_ip"][:10]:
        print(f"  {row['source_ip']}: {row['total_events']} events across {row['session_count']} session(s)")

    print("\n-- Most Common Usernames --")
    for row in report["most_common_usernames"][:10]:
        print(f"  {row['username']}: {row['attempts']} attempts")

    print("\n-- Most Common Passwords --")
    for row in report["most_common_passwords"][:10]:
        print(f"  {row['password']}: {row['attempts']} attempts")

    aaps = report["average_attempts_per_session"]
    print("\n-- Average Attempts Per Session --")
    print(f"  average={aaps['average']}  min={aaps['min']}  max={aaps['max']}  (n={aaps['session_count']} sessions)")

    freq = report["attack_frequency_24h"]
    print("\n-- Attack Frequency (last 24h) --")
    print(f"  {freq['connections_per_hour']} connections/hour  "
          f"(busiest hour: {freq['busiest_hour']} with {freq['busiest_hour_count']})")

    det = report["detection_rate"]
    print("\n-- Detection Rate --")
    print(f"  {det['alerted_sessions']}/{det['total_sessions']} sessions triggered an alert "
          f"({det['detection_rate_percent']}%)")

    print("\n-- Alert Severity Breakdown --")
    for level, count in report["severity_breakdown"].items():
        print(f"  {level}: {count}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print_report()
