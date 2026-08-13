"""
Read-only web dashboard for the honeypot database.

SECURITY NOTE: this app never writes to events/sessions/alerts. Binds to
127.0.0.1 by default (see honeypot/config.py's DASHBOARD_HOST) -- change
that only deliberately, and pair it with DASHBOARD_USERNAME/PASSWORD if
you do, since this dashboard displays captured credential attempts.
"""
import csv
import io
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request

from dashboard import queries
from db.database import init_db, get_recent_events
from honeypot.config import get_config

app = Flask(__name__)


def requires_auth(f):
    """
    Minimal HTTP Basic Auth gate. Only enforced if DASHBOARD_USERNAME is
    set -- left blank (the default) for pure-localhost use, where an
    extra login prompt adds friction without adding real security (only
    you can reach 127.0.0.1 on your own machine).
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        config = get_config()
        if not config.DASHBOARD_USERNAME:
            return f(*args, **kwargs)

        auth = request.authorization
        if not auth or auth.username != config.DASHBOARD_USERNAME or auth.password != config.DASHBOARD_PASSWORD:
            return Response(
                "Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'}
            )
        return f(*args, **kwargs)

    return wrapped


@app.route("/")
@requires_auth
def index():
    reveal_passwords = request.args.get("reveal") == "1"
    return render_template(
        "index.html",
        stats=queries.get_summary_stats(),
        top_usernames=queries.get_top_usernames(),
        top_passwords=queries.get_top_passwords(),
        top_commands=queries.get_top_commands(),
        top_ips=queries.get_top_source_ips(),
        severity_dist=queries.get_severity_distribution(),
        attempts_over_time=queries.get_attempts_over_time(),
        recent_alerts=queries.get_recent_alerts(),
        recent_sessions=queries.get_recent_sessions(),
        reveal_passwords=reveal_passwords,
    )


@app.route("/session/<session_id>")
@requires_auth
def session_detail(session_id):
    detail = queries.get_session_detail(session_id)
    if not detail:
        return "Session not found", 404
    return render_template("session.html", **detail)


@app.route("/api/run-detection", methods=["POST"])
@requires_auth
def api_run_detection():
    """Lets the dashboard trigger an on-demand detection pass."""
    from detection.rules import run_detection_pass

    alerts = run_detection_pass()
    return jsonify({"alerts_generated": len(alerts)})


@app.route("/export/events.json")
@requires_auth
def export_events_json():
    with_limit = request.args.get("limit", "1000")
    limit = int(with_limit) if with_limit.isdigit() else 1000
    limit = min(limit, 10000)  # hard ceiling regardless of what's requested
    rows = [dict(r) for r in get_recent_events(limit=limit)]
    return jsonify(rows)


@app.route("/export/events.csv")
@requires_auth
def export_events_csv():
    with_limit = request.args.get("limit", "1000")
    limit = int(with_limit) if with_limit.isdigit() else 1000
    limit = min(limit, 10000)
    rows = [dict(r) for r in get_recent_events(limit=limit)]
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_events.csv"},
    )


@app.route("/export/alerts.json")
@requires_auth
def export_alerts_json():
    return jsonify(queries.get_recent_alerts(limit=1000))


def main():
    config = get_config()
    init_db()
    print("=" * 70)
    print(f" Honeypot Dashboard starting on http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    if not config.DASHBOARD_USERNAME:
        print(" NOTE: DASHBOARD_USERNAME is unset -- no login required.")
        print(" This is fine for 127.0.0.1-only use; set credentials before")
        print(" binding this dashboard to any wider interface.")
    print("=" * 70)
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=False)


if __name__ == "__main__":
    main()
