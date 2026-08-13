# 🍯 Honeypot for Attack Detection

A low-interaction network honeypot for **defensive cybersecurity research and education**, built for use entirely within an isolated lab environment. It presents a fake SSH-like login service, captures connection/authentication/command attempts as inert data, runs a rule-based detection engine over what it captures, and visualizes everything on a live dashboard.

> ⚠️ **This tool is for isolated lab use only.** Never expose it to the public internet or any network you do not own or have explicit authorization to test. See [Security and Ethical Considerations](docs/Honeypot_Project_Documentation.md#14-security-and-ethical-considerations) in the full project documentation.

## What this is

- A fake TCP service that looks like an SSH login prompt, always rejects authentication, and (optionally) drops into a fake shell that logs typed commands as plain strings — **never executes them**.
- A structured SQLite log of every connection, authentication attempt, and command attempt.
- A rule-based detection engine that flags suspicious patterns (repeated failed logins, common-username sweeps, rapid connection bursts, known attacker-tooling command patterns) with LOW/MEDIUM/HIGH/CRITICAL severity and a human-readable reason for each.
- A read-only Flask dashboard: live metrics, charts, top usernames/passwords/commands/source IPs, recent alerts, and per-session drill-down.
- A statistical analysis module for after-the-fact reporting (attacks per day, attempts per IP, detection rate, etc.), each metric explained from a cybersecurity perspective.
- A safe traffic simulator for generating test scenarios against your own lab instance only.

Full design rationale, threat model, architecture diagrams, and write-up structure are in **[docs/Honeypot_Project_Documentation.md](docs/Honeypot_Project_Documentation.md)**.

## Project Structure

```
honeypot-project/
├── honeypot/            # Fake TCP service, config, banners, Dockerfile
│   ├── service.py        # asyncio server -- the only component touching untrusted input
│   ├── banners.py         # fake login/shell prompt text
│   ├── config.py           # env-var driven configuration
│   └── Dockerfile
├── db/                   # SQLite schema + parameterized data access layer
│   ├── schema.sql
│   └── database.py
├── detection/             # Rule-based detection engine
│   └── rules.py
├── dashboard/              # Read-only Flask web dashboard
│   ├── app.py
│   ├── queries.py
│   ├── templates/
│   └── static/
├── testing/                # Isolated-lab traffic simulator + safe-testing procedure
│   ├── simulate_traffic.py
│   └── README.md
├── analysis/                # Statistical reporting
│   └── stats.py
├── tests/                    # pytest suite (database, detection, stats)
├── docs/
│   └── Honeypot_Project_Documentation.md   # full write-up: abstract through conclusion
├── docker-compose.lab.yml     # isolated lab network (not a production deployment)
├── .env.example
├── requirements.txt
└── LICENSE
```

## Quick Start (local, no Docker)

Requires Python 3.10+.

```bash
pip install -r requirements.txt
cp .env.example .env
mkdir -p data
```

**Terminal 1 — start the honeypot:**
```bash
python3 -m honeypot.service
```

**Terminal 2 — start the dashboard:**
```bash
python3 -m dashboard.app
# Visit http://127.0.0.1:5000
```

**Terminal 3 — generate safe test traffic (from your own machine, targeting your own honeypot):**
```bash
python3 testing/simulate_traffic.py --target 127.0.0.1 --port 2222 --confirm-lab --scenario all
```

Then click **Run Detection Now** on the dashboard, or run:
```bash
python3 -m detection.rules
python3 -m analysis.stats
```

This local quick start is fine for solo experimentation on your own machine. For anything resembling a real "attacker vs. target" setup, use the isolated lab described next and in `testing/README.md`.

## Isolated Lab Setup (recommended for real testing)

```bash
docker network create --internal honeypot-lab-net
docker compose -f docker-compose.lab.yml up -d --build

# Get a shell on the "attacker" side of the isolated network
docker exec -it attacker-lab bash
# From inside: python3 -c "import socket; socket.create_connection(('honeypot', 2222))"
```

The `--internal` Docker network has no route to the public internet — the honeypot container is isolated even if something in it misbehaves. Full setup (including a VM-based alternative) is documented in the [System Architecture / Lab Setup](docs/Honeypot_Project_Documentation.md) section of the project write-up.

## Running Tests

```bash
pip install pytest
pytest
```

The suite covers: parameterized-query safety (including a deliberate SQL-injection-payload test), session/event lifecycle, all five detection rules (including the CRITICAL escalation path), and the analysis statistics functions.

## Safety Guarantees (by design, not just by policy)

- **Attacker input is never executed.** Every captured string (username, password, command) is only ever passed to the database logging layer — verified in this repo's tests with actual injection-style payloads.
- **No real credentials, no real access.** Authentication always fails; there is nothing real behind the fake shell.
- **No host OS access.** The honeypot runs as an unprivileged user; Docker lab setup isolates it on a network with no internet route.
- **SQL injection resistant.** All database queries are parameterized — confirmed with a test that stores `'; DROP TABLE events; --` as a password and verifies the table survives intact.
- **XSS resistant.** The dashboard relies on Flask/Jinja2's default autoescaping — confirmed with a test that stores a `<script>` tag as a username and verifies it renders escaped, never executed.
- **Captured data is access-restricted.** The SQLite file is chmod'd to owner-only on POSIX systems; the dashboard binds to `127.0.0.1` by default and masks captured passwords unless explicitly revealed.

## Documentation

See **[docs/Honeypot_Project_Documentation.md](docs/Honeypot_Project_Documentation.md)** for the full project write-up: abstract, threat model, system architecture, database design, detection methodology, testing methodology, results template, limitations, security/ethical considerations, future improvements, and conclusion.

## License

MIT — see [LICENSE](LICENSE).
