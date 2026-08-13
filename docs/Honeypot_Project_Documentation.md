# Honeypot for Attack Detection

### A Low-Interaction Honeypot for Defensive Cybersecurity Research and Education

---

## Abstract

This project implements a low-interaction network honeypot designed to observe, log, and analyze unauthorized connection attempts in a fully isolated laboratory environment. The system presents a fake SSH-like login service, captures connection metadata, authentication attempts, and post-login command strings without ever executing attacker-submitted input or granting real system access. Captured data is stored in a structured SQLite database and processed by a rule-based detection engine that assigns severity levels (LOW/MEDIUM/HIGH/CRITICAL) to suspicious behavior patterns such as repeated authentication failures, common-username sweeps, rapid connection bursts, and known attacker-tooling command signatures. A web dashboard visualizes connection volume, top attempted credentials, alert severity distribution, and per-session activity in real time. The project demonstrates end-to-end honeypot architecture — ingestion, structured logging, detection, visualization, and statistical analysis — while enforcing strict safety boundaries: complete network isolation, no execution of attacker input, no real credentials or production services, and no testing against any system outside the author's own laboratory environment.

---

## 1. Introduction

Honeypots are decoy systems deliberately exposed to attract unauthorized access attempts. Because no legitimate user has any reason to interact with a honeypot, every connection it receives is inherently suspicious — which makes honeypots a uniquely clean data source for studying attacker behavior, compared to filtering signal out of the noise of real production traffic.

This project builds a **low-interaction** honeypot: one that presents a convincing but non-functional façade (a fake login prompt and, optionally, a fake command shell) rather than a fully emulated operating system. Low-interaction honeypots trade realism for safety — they cannot be used to pivot further into a network because there is nothing real behind the façade — which makes them appropriate for an educational project built and run by a single developer in a personal lab, without the operational overhead a high-interaction honeypot would require to run safely.

## 2. Problem Statement

Understanding what attackers actually do — which usernames and passwords they try, how quickly they iterate, what commands they attempt once they believe they've gained access — is difficult to observe directly without either compromising a real system or deploying purpose-built instrumentation. Production systems that get attacked are, by definition, systems you can't experiment freely with; you also generally don't want to *wait* for an attack to study one. A honeypot solves both problems: it is disposable by design, safe to expose to unauthorized traffic because it has nothing real to lose, and — critically for this project — safe to build and test entirely within a self-contained lab, using traffic the developer generates themselves, without needing to expose anything to the public internet at all.

## 3. Objectives

1. Design and implement a fake network service that captures connection attempts without granting real access or executing attacker input.
2. Build a structured, queryable logging system capturing the fields necessary for later analysis (source, timing, credentials, commands, session grouping).
3. Implement a rule-based detection engine that assigns explainable severity levels to suspicious patterns.
4. Build a live dashboard summarizing captured data through metrics, tables, and charts.
5. Establish and document a safe, fully isolated testing methodology, including reproducible test traffic.
6. Produce statistical analysis of captured data with cybersecurity interpretation, not just raw numbers.
7. Maintain strict safety and ethical boundaries throughout: isolation, no code execution of attacker input, no real credentials, and testing restricted exclusively to self-owned/authorized systems.

## 4. Scope

**In scope:**
- A single fake TCP service (SSH-style login flow, with an optional post-login fake shell)
- Local, file-based structured logging (SQLite)
- Rule-based (not ML-based) detection logic
- A locally-hosted, read-only web dashboard
- Statistical/analytical reporting over captured data
- Testing exclusively within an isolated lab (VM or Docker network with no external route), using self-generated traffic

**Out of scope:**
- Execution of any attacker-submitted input under any circumstances
- High-interaction emulation (a real filesystem, real command execution, real service behavior)
- Deployment to, or testing against, any publicly reachable host or any system the author does not own or have explicit authorization to test
- Machine-learning-based anomaly detection (left as a future improvement)
- Multi-honeypot / distributed sensor architecture

## 5. Threat Model

Two distinct threat surfaces are relevant to this project, and they must be reasoned about separately.

### 5.1 Threats the honeypot observes (the subject of study)

| Threat | Description | How this project captures it |
|---|---|---|
| Automated credential stuffing / brute force | Scripted tools trying many username/password combinations rapidly | `auth_attempt` events, `repeated_auth_failures` rule |
| Common-credential sweeping | Use of standard default-username wordlists (`root`, `admin`, `test`, etc.) | `common_username_sweep` rule |
| Automated scanning | High-frequency connection attempts from a single source, consistent with tooling rather than manual use | `sessions` table + `rapid_connections` rule |
| Post-"login" exploration | Attacker behavior after believing they've gained access — reconnaissance and exploitation commands | `command_attempt` events, `suspicious_command` rule |
| Combined/escalating attacks | Multiple attack behaviors from the same source in one window | `multi_signal_critical` escalation rule |

### 5.2 Threats the honeypot itself must be hardened against

| Threat | Mitigation |
|---|---|
| Command/code execution escape (attacker input reaching a real interpreter) | Architectural rule: `command_text` and all captured strings are only ever passed to the database logging layer, never to `subprocess`, `eval`, `exec`, or `os.system`. Verified by design (Stage 5) and by deliberately testing injection-flavored input (Stage 5/8). |
| Pivoting from the honeypot host to other lab/network resources | Network isolation via Docker `--internal` network or VM host-only adapter (Stage 3); honeypot process runs as an unprivileged user (Stage 5 Dockerfile) |
| Resource exhaustion (memory/disk/connection floods) | Bounded line-length reads, per-connection timeouts, capped authentication attempts, capped fake-shell command count (Stage 5) |
| Exposure of captured (fake) credential data | Database file permissions locked to owner-only on POSIX systems; dashboard binds to `127.0.0.1` by default; passwords masked in the UI unless explicitly revealed (Stages 4, 7) |
| SQL injection against the logging database itself | Parameterized queries exclusively, throughout the data access layer (Stage 4), verified with deliberate injection-payload test input |
| Scope creep into testing unauthorized systems | `--confirm-lab` required flag on the traffic simulator; documented safe-testing procedure restricting all test traffic to self-owned lab infrastructure (Stage 8) |

## 6. System Architecture

The system is composed of four independently responsible components connected through a shared SQLite database, deliberately designed so that untrusted network input touches exactly one component.

```
Attacker / Test Traffic (isolated lab only)
        │ TCP connect
        ▼
 Honeypot Service  ──writes──▶  Data Layer (SQLite)  ◀──reads── Detection Engine ──writes──▶ alerts
 (asyncio TCP server,                  │
  fake banner, credential                reads
  capture, no execution)                  │
                                          ▼
                                     Dashboard (Flask, read-only)
                                          │
                                          ▼
                                     Analyst's Browser
```

The **Honeypot Service** is the only component that parses untrusted network input; everything it captures is immediately converted to a plain string and handed to the data layer. The **Detection Engine** and **Dashboard** never see a live socket — they only ever read structured rows from the database, which is what allows them to be developed and reasoned about without re-litigating the "could this execute attacker input" question every time.

## 7. Technologies Used

| Layer | Technology | Rationale |
|---|---|---|
| Honeypot service | Python 3 `asyncio` | Lightweight concurrent connection handling without thread-management complexity; native support for per-connection timeouts |
| Database | SQLite (`sqlite3` stdlib) | Zero-setup, file-based, sufficient for single-machine lab scale; parameterized queries provide injection safety |
| Detection engine | Pure Python, rule functions | Explainable, auditable logic — each rule's reasoning is directly inspectable, unlike a black-box model |
| Dashboard | Flask + Jinja2 | Simple server-rendered HTML sufficient for a read-only internal tool; Jinja2's default autoescaping protects against XSS from captured attacker strings |
| Charts | Chart.js (CDN) | No build tooling required |
| Configuration | `python-dotenv` + environment variables | No hardcoded secrets or environment-specific paths |
| Isolation | Docker (`--internal` network) or VirtualBox/VMware (host-only networking) | Both provide a lab network with no route to the public internet |

## 8. Database Design

Three tables form the entire schema (full DDL in Stage 4):

- **`sessions`** — one row per TCP connection; tracks source, timing, event count, and how the connection ended.
- **`events`** — one row per meaningful occurrence within a session (`connection`, `auth_attempt`, `command_attempt`, `disconnect`), with typed columns for `username`, `password`, and `command_text`. This is the append-only ground-truth log.
- **`alerts`** — one row per detection-engine finding, linking back to the triggering session/events with a rule name, severity, and human-readable reason.

Indexes on `source_ip`, `timestamp`, `session_id`, and `alerts.created_at` support the query patterns actually used by the detection engine and dashboard (recent events by IP, events within a session, recent alerts) without requiring a heavier database engine.

Design decisions worth noting in a write-up: captured passwords are stored in plain text deliberately (they are fake credentials being studied as data, not real secrets protecting anything — hashing them would only make analysis harder), while the database file itself is access-restricted at the OS level as the actual security control for this sensitive-but-fake data.

## 9. Detection Methodology

The detection engine (Stage 6) applies five independent, composable rules against recent activity, grouped by source IP:

1. **`repeated_auth_failures`** — flags MEDIUM at 5+ authentication attempts from one source, HIGH at 15+.
2. **`common_username_sweep`** — flags MEDIUM when 3+ usernames from a known default/attack-username set are attempted.
3. **`rapid_connections`** — flags HIGH when 4+ new sessions arrive from one source within a 30-second window.
4. **`suspicious_command`** — flags HIGH (or CRITICAL for destructive patterns like `rm -rf` or `/etc/shadow` access) when post-login command attempts match known attacker-tooling keyword patterns.
5. **`multi_signal_critical`** — an escalation rule that raises a combined CRITICAL alert when two or more HIGH-or-above rules fire for the same source in the same detection pass.

Severity in this system measures **how consistent the observed behavior is with automated attack tooling**, not real-world damage potential (since no real damage is possible against a honeypot) — an important framing distinction for interpreting results. Rules are pure functions over event/session data, making each one independently testable and its reasoning fully inspectable (no black-box scoring).

## 10. Implementation Summary

The system was implemented in five functional layers, built and verified incrementally:

- **Network/capture layer** (`honeypot/service.py`): an `asyncio` TCP server presenting a fake OpenSSH banner and login/password prompt loop, always rejecting authentication, with an optional post-login fake shell. Bounded reads, timeouts, and attempt caps enforce the resource-safety requirements from the threat model.
- **Data layer** (`db/database.py`, `db/schema.sql`): connection/session/event/alert persistence via parameterized SQLite queries exclusively.
- **Detection layer** (`detection/rules.py`): the five rules described above, orchestrated by `run_detection_pass()`.
- **Presentation layer** (`dashboard/app.py`, templates, `dashboard/queries.py`): a read-only Flask dashboard with metrics, charts, tables, per-session drill-down, and CSV/JSON export.
- **Analysis layer** (`analysis/stats.py`): after-the-fact statistical reporting with cybersecurity-relevant interpretation for each metric.

Configuration throughout is environment-variable driven (`honeypot/config.py`, `.env.example`) with no hardcoded secrets, satisfying the code-quality requirements set at the project's outset.

## 11. Testing Methodology

Testing was conducted exclusively within an isolated lab network (Docker `--internal` bridge or VM host-only adapter — Stage 3), using a purpose-built traffic simulator (`testing/simulate_traffic.py`, Stage 8) that requires an explicit `--confirm-lab` flag before sending any traffic, and which only ever targets a single operator-specified host.

Five scenarios were scripted to exercise specific detection behaviors:

| Scenario | Purpose | Expected detection outcome |
|---|---|---|
| Normal connection | Baseline: one unremarkable interaction | No alert |
| Failed login | Single failed auth, below any threshold | No alert |
| Repeated login attempts | Scripted brute-force pattern | `repeated_auth_failures`, likely `common_username_sweep` |
| Suspicious request | Post-login attacker-tooling command patterns | `suspicious_command` |
| Multiple connections | Rapid successive connections from one source | `rapid_connections` |

Testing also explicitly included adversarial input against the system's own safety boundaries: oversized payloads (to verify bounded reads), idle connections (to verify timeout handling), and injection-flavored strings such as `'; DROP TABLE events; --` and shell metacharacters in username/password/command fields (to verify these are stored as inert text and never interpreted).

## 12. Results

*(This section is a template — fill in with your actual observed numbers after running the Stage 8 scenarios and Stage 9's `analysis.stats` report against your own lab.)*

Example structure for reporting results:

- Total connections captured: **[N]**
- Unique source IPs (test scenarios): **[N]**
- Total authentication attempts: **[N]**
- Alerts generated, by severity: LOW **[N]** / MEDIUM **[N]** / HIGH **[N]** / CRITICAL **[N]**
- Detection rate (sessions with ≥1 alert / total sessions): **[N]%**
- Scenario-to-alert correspondence: state explicitly whether each scripted scenario in the table above produced the *expected* alert, and note any discrepancies (e.g. a scenario that didn't fire an expected rule, which is itself a useful finding about threshold tuning).
- Most frequently attempted usernames/passwords from your test data, with brief commentary on whether they matched real-world common-credential lists.

Presenting results against the *predicted* outcomes from the Stage 8 testing table (rather than only reporting raw numbers) demonstrates that the detection engine's behavior was verified, not just observed.

## 13. Limitations

- **Static, fixed detection thresholds.** An attacker aware of the exact thresholds (e.g. 5 auth attempts) could deliberately stay just under them to avoid detection. Production systems often use adaptive/statistical baselining specifically to counter this.
- **No alert deduplication.** Running detection repeatedly against ongoing behavior from a patient attacker can generate multiple alerts for what is conceptually one continuing incident, rather than a single alert that updates.
- **Low-interaction design limits realism.** Because there is no real shell or filesystem behind the fake prompt, sophisticated attackers who verify their access (e.g. checking command output for consistency) would likely detect the deception quickly — a fundamental trade-off of choosing low-interaction over high-interaction honeypot design for safety reasons.
- **Single-sensor, single-vantage-point data.** All observations come from one honeypot instance in one lab; conclusions about "typical" attacker behavior would need much broader deployment to generalize.
- **No unbounded-runtime data management.** The schema has no retention/rotation policy; a long-running deployment would need one.
- **"Detection rate" has no ground truth for false negatives.** Every interaction with the honeypot is inherently unauthorized by definition, so there's no benign-traffic baseline to compute true precision/recall against — the metric measures "how much observed activity crossed an alerting threshold," not classification accuracy in the formal sense.

## 14. Security and Ethical Considerations

This project was designed and operated under the following non-negotiable constraints:

1. **Isolation.** The honeypot ran exclusively within a network with no route to the public internet (Docker `--internal` network or VM host-only adapter), verified before each testing session.
2. **No code execution of attacker input.** Every captured string (username, password, command) is stored and only ever stored — never passed to any execution primitive. This was a hard architectural rule, not a best-effort guideline, and was specifically verified by testing with adversarial/injection-style input.
3. **No real credentials or production services exposed.** The service is entirely fake; authentication always fails; there is no real backend to compromise.
4. **No host OS access.** The honeypot process runs as an unprivileged user within its isolated container/VM and has no mechanism by which a connecting client could reach the underlying host.
5. **Secure data handling.** Captured data (including fake credentials) is stored locally with restricted file permissions, and the dashboard defaults to localhost-only access with credentials masked by default.
6. **Authorized testing only.** All test traffic was generated by the author, from infrastructure the author owns, within the isolated lab — the traffic simulator technically enforces this via a required `--confirm-lab` flag and by only ever targeting a single explicitly-specified host, with no scanning or discovery capability.
7. **Privacy.** Any geographic/IP-based analysis was scoped to the author's own test traffic; the project does not attempt to deanonymize or attribute real-world actors.

These constraints were treated as first-class requirements throughout design (Stage 1), not retrofitted after implementation — each later stage's "possible security problems" review checked back against this list.

## 15. Future Improvements

- Swap fixed detection thresholds for statistical/behavioral baselining (e.g. flag deviation from a rolling average rather than a fixed count).
- Add alert deduplication/suppression for ongoing incidents.
- Introduce a second, differently-themed low-interaction service (e.g. fake HTTP admin panel or fake FTP) to broaden the observed attack surface while keeping the same safety architecture.
- Add coarse, privacy-conscious geographic enrichment (e.g. country-level GeoIP) for the dashboard's source-IP breakdown, clearly labeled as approximate.
- Migrate from SQLite to PostgreSQL and containerize with a proper retention policy if extending to longer-running or multi-sensor deployment.
- Explore (carefully, and only ever within the same execution-safety boundaries) a higher-interaction fake shell that mimics plausible command output without ever running real commands, to study more sophisticated attacker follow-through.

## 16. Conclusion

This project delivered a complete, functioning low-interaction honeypot pipeline — from raw TCP capture through structured logging, rule-based detection, live visualization, and statistical analysis — built entirely within a self-contained, isolated lab environment. The central design commitment, that captured attacker input is data and only ever data, never code, was carried consistently through every layer of the system and verified through deliberate adversarial testing rather than simply assumed. The result is a project that demonstrates the full architecture of a real honeypot deployment while remaining safe to build, run, and test end-to-end on a single personal machine, with no risk to any real system.

---

## Appendix A: Project Structure

```
honeypot-project/
├── honeypot/            # Fake TCP service, config, banners (Stage 5)
├── db/                  # Schema + parameterized data access layer (Stage 4)
├── detection/            # Rule-based detection engine (Stage 6)
├── dashboard/            # Flask read-only web dashboard (Stage 7)
├── testing/              # Isolated-lab traffic simulator + procedure (Stage 8)
├── analysis/              # Statistical reporting (Stage 9)
├── docs/                  # This document
├── .env.example
├── requirements.txt
├── README.md
└── LICENSE
```

## Appendix B: Requirements Traceability

| Original Requirement | Delivered In |
|---|---|
| Isolated VM/container only | Stage 3 |
| No real credentials/production services | Stage 1, 5 |
| No host OS access | Stage 3, 5 |
| Never execute attacker commands | Stage 5 (architectural invariant), verified Stage 5 & 8 |
| Secure data storage | Stage 4 |
| Distinguish simulated vs. real attacks | Stage 8 (all traffic self-generated and labeled) |
| Detection engine with severity levels | Stage 6 |
| Web dashboard | Stage 7 |
| Safe testing environment | Stage 3, 8 |
| Data analysis/statistics | Stage 9 |
| Full documentation | Stage 10 (this document) |
