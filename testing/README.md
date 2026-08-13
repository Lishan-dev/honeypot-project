# Safe Testing Procedure

## Before every test session

1. Confirm you're on the isolated lab network -- from the attacker box:
   `ping 8.8.8.8` should FAIL (no internet route).
2. Confirm the honeypot's bound address is the lab-internal address, not
   a real network interface: check `HONEYPOT_HOST` in the running
   service's environment/logs.
3. Start the honeypot service and confirm it logs its "AUTHORIZED LAB
   USE ONLY" banner on startup.
4. (Optional but recommended) Take a fresh look at `data/honeypot.db`'s
   row counts before you start, so you can confirm growth matches what
   you expect after each scenario.

## Running scenarios

From the attacker box/container:

    python3 testing/simulate_traffic.py --target <honeypot-lab-ip> --port 2222 --confirm-lab --scenario all

Or one at a time, to correlate each with dashboard/detection output as
you go:

    python3 testing/simulate_traffic.py --target <ip> --port 2222 --confirm-lab --scenario normal
    python3 testing/simulate_traffic.py --target <ip> --port 2222 --confirm-lab --scenario failed_login
    python3 testing/simulate_traffic.py --target <ip> --port 2222 --confirm-lab --scenario repeated
    python3 testing/simulate_traffic.py --target <ip> --port 2222 --confirm-lab --scenario suspicious
    python3 testing/simulate_traffic.py --target <ip> --port 2222 --confirm-lab --scenario multi

## After each scenario

1. Run a detection pass: `python3 -m detection.rules` (or click "Run
   Detection Now" on the dashboard).
2. Open the dashboard and confirm:
   - Connection/event counts increased as expected
   - The expected alert(s) appeared (see table below)
3. Spot-check the raw session in the dashboard's session detail view.

## Expected outcomes per scenario

| Scenario | Expected events | Expected alert(s) |
|---|---|---|
| `normal` | 1 connection, 1 auth_attempt, 1 disconnect | None (single unremarkable event) |
| `failed_login` | 1 connection, 1 auth_attempt, 1 disconnect | None (below repeated-failure threshold) |
| `repeated` | 1 connection, 6 auth_attempts, 1 disconnect | `repeated_auth_failures` (MEDIUM), likely `common_username_sweep` (MEDIUM) |
| `suspicious` | 1 connection, 1 auth_attempt + command_attempts (if `FAKE_SHELL_ENABLED`) | `suspicious_command` (HIGH/CRITICAL) if commands were captured |
| `multi` | 5 connections in quick succession | `rapid_connections` (HIGH) |

If your results don't match this table, that's useful information too --
it means either a threshold needs tuning or there's a bug to chase down.
Document any mismatches rather than quietly adjusting thresholds until
the table matches after the fact.

## After the test session

- Stop the honeypot service.
- Review `data/honeypot.db` for anything unexpected (connections from an
  IP you didn't generate, for instance -- would indicate the isolation
  boundary was breached and needs investigating before you trust any
  further results).
- If using the VM lab: restore your clean snapshot before the next
  session, so each test run starts from known-good state.
