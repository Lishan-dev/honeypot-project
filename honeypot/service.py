"""
Low-interaction honeypot TCP service.

SECURITY-CRITICAL INVARIANT: nothing read from the socket in this file is
ever passed to subprocess, eval, exec, os.system, or any other execution
primitive. Attacker input is captured as a string, logged via
db.database.log_event(), and that is the end of its lifecycle. If you are
extending this file, do not break that invariant.
"""
import asyncio
import logging
import uuid

from honeypot import banners
from honeypot.config import get_config
from db import database

logger = logging.getLogger("honeypot.service")

# Populated at startup from config; a simple in-memory counter is enough
# for a lab-scale project. Keyed by source IP, reset never (process
# lifetime only) -- good enough to spot a burst of activity from one
# address without needing a separate rate-limiting service.
_connection_counts: dict[str, int] = {}


class ClientDisconnected(Exception):
    """Raised internally when the peer closes the connection or we hit EOF."""


async def _read_line(reader: asyncio.StreamReader, max_length: int) -> str:
    """
    Reads a single line from the client, bounded in size. Raises
    ClientDisconnected on EOF, and truncates (rather than blocking
    forever or consuming unbounded memory) if the client sends more
    than max_length bytes without a newline.
    """
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=get_config().CONNECTION_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise ClientDisconnected("read timeout")

    if raw == b"":
        raise ClientDisconnected("EOF")

    # Bound the length we keep, regardless of how much the client sent.
    raw = raw[:max_length]
    # Decode defensively -- attacker input is not guaranteed to be valid
    # UTF-8, and a crash here would be an easy denial-of-service against
    # our own logging. Replace invalid bytes rather than raising.
    text = raw.decode("utf-8", errors="replace").strip("\r\n")
    return text


async def _handle_authentication(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    session_id: str,
    source_ip: str,
    source_port: int,
) -> bool:
    """
    Runs the fake login/password loop. Always ultimately rejects --
    there is no code path in this function that grants real access.
    Returns True if the (fake) auth loop completed normally, False if
    the client disconnected mid-flow.
    """
    config = get_config()
    attempts = 0

    while attempts < config.MAX_AUTH_ATTEMPTS:
        writer.write(banners.LOGIN_PROMPT.encode())
        await writer.drain()
        username = await _read_line(reader, config.MAX_LINE_LENGTH)

        writer.write(banners.PASSWORD_PROMPT.encode())
        await writer.drain()
        password = await _read_line(reader, config.MAX_LINE_LENGTH)

        attempts += 1

        database.log_event(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="auth_attempt",
            username=username,
            password=password,
            metadata={"attempt_number": attempts},
        )
        logger.info("Auth attempt %d from %s:%d (user=%r)", attempts, source_ip, source_port, username)

        # This service NEVER authenticates anyone. That is the entire
        # point of a honeypot -- every credential is fake-rejected.
        writer.write(banners.AUTH_FAILURE_MSG.encode())
        await writer.drain()

    writer.write(banners.MAX_ATTEMPTS_MSG.encode())
    await writer.drain()
    return True


async def _handle_fake_shell(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    session_id: str,
    source_ip: str,
    source_port: int,
) -> None:
    """
    Optional post-"login" fake shell. Captures typed commands as inert
    strings and echoes a generic "command not found" response -- it
    never interprets, executes, or shells out to anything.
    """
    config = get_config()
    writer.write(banners.SHELL_WELCOME.encode())
    writer.write(banners.SHELL_PROMPT.encode())
    await writer.drain()

    commands_seen = 0
    max_commands = config.MAX_FAKE_SHELL_COMMANDS

    while commands_seen < max_commands:
        command = await _read_line(reader, config.MAX_LINE_LENGTH)
        commands_seen += 1

        database.log_event(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            event_type="command_attempt",
            command_text=command,  # stored as a plain string; never executed, ever
            metadata={"command_number": commands_seen},
        )
        logger.info("Command attempt from %s:%d: %r", source_ip, source_port, command)

        if command.strip() in ("exit", "logout", "quit"):
            break

        # Deliberately generic response -- we don't try to fake real
        # command output (that's a much higher-interaction honeypot,
        # out of scope here per the threat model).
        first_word = command.strip().split(" ", 1)[0] if command.strip() else ""
        writer.write(banners.COMMAND_NOT_FOUND.format(cmd=first_word).encode())
        writer.write(banners.SHELL_PROMPT.encode())
        await writer.drain()


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Entry point for every accepted TCP connection."""
    config = get_config()
    peer = writer.get_extra_info("peername")
    source_ip, source_port = (peer[0], peer[1]) if peer else ("unknown", 0)
    session_id = str(uuid.uuid4())

    _connection_counts[source_ip] = _connection_counts.get(source_ip, 0) + 1

    database.create_session(session_id, source_ip, source_port)
    database.log_event(session_id, source_ip, source_port, event_type="connection")
    logger.info("New connection: session=%s ip=%s port=%d (total from this IP: %d)",
                session_id, source_ip, source_port, _connection_counts[source_ip])

    close_reason = "client_disconnect"
    try:
        writer.write(banners.SSH_BANNER.encode())
        await writer.drain()

        await _handle_authentication(reader, writer, session_id, source_ip, source_port)

        if config.FAKE_SHELL_ENABLED:
            await _handle_fake_shell(reader, writer, session_id, source_ip, source_port)

    except ClientDisconnected as exc:
        close_reason = "timeout" if "timeout" in str(exc) else "client_disconnect"
    except Exception:
        # Never let a malformed/malicious input crash the whole server --
        # log it, close this one connection, keep listening for others.
        logger.exception("Unexpected error handling session %s", session_id)
        close_reason = "error"
    finally:
        database.log_event(session_id, source_ip, source_port, event_type="disconnect")
        database.close_session(session_id, close_reason)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass  # peer may already be gone; nothing more to do


async def run_server() -> None:
    config = get_config()
    database.init_db()

    server = await asyncio.start_server(handle_connection, config.HONEYPOT_HOST, config.HONEYPOT_PORT)
    addr = server.sockets[0].getsockname()
    logger.warning(
        "Honeypot listening on %s:%d -- FOR ISOLATED LAB USE ONLY. "
        "Do not expose this to the public internet or any network you "
        "do not own/have explicit authorization to test.",
        addr[0], addr[1],
    )

    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    print("=" * 70)
    print(" HONEYPOT SERVICE -- AUTHORIZED LAB USE ONLY")
    print(" This tool must only run in an isolated environment against")
    print(" traffic you generate yourself. Do not expose it publicly.")
    print("=" * 70)
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot service.")


if __name__ == "__main__":
    main()
