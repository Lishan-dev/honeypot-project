"""
Text presented to connecting clients. Kept separate from service.py so
the "what does this honeypot pretend to be" decision is easy to find
and change without touching connection-handling logic.
"""

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

LOGIN_PROMPT = "login: "
PASSWORD_PROMPT = "Password: "
AUTH_FAILURE_MSG = "Access denied\r\n"
MAX_ATTEMPTS_MSG = "Too many authentication failures\r\n"

# Presented only if FAKE_SHELL_ENABLED=true -- see config.py
SHELL_WELCOME = (
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
    "Last login: Mon Jan  1 00:00:00 2026 from 10.0.0.1\r\n"
)
SHELL_PROMPT = "user@srv01:~$ "
COMMAND_NOT_FOUND = "-bash: {cmd}: command not found\r\n"
