"""
Central configuration, loaded from environment variables. No secrets or
environment-specific paths are hardcoded here -- see .env.example for the
full list of variables this project understands.
"""
import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()  # loads a local .env file if present; does nothing in prod if absent


@dataclass(frozen=True)
class Config:
    # Honeypot service
    HONEYPOT_HOST: str = os.getenv("HONEYPOT_HOST", "127.0.0.1")  # bind to lab-only interface by default
    HONEYPOT_PORT: int = int(os.getenv("HONEYPOT_PORT", "2222"))  # unprivileged port, not real SSH's 22
    MAX_AUTH_ATTEMPTS: int = int(os.getenv("MAX_AUTH_ATTEMPTS", "5"))
    CONNECTION_TIMEOUT_SECONDS: int = int(os.getenv("CONNECTION_TIMEOUT_SECONDS", "60"))
    MAX_LINE_LENGTH: int = int(os.getenv("MAX_LINE_LENGTH", "1024"))  # caps memory use per read
    FAKE_SHELL_ENABLED: bool = os.getenv("FAKE_SHELL_ENABLED", "true").lower() == "true"
    MAX_FAKE_SHELL_COMMANDS: int = int(os.getenv("MAX_FAKE_SHELL_COMMANDS", "20"))

    # Database
    DB_PATH: str = os.getenv("DB_PATH", "./data/honeypot.db")

    # Dashboard
    DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "5000"))
    DASHBOARD_USERNAME: str = os.getenv("DASHBOARD_USERNAME", "")  # blank = no auth (local-only use)
    DASHBOARD_PASSWORD: str = os.getenv("DASHBOARD_PASSWORD", "")


@lru_cache
def get_config() -> Config:
    return Config()
