"""
Application configuration via Pydantic Settings.
All values can be overridden by environment variables or a .env file.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── DigiCert ACME ──────────────────────────────────────────────────────
    DIGICERT_ACME_DIRECTORY: str = "https://acme.digicert.com/v2/DV/directory"
    DIGICERT_EAB_KEY_ID: str = ""
    DIGICERT_EAB_HMAC_KEY: str = ""

    # ── Domain management ──────────────────────────────────────────────────
    MANAGED_DOMAINS: List[str] = []
    RENEWAL_THRESHOLD_DAYS: int = 30

    # ── Storage ────────────────────────────────────────────────────────────
    CERT_STORE_PATH: str = "./certs"
    ACCOUNT_KEY_PATH: str = "./account.key"

    # ── HTTP-01 Challenge ──────────────────────────────────────────────────
    HTTP_CHALLENGE_MODE: str = "standalone"   # "standalone" | "webroot"
    HTTP_CHALLENGE_PORT: int = 80
    WEBROOT_PATH: Optional[str] = None

    # ── LLM (Anthropic) ────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    LLM_MODEL_PLANNER: str = "claude-haiku-4-5-20251001"
    LLM_MODEL_ERROR_HANDLER: str = "claude-sonnet-4-6"
    LLM_MODEL_REPORTER: str = "claude-haiku-4-5-20251001"

    # ── Scheduling ─────────────────────────────────────────────────────────
    SCHEDULE_TIME: str = "06:00"

    # ── Retry / resilience ─────────────────────────────────────────────────
    MAX_RETRIES: int = 3

    # ── ACME TLS (for testing against Pebble / self-signed CAs) ───────────
    ACME_CA_BUNDLE: str = ""       # Path to CA cert bundle; empty = system default
    ACME_INSECURE: bool = False    # Skip TLS verification (never use in production)

    # ── LangSmith (optional) ───────────────────────────────────────────────
    LANGCHAIN_TRACING_V2: bool = False
    LANGCHAIN_API_KEY: str = ""
    LANGCHAIN_PROJECT: str = "acme-cert-agent"

    @field_validator("MANAGED_DOMAINS", mode="before")
    @classmethod
    def parse_domains(cls, v: object) -> List[str]:
        """Accept comma-separated string or list."""
        if isinstance(v, str):
            return [d.strip() for d in v.split(",") if d.strip()]
        return v  # type: ignore[return-value]

    @field_validator("HTTP_CHALLENGE_MODE")
    @classmethod
    def validate_challenge_mode(cls, v: str) -> str:
        allowed = {"standalone", "webroot"}
        if v not in allowed:
            raise ValueError(f"HTTP_CHALLENGE_MODE must be one of {allowed}")
        return v

    @model_validator(mode="after")
    def validate_webroot(self) -> "Settings":
        if self.HTTP_CHALLENGE_MODE == "webroot" and not self.WEBROOT_PATH:
            raise ValueError(
                "WEBROOT_PATH must be set when HTTP_CHALLENGE_MODE='webroot'"
            )
        return self


# Module-level singleton — import and use everywhere.
settings = Settings()
