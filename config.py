"""
Application configuration via Pydantic Settings.
All values can be overridden by environment variables or a .env file.
"""
from __future__ import annotations

import os
import warnings
from typing import List, Literal, Optional

from pydantic import field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)


class _CommaFallbackMixin:
    """Return the raw string when JSON parsing fails.

    pydantic-settings ≥2.7 calls json.loads() on complex-typed fields
    (e.g. List[str]) before field_validators run.  A plain comma-separated
    value like ``api.example.com,shop.example.com`` is not valid JSON and
    raises SettingsError before the parse_domains validator can handle it.
    This mixin catches that ValueError and returns the raw string so the
    field_validator receives it and can split on commas as intended.
    """

    def prepare_field_value(self, field_name, field, value, value_is_complex):  # type: ignore[override]
        try:
            return super().prepare_field_value(field_name, field, value, value_is_complex)  # type: ignore[misc]
        except ValueError:
            return value


class _CSVEnvSource(_CommaFallbackMixin, EnvSettingsSource):
    pass


class _CSVDotEnvSource(_CommaFallbackMixin, DotEnvSettingsSource):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── CA Provider ────────────────────────────────────────────────────────
    CA_PROVIDER: Literal[
        "digicert", "letsencrypt", "letsencrypt_staging", "zerossl", "sectigo", "custom"
    ] = "digicert"

    # ── ACME credentials (EAB — required for DigiCert, ZeroSSL, and Sectigo) ──────
    ACME_EAB_KEY_ID: str = ""
    ACME_EAB_HMAC_KEY: str = ""
    # Only consulted when CA_PROVIDER="custom"
    ACME_DIRECTORY_URL: str = ""

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

    # ── LLM ────────────────────────────────────────────────────────────────
    LLM_PROVIDER: Literal["anthropic", "openai", "ollama"] = "anthropic"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"
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

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            _CSVEnvSource(settings_cls),
            _CSVDotEnvSource(settings_cls),
            file_secret_settings,
        )

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

    @model_validator(mode="after")
    def resolve_acme_directory(self) -> "Settings":
        if any(os.environ.get(k) for k in (
            "DIGICERT_ACME_DIRECTORY", "DIGICERT_EAB_KEY_ID", "DIGICERT_EAB_HMAC_KEY"
        )):
            warnings.warn(
                "DIGICERT_ACME_DIRECTORY/DIGICERT_EAB_KEY_ID/DIGICERT_EAB_HMAC_KEY are deprecated. "
                "Use CA_PROVIDER + ACME_EAB_KEY_ID + ACME_EAB_HMAC_KEY instead.",
                DeprecationWarning,
                stacklevel=2,
            )

        _PRESETS = {
            "digicert":            "https://acme.digicert.com/v2/DV/directory",
            "letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
            "letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "zerossl":             "https://acme.zerossl.com/v2/DV90",
            "sectigo":             "https://acme.sectigo.com/v2/DV",
        }
        if self.CA_PROVIDER in _PRESETS:
            self.ACME_DIRECTORY_URL = _PRESETS[self.CA_PROVIDER]
        elif not self.ACME_DIRECTORY_URL:
            raise ValueError("ACME_DIRECTORY_URL must be set when CA_PROVIDER='custom'")
        return self


# Module-level singleton — import and use everywhere.
settings = Settings()
