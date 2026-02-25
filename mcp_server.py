"""
MCP server exposing ACME lifecycle services as tools.

Tools:
  - health: configuration/provider sanity check (no side effects)
  - renew_once: run one renewal cycle
  - revoke_cert: revoke one or more certificates
  - expiring_in_30_days: list domains with certs expiring in <= 30 days
  - domain_status: get cert status for one or more domains
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Literal

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "MCP dependency is missing. Install project dependencies with 'uv sync'."
    ) from exc


mcp = FastMCP("acme-certificate-lifecycle-agent")
CA_PROVIDER_CHOICES = {
    "digicert",
    "letsencrypt",
    "letsencrypt_staging",
    "zerossl",
    "sectigo",
    "custom",
}
CA_INPUT_MODE_CHOICES = {"config", "custom"}


def _resolve_ca_inputs(
    ca_input_mode: str,
    ca_provider: str | None,
    acme_directory_url: str | None,
) -> tuple[str | None, str | None]:
    """Resolve CA inputs from explicit mode selection.

    - config: use config.py/.env values, ignore custom inputs
    - custom: require both ca_provider and acme_directory_url
    """
    if ca_input_mode not in CA_INPUT_MODE_CHOICES:
        raise ValueError("ca_input_mode must be one of: config, custom")

    if ca_input_mode == "config":
        return None, None

    if not ca_provider or not acme_directory_url:
        raise ValueError(
            "When ca_input_mode='custom', both ca_provider and acme_directory_url are required"
        )
    return ca_provider, acme_directory_url


@contextmanager
def _temporary_settings_override(
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
):
    """Temporarily override config settings for a single tool execution."""
    import config

    original_ca_provider_env = os.environ.get("CA_PROVIDER")
    original_acme_directory_env = os.environ.get("ACME_DIRECTORY_URL")

    if ca_provider:
        if ca_provider not in CA_PROVIDER_CHOICES:
            raise ValueError(
                "ca_provider must be one of: digicert, letsencrypt, letsencrypt_staging, zerossl, sectigo, custom"
            )
        os.environ["CA_PROVIDER"] = ca_provider
    if acme_directory_url:
        os.environ["ACME_DIRECTORY_URL"] = acme_directory_url

    config.settings = config.Settings()
    try:
        yield
    finally:
        if original_ca_provider_env is None:
            os.environ.pop("CA_PROVIDER", None)
        else:
            os.environ["CA_PROVIDER"] = original_ca_provider_env

        if original_acme_directory_env is None:
            os.environ.pop("ACME_DIRECTORY_URL", None)
        else:
            os.environ["ACME_DIRECTORY_URL"] = original_acme_directory_env

        config.settings = config.Settings()


def _validate_reason(reason: int) -> int:
    if reason not in {0, 1, 4, 5}:
        raise ValueError("reason must be one of: 0, 1, 4, 5")
    return reason


def _run_renew_once(domains: list[str] | None, checkpoint: bool) -> dict[str, Any]:
    from main import run_once

    try:
        return run_once(domains=domains, use_checkpoint=checkpoint)
    except SystemExit as exc:
        raise RuntimeError(f"renew_once failed with exit code {exc.code}") from exc


def _run_revoke(domains: list[str], reason: int, checkpoint: bool) -> dict[str, Any]:
    from main import run_revocation

    try:
        return run_revocation(domains=domains, reason=reason, use_checkpoint=checkpoint)
    except SystemExit as exc:
        raise RuntimeError(f"revoke_cert failed with exit code {exc.code}") from exc


def _run_expiring_in_30_days(domains: list[str] | None) -> list[str]:
    from main import list_domains_expiring_within

    try:
        return list_domains_expiring_within(days=30, domains=domains)
    except SystemExit as exc:
        raise RuntimeError(
            f"expiring_in_30_days failed with exit code {exc.code}"
        ) from exc


def _run_domain_status(domains: list[str]) -> list[dict[str, Any]]:
    from main import get_domain_statuses

    try:
        return get_domain_statuses(domains)
    except SystemExit as exc:
        raise RuntimeError(f"domain_status failed with exit code {exc.code}") from exc


@mcp.tool()
def health(
    ca_input_mode: Literal["config", "custom"],
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Return non-secret configuration/readiness checks with explicit CA input mode."""
    import config

    resolved_provider, resolved_directory = _resolve_ca_inputs(
        ca_input_mode=ca_input_mode,
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
    )

    with _temporary_settings_override(
        ca_provider=resolved_provider,
        acme_directory_url=resolved_directory,
    ):
        current_settings = config.settings
        missing_llm_key = (
            current_settings.LLM_PROVIDER == "anthropic"
            and not current_settings.ANTHROPIC_API_KEY
            or current_settings.LLM_PROVIDER == "openai"
            and not current_settings.OPENAI_API_KEY
        )

        warnings: list[str] = []
        if not current_settings.MANAGED_DOMAINS:
            warnings.append("MANAGED_DOMAINS is empty")
        if missing_llm_key:
            warnings.append(f"{current_settings.LLM_PROVIDER.upper()} API key is not set")
        if (
            current_settings.HTTP_CHALLENGE_MODE == "standalone"
            and current_settings.HTTP_CHALLENGE_PORT != 80
        ):
            warnings.append("HTTP_CHALLENGE_PORT is not 80; ensure public HTTP-01 reachability")
        if current_settings.ACME_INSECURE:
            warnings.append("ACME_INSECURE=true (testing only)")

        return {
            "ok": len(warnings) == 0,
            "provider": current_settings.CA_PROVIDER,
            "acme_directory": current_settings.ACME_DIRECTORY_URL,
            "llm_provider": current_settings.LLM_PROVIDER,
            "challenge_mode": current_settings.HTTP_CHALLENGE_MODE,
            "managed_domain_count": len(current_settings.MANAGED_DOMAINS),
            "warnings": warnings,
        }


@mcp.tool()
def renew_once(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str] | None = None,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Run one renewal cycle with explicit CA input mode."""
    resolved_provider, resolved_directory = _resolve_ca_inputs(
        ca_input_mode=ca_input_mode,
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
    )

    with _temporary_settings_override(
        ca_provider=resolved_provider,
        acme_directory_url=resolved_directory,
    ):
        final_state = _run_renew_once(domains=domains, checkpoint=checkpoint)
        return {
            "completed_renewals": final_state.get("completed_renewals", []),
            "failed_renewals": final_state.get("failed_renewals", []),
            "error_log": final_state.get("error_log", []),
        }


@mcp.tool()
def revoke_cert(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str],
    reason: int = 0,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Revoke certs with explicit CA input mode (RFC 5280 reasons: 0,1,4,5)."""
    if not domains:
        raise ValueError("domains must contain at least one domain")

    resolved_provider, resolved_directory = _resolve_ca_inputs(
        ca_input_mode=ca_input_mode,
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
    )

    with _temporary_settings_override(
        ca_provider=resolved_provider,
        acme_directory_url=resolved_directory,
    ):
        final_state = _run_revoke(
            domains=domains,
            reason=_validate_reason(reason),
            checkpoint=checkpoint,
        )
        return {
            "revoked_domains": final_state.get("revoked_domains", []),
            "failed_revocations": final_state.get("failed_revocations", []),
            "error_log": final_state.get("error_log", []),
        }


@mcp.tool()
def expiring_in_30_days(domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires in 30 days or less."""
    expiring_domains = _run_expiring_in_30_days(domains=domains)
    return {
        "window_days": 30,
        "expiring_domains": expiring_domains,
    }


@mcp.tool()
def domain_status(domains: list[str]) -> dict[str, Any]:
    """Get certificate status details for one or more domains."""
    if not domains:
        raise ValueError("domains must contain at least one domain")

    return {
        "domain_statuses": _run_domain_status(domains=domains),
    }


if __name__ == "__main__":
    mcp.run()
