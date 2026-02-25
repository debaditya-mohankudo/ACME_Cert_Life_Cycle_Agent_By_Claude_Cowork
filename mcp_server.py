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

import asyncio
import logging
from contextlib import asynccontextmanager, contextmanager
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
# Rationale: see doc/README_MCP_TOOL_SERIALIZATION.md#why-asyncio-lock-instead-of-threading-lock
_MCP_OPERATION_LOCK = asyncio.Lock()


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
    settings_override: Any | None = None,
):
    """Temporarily replace config settings for a single tool execution."""
    import config

    original_settings = config.settings
    if settings_override is not None:
        config.settings = settings_override

    try:
        yield
    finally:
        config.settings = original_settings


def _build_effective_settings(
    ca_provider: str | None,
    acme_directory_url: str | None,
) -> Any:
    from main import build_settings_from_override
    import config

    return build_settings_from_override(
        ca_provider=ca_provider,
        acme_directory_url=acme_directory_url,
        base_settings=config.settings,
    )


def _validate_reason(reason: int) -> int:
    if reason not in {0, 1, 4, 5}:
        raise ValueError("reason must be one of: 0, 1, 4, 5")
    return reason


@asynccontextmanager
async def _operation_lock(*, required: bool):
    """Acquire process-wide operation lock when required by policy."""
    if not required:
        yield
        return

    async with _MCP_OPERATION_LOCK:
        yield


def _run_renew_once(domains: list[str] | None, checkpoint: bool, settings: Any | None = None) -> dict[str, Any]:
    from main import run_once

    try:
        return run_once(domains=domains, use_checkpoint=checkpoint, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(f"renew_once failed with exit code {exc.code}") from exc


def _run_revoke(
    domains: list[str],
    reason: int,
    checkpoint: bool,
    settings: Any | None = None,
) -> dict[str, Any]:
    from main import run_revocation

    try:
        return run_revocation(
            domains=domains,
            reason=reason,
            use_checkpoint=checkpoint,
            settings=settings,
        )
    except SystemExit as exc:
        raise RuntimeError(f"revoke_cert failed with exit code {exc.code}") from exc


def _run_expiring_in_30_days(domains: list[str] | None, settings: Any | None = None) -> list[str]:
    from main import list_domains_expiring_within

    try:
        return list_domains_expiring_within(days=30, domains=domains, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(
            f"expiring_in_30_days failed with exit code {exc.code}"
        ) from exc


def _run_domain_status(domains: list[str], settings: Any | None = None) -> list[dict[str, Any]]:
    from main import get_domain_statuses

    try:
        return get_domain_statuses(domains, settings=settings)
    except SystemExit as exc:
        raise RuntimeError(f"domain_status failed with exit code {exc.code}") from exc


@mcp.tool()
async def health(
    ca_input_mode: Literal["config", "custom"],
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Return non-secret configuration/readiness checks with explicit CA input mode."""
    try:
        import config

        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                current_settings = config.settings
                missing_llm_key = (
                    (current_settings.LLM_PROVIDER == "anthropic" and not current_settings.ANTHROPIC_API_KEY)
                    or (current_settings.LLM_PROVIDER == "openai" and not current_settings.OPENAI_API_KEY)
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
    except Exception as e:
        logging.exception("health check failed")
        return {
            "ok": False,
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def renew_once(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str] | None = None,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Run one renewal cycle with explicit CA input mode."""
    try:
        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                final_state = _run_renew_once(
                    domains=domains,
                    checkpoint=checkpoint,
                    settings=effective_settings,
                )
                return {
                    "status": "success",
                    "completed_renewals": final_state.get("completed_renewals", []),
                    "failed_renewals": final_state.get("failed_renewals", []),
                    "error_log": final_state.get("error_log", []),
                }
    except Exception as e:
        logging.exception("renew_once failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def revoke_cert(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str],
    reason: int = 0,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Revoke certs with explicit CA input mode (RFC 5280 reasons: 0,1,4,5)."""
    try:
        if not domains:
            raise ValueError("domains must contain at least one domain")

        resolved_provider, resolved_directory = _resolve_ca_inputs(
            ca_input_mode=ca_input_mode,
            ca_provider=ca_provider,
            acme_directory_url=acme_directory_url,
        )
        effective_settings = _build_effective_settings(
            ca_provider=resolved_provider,
            acme_directory_url=resolved_directory,
        )

        async with _operation_lock(required=True):
            with _temporary_settings_override(
                settings_override=effective_settings,
            ):
                final_state = _run_revoke(
                    domains=domains,
                    reason=_validate_reason(reason),
                    checkpoint=checkpoint,
                    settings=effective_settings,
                )
                return {
                    "status": "success",
                    "revoked_domains": final_state.get("revoked_domains", []),
                    "failed_revocations": final_state.get("failed_revocations", []),
                    "error_log": final_state.get("error_log", []),
                }
    except Exception as e:
        logging.exception("revoke_cert failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def expiring_in_30_days(domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires in 30 days or less."""
    try:
        import config

        async with _operation_lock(required=True):
            expiring_domains = _run_expiring_in_30_days(domains=domains, settings=config.settings)
        return {
            "status": "success",
            "window_days": 30,
            "expiring_domains": expiring_domains,
        }
    except Exception as e:
        logging.exception("expiring_in_30_days failed")
        return {
            "status": "failed",
            "error": str(e),
        }


@mcp.tool()
async def domain_status(domains: list[str]) -> dict[str, Any]:
    """Get certificate status details for one or more domains."""
    try:
        import config

        if not domains:
            raise ValueError("domains must contain at least one domain")

        async with _operation_lock(required=True):
            return {
                "status": "success",
                "domain_statuses": _run_domain_status(domains=domains, settings=config.settings),
            }
    except Exception as e:
        logging.exception("domain_status failed")
        return {
            "status": "failed",
            "error": str(e),
        }


if __name__ == "__main__":
    mcp.run()
