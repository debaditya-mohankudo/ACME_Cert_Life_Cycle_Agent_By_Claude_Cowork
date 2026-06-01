"""
MCP server exposing ACME lifecycle services as tools.

Architecture
------------
This MCP server is a thin dispatch layer. All business logic lives in the
FastAPI REST server (server/main.py). Each tool makes a synchronous HTTP call
to 127.0.0.1:SERVER_PORT and returns the result.

On startup, the MCP server auto-starts the FastAPI server as a subprocess if
it is not already running. This means the operator only needs to start one
process: `python mcp_server.py`.

Sync / async split
------------------
MCP tool functions are declared `async` because FastMCP requires it for its
event loop. The actual work (the HTTP call to FastAPI) is synchronous —
urllib is used deliberately instead of httpx/aiohttp. This is consistent with
the project's decision not to introduce async I/O until a ground-up redesign.
The asyncio.to_thread wrapper offloads the blocking HTTP call off the event
loop thread so FastMCP's loop stays responsive, without introducing true
async I/O into the business layer.

Tools
-----
  health              — configuration/provider sanity check
  renew_once          — run one renewal cycle for one or more domains
  revoke_cert         — revoke one or more certificates
  expiring_in_30_days — list domains expiring in <= 30 days
  expiring_within     — list domains expiring within N days
  list_managed_domains— return configured managed domain list
  domain_status       — cert status for one or more domains
  read_cert_details   — rich cert inspection (SANs, issuer, serial, dates)
  generate_test_cert  — generate self-signed test cert
  query_context       — query unified 3-layer team context
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from config import Settings

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "MCP dependency is missing. Install project dependencies with 'uv sync'."
    ) from exc

from logger import logger

# ---------------------------------------------------------------------------
# FastAPI server lifecycle
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent
SERVER_PORT = 8741
_BASE_URL   = f"http://127.0.0.1:{SERVER_PORT}"
_HEALTH_URL = f"{_BASE_URL}/health"


def _is_server_running() -> bool:
    try:
        urllib.request.urlopen(_HEALTH_URL, timeout=2)
        return True
    except Exception:
        return False


def start_rest_server() -> None:
    """Start the FastAPI server as a subprocess if not already running."""
    if _is_server_running():
        return

    subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "server.main:app",
            "--host", "127.0.0.1",
            "--port", str(SERVER_PORT),
            "--workers", "1",  # single worker — concurrent ACME ops are forbidden (Hard Invariant 4)
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for _ in range(20):
        time.sleep(0.5)
        if _is_server_running():
            return

    logger.warning("REST server did not start on port %d", SERVER_PORT)


# ---------------------------------------------------------------------------
# HTTP helpers — sync by design, offloaded via asyncio.to_thread
# ---------------------------------------------------------------------------

def _get(path: str) -> dict[str, Any]:
    url = f"{_BASE_URL}{path}"
    with urllib.request.urlopen(url, timeout=300) as resp:
        return json.loads(resp.read())


def _post(path: str, body: dict | None = None) -> dict[str, Any]:
    url = f"{_BASE_URL}{path}"
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def _delete(path: str, body: dict | None = None) -> dict[str, Any]:
    url = f"{_BASE_URL}{path}"
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="DELETE",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def _http_error_to_dict(exc: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        detail = json.loads(exc.read()).get("detail", str(exc))
    except Exception:
        detail = str(exc)
    return {"status": "failed", "error": detail}


# ---------------------------------------------------------------------------
# CA input resolution (unchanged from original)
# ---------------------------------------------------------------------------

CA_PROVIDER_CHOICES = {
    "digicert", "letsencrypt", "letsencrypt_staging",
    "zerossl", "sectigo", "custom",
}
CA_INPUT_MODE_CHOICES = {"config", "custom"}


def _resolve_ca_inputs(
    ca_input_mode: str,
    ca_provider: str | None,
    acme_directory_url: str | None,
) -> tuple[str | None, str | None]:
    if ca_input_mode not in CA_INPUT_MODE_CHOICES:
        raise ValueError(f"ca_input_mode must be one of: {', '.join(sorted(CA_INPUT_MODE_CHOICES))}")
    if ca_input_mode == "config":
        return None, None
    if not ca_provider or not acme_directory_url:
        raise ValueError(
            "When ca_input_mode='custom', both ca_provider and acme_directory_url are required"
        )
    if ca_provider not in CA_PROVIDER_CHOICES:
        raise ValueError(f"ca_provider must be one of: {', '.join(sorted(CA_PROVIDER_CHOICES))}")
    if not acme_directory_url.startswith(("http://", "https://")):
        raise ValueError("acme_directory_url must start with http:// or https://")
    return ca_provider, acme_directory_url


def _validate_domain_for_cert_generation(domain: str) -> None:
    if not domain:
        raise ValueError("domain cannot be empty")
    if "/" in domain or "\\" in domain:
        raise ValueError("domain cannot contain path separators")
    if ".." in domain or domain.startswith("."):
        raise ValueError("domain cannot contain path traversal sequences")
    if domain in {".", ".."}:
        raise ValueError("invalid domain name")


# ---------------------------------------------------------------------------
# MCP server + tools
# ---------------------------------------------------------------------------

mcp = FastMCP("acme-certificate-lifecycle-agent")


@mcp.tool()
async def health(
    ca_input_mode: Literal["config", "custom"],
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Return non-secret configuration/readiness checks with explicit CA input mode."""
    try:
        _resolve_ca_inputs(ca_input_mode, ca_provider, acme_directory_url)
        return await asyncio.to_thread(_get, "/health")
    except Exception as exc:
        logger.exception("health check failed")
        return {"ok": False, "status": "failed", "error": str(exc)}


@mcp.tool()
async def renew_once(
    ca_input_mode: Literal["config", "custom"],
    domains: list[str] | None = None,
    checkpoint: bool = False,
    ca_provider: str | None = None,
    acme_directory_url: str | None = None,
) -> dict[str, Any]:
    """Run one renewal cycle. Blocks until the full graph completes — synchronous by design."""
    try:
        _resolve_ca_inputs(ca_input_mode, ca_provider, acme_directory_url)
        effective_domains = domains or []
        if not effective_domains:
            import config
            effective_domains = list(config.settings.MANAGED_DOMAINS)

        results: dict[str, Any] = {
            "status": "success",
            "completed_renewals": [],
            "failed_renewals": [],
            "error_log": [],
        }
        for domain in effective_domains:
            r = await asyncio.to_thread(
                _post,
                f"/domains/{domain}/renew",
                {"checkpoint": checkpoint},
            )
            results["completed_renewals"].extend(r.get("completed_renewals", []))
            results["failed_renewals"].extend(r.get("failed_renewals", []))
            results["error_log"].extend(r.get("error_log", []))
        return results
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("renew_once failed")
        return {"status": "failed", "error": str(exc)}


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
        _resolve_ca_inputs(ca_input_mode, ca_provider, acme_directory_url)
        if reason not in {0, 1, 4, 5}:
            raise ValueError("reason must be one of: 0, 1, 4, 5")

        results: dict[str, Any] = {
            "status": "success",
            "revoked_domains": [],
            "failed_revocations": [],
            "error_log": [],
        }
        for domain in domains:
            r = await asyncio.to_thread(
                _delete,
                f"/domains/{domain}/cert",
                {"reason": reason, "checkpoint": checkpoint},
            )
            results["revoked_domains"].extend(r.get("revoked_domains", []))
            results["failed_revocations"].extend(r.get("failed_revocations", []))
            results["error_log"].extend(r.get("error_log", []))
        return results
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("revoke_cert failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def expiring_in_30_days(domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires in 30 days or less (read-only)."""
    try:
        return await asyncio.to_thread(_get, "/domains/expiring?days=30")
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("expiring_in_30_days failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def expiring_within(days: int, domains: list[str] | None = None) -> dict[str, Any]:
    """List domains whose current cert expires within N days (read-only).

    Args:
        days: Look-ahead window in days (1–3650).
        domains: Domains to check. Defaults to all managed domains.
    """
    try:
        if days < 1 or days > 3650:
            raise ValueError("days must be between 1 and 3650")
        return await asyncio.to_thread(_get, f"/domains/expiring?days={days}")
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("expiring_within failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def list_managed_domains() -> dict[str, Any]:
    """Return the list of domains currently configured in MANAGED_DOMAINS (read-only)."""
    try:
        return await asyncio.to_thread(_get, "/domains")
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("list_managed_domains failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def domain_status(domains: list[str]) -> dict[str, Any]:
    """Get certificate status details for one or more domains (read-only)."""
    try:
        if not domains:
            raise ValueError("domains must contain at least one domain")
        statuses = []
        for domain in domains:
            r = await asyncio.to_thread(_get, f"/domains/{domain}/status")
            statuses.append(r)
        return {"status": "success", "domain_statuses": statuses}
    except urllib.error.HTTPError as exc:
        return _http_error_to_dict(exc)
    except Exception as exc:
        logger.exception("domain_status failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def read_cert_details(domains: list[str]) -> dict[str, Any]:
    """Return rich certificate details for one or more domains (read-only).

    Includes subject CN, SANs, issuer org, detected CA, serial number, and validity dates.
    """
    try:
        if not domains:
            raise ValueError("domains must contain at least one domain")
        details = []
        for domain in domains:
            try:
                r = await asyncio.to_thread(_get, f"/domains/{domain}/cert")
                details.append(r)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    details.append({"domain": domain, "cert_found": False})
                else:
                    details.append({"domain": domain, "cert_found": True, "status": "error", "error": str(exc)})
        return {"status": "success", "cert_details": details}
    except Exception as exc:
        logger.exception("read_cert_details failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def generate_test_cert(domain: str, days: int) -> dict[str, Any]:
    """Generate a self-signed test certificate with configurable validity period.

    Args:
        domain: Domain name for the certificate CN (must not contain path separators)
        days: Validity period in days from now (use negative for expired certs)
    """
    try:
        from scripts.generate_test_cert import generate_self_signed_cert
        import datetime
        import config

        _validate_domain_for_cert_generation(domain)
        store_path = Path(config.settings.CERT_STORE_PATH)
        output_dir = store_path / domain

        await asyncio.to_thread(
            generate_self_signed_cert,
            domain=domain,
            validity_days=days,
            output_dir=output_dir,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_after = now + datetime.timedelta(days=days)
        days_remaining = (not_valid_after - now).days
        status_text = (
            "EXPIRED" if days_remaining < 0
            else ("EXPIRING SOON" if days_remaining <= 30 else "VALID")
        )

        return {
            "status": "success",
            "message": f"Generated self-signed certificate for {domain}",
            "domain": domain,
            "validity_days": days,
            "cert_status": status_text,
            "days_remaining": days_remaining,
            "output_directory": str(output_dir),
            "files": [
                str(output_dir / "cert.pem"),
                str(output_dir / "privkey.pem"),
                str(output_dir / "metadata.json"),
            ],
        }
    except Exception as exc:
        logger.exception("generate_test_cert failed")
        return {"status": "failed", "error": str(exc)}


@mcp.tool()
async def query_context(
    prompt: str,
    top_n: int = 5,
    layers: list[str] | None = None,
) -> dict[str, Any]:
    """Query the unified 3-layer team context: SQLite memory, code graph, and RAG over docs/PRs.

    Layers:
      - memory : curated SQLite facts, gotchas, architectural decisions
      - graph  : structural facts — who calls what, where is a symbol defined
      - rag    : semantic search over doc/ markdown and merged PR descriptions

    Args:
        prompt: Natural language question or keyword
        top_n:  Max results per layer (default 5)
        layers: Subset of layers to query. Defaults to all three.
    """
    import sys
    from pathlib import Path as _Path

    tools_dir = _Path(__file__).parent / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))

    try:
        from context_query import context_query
    except ImportError as exc:
        return {"status": "error", "error": f"context_query not available: {exc}"}

    try:
        result = await asyncio.to_thread(context_query, prompt, top_n=top_n, layers=layers)
        return {"status": "ok", "result": result}
    except Exception as exc:
        logger.exception("query_context failed")
        return {"status": "error", "error": str(exc)}


if __name__ == "__main__":
    start_rest_server()
    mcp.run()
