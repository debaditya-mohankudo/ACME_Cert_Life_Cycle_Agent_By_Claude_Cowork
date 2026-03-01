# MCP Server Usage

This project can be run as an MCP server and expose ACME lifecycle services as tools.

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- MCP implementation details: [MCP_IMPLEMENTATION_DETAILS.md](MCP_IMPLEMENTATION_DETAILS.md)
- MCP serialization policy: [MCP_TOOL_SERIALIZATION.md](MCP_TOOL_SERIALIZATION.md)

## Retrieval keywords

`mcp`, `stdio transport`, `mcp_server.py`, `tool list`, `health`, `renew_once`, `domain_status`, `revoke_cert`, `generate_test_cert`, `expiring_within`, `list_managed_domains`, `read_cert_details`, `SANs`, `serial`, `self-signed`, `vscode mcp`, `.vscode/mcp.json`, `smoke test`
[negative keywords / not-this-doc]
async, concurrency, parallel, checkpoint, nonce, stateful, planner, LLM, CI, revoke, configuration, storage, atomic, filesystem, docker, container, test, coverage, audit, performance, optimization, operator

## Prerequisites

- Project dependencies installed:

```bash
uv sync
```

- Valid `.env` configuration (same as normal CLI usage)

## Start the MCP server

```bash
python mcp_server.py
```

The server runs over stdio transport, suitable for MCP clients such as Claude Desktop and IDE-based agents.

## VS Code workspace configuration

This repository includes a workspace MCP config at `.vscode/mcp.json` with this server registered:

```json
"local/acme-certificate-lifecycle-agent": {
  "type": "stdio",
  "command": "uv",
  "args": ["run", "python", "mcp_server.py"]
}
```

In VS Code:

1. Open this workspace.
2. Ensure dependencies are installed with `uv sync`.
3. Open Chat/Copilot Agent tools and refresh MCP servers (or reload window).
4. Confirm `local/acme-certificate-lifecycle-agent` is available.

## Smoke test (VS Code terminal)

Safe default (non-mutating: checks server startup, tool list, and `health`):

```bash
uv run python scripts/mcp_smoke_test.py
```

Optional mutating calls:

```bash
# Includes renew_once
uv run python scripts/mcp_smoke_test.py --run-renew

# Includes revoke_cert (example)
uv run python scripts/mcp_smoke_test.py --run-revoke --revoke-domains example.com --reason 4
```

## Exposed tools

### Read-only tools (not serialized — concurrent-safe)

- `list_managed_domains()`
  - Returns the full list of domains currently configured in `MANAGED_DOMAINS`.
  - Returns: `managed_domains`, `count`.
- `expiring_in_30_days(domains?: string[])`
  - Returns managed domains with existing certificates expiring in 30 days or less.
  - If `domains` is omitted, uses `MANAGED_DOMAINS` from `.env`.
- `expiring_within(days: int, domains?: string[])`
  - Configurable version of `expiring_in_30_days` — accepts any look-ahead window (1–3650 days).
  - Returns: `window_days`, `expiring_domains`.
- `domain_status(domains: string[])`
  - Returns certificate status details for specific domains.
  - Status values: `missing`, `expired`, `expiring_soon`, `valid`, `parse_error`.
- `read_cert_details(domains: string[])`
  - Returns rich certificate inspection for one or more domains.
  - Fields: `subject_cn`, `sans`, `issuer_org`, `detected_ca`, `serial` (colon-hex), `not_before`, `not_after`, `days_until_expiry`, `status`, `expired`.
  - CA detection uses `metadata.json` first, then X.509 issuer field inspection.

### Mutating tools (serialized via process-wide lock)

- `health(ca_input_mode: "config"|"custom", ca_provider?: string, acme_directory_url?: string)`
  - Returns non-secret configuration/provider readiness checks.
- `renew_once(ca_input_mode: "config"|"custom", domains?: string[], checkpoint?: bool, ca_provider?: string, acme_directory_url?: string)`
  - Runs one renewal cycle.
  - If `domains` is omitted, uses `MANAGED_DOMAINS` from `.env`.
- `revoke_cert(ca_input_mode: "config"|"custom", domains: string[], reason?: 0|1|4|5, checkpoint?: bool, ca_provider?: string, acme_directory_url?: string)`
  - Revokes certificates for one or more domains.
  - `ca_input_mode="config"` uses values from config.py/.env.
  - `ca_input_mode="custom"` requires both `ca_provider` and `acme_directory_url`.
- `generate_test_cert(domain: string, days: int)`
  - Generates a self-signed test certificate for local testing.
  - Useful for creating certificates with specific expiry states (use negative `days` for expired certs).
  - Always stored in configured `CERT_STORE_PATH` (path traversal protected).
  - Returns: `domain`, `validity_days`, `cert_status` (EXPIRED | EXPIRING SOON | VALID), `output_directory`, `files`.

Example with explicit CA inputs:

```json
{
  "ca_input_mode": "custom",
  "domains": ["my.local"],
  "ca_provider": "custom",
  "acme_directory_url": "https://localhost:14000/dir"
}
```

Example request for expiring domains:

```json
{
  "domains": ["api.example.com", "shop.example.com"]
}
```

Example request for domain status:

```json
{
  "domains": ["my.local", "api.example.com"]
}
```

## Notes

- The MCP tools reuse the existing graph entrypoints in `main.py` to preserve deterministic ACME flow and retry behavior.
- A process-wide operation lock serializes mutating MCP tool calls (`health`, `renew_once`, `revoke_cert`, `generate_test_cert`). Read-only tools (`list_managed_domains`, `expiring_in_30_days`, `expiring_within`, `domain_status`, `read_cert_details`) do not require this lock and can execute concurrently.
- Long-running schedule mode is intentionally not exposed as an MCP tool.
- `generate_test_cert` is intended for local testing and development; generated test certificates are not trusted by browsers.
