# MCP Server Usage

This project can be run as an MCP server and expose ACME lifecycle services as tools.

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

- `health(ca_input_mode: "config"|"custom", ca_provider?: string, acme_directory_url?: string)`
  - Returns non-secret configuration/provider readiness checks.
- `expiring_in_30_days(domains?: string[])`
  - Returns managed domains with existing certificates expiring in 30 days or less.
  - If `domains` is omitted, uses `MANAGED_DOMAINS` from `.env`.
- `domain_status(domains: string[])`
  - Returns certificate status details for specific domains.
  - Status values: `missing`, `expired`, `expiring_soon`, `valid`, `parse_error`.
- `renew_once(ca_input_mode: "config"|"custom", domains?: string[], checkpoint?: bool, ca_provider?: string, acme_directory_url?: string)`
  - Runs one renewal cycle.
  - If `domains` is omitted, uses `MANAGED_DOMAINS` from `.env`.
- `revoke_cert(ca_input_mode: "config"|"custom", domains: string[], reason?: 0|1|4|5, checkpoint?: bool, ca_provider?: string, acme_directory_url?: string)`
  - Revokes certificates for one or more domains.
  - `ca_input_mode="config"` uses values from config.py/.env.
  - `ca_input_mode="custom"` requires both `ca_provider` and `acme_directory_url`.

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
- A process-wide operation lock serializes all MCP tool calls (`health`, `renew_once`, `revoke_cert`, `expiring_in_30_days`, `domain_status`).
- Long-running schedule mode is intentionally not exposed as an MCP tool.
