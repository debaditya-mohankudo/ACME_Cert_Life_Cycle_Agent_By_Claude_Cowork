# MCP Server Implementation Details

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- MCP usage guide: [MCP_SERVER.md](MCP_SERVER.md)
- MCP serialization policy: [MCP_TOOL_SERIALIZATION.md](MCP_TOOL_SERIALIZATION.md)
- Security controls: [SECURITY.md](SECURITY.md)

This document captures the implementation details added to expose this project as an MCP server.

## Scope implemented

- Added a local MCP server entrypoint for ACME lifecycle operations.
- Exposed MCP tools mapped to existing CLI/graph entrypoints.
- Added VS Code workspace MCP configuration.
- Added a smoke-test client script for end-to-end validation.
- Added user-facing documentation for setup and usage.

## New server entrypoint

- File: `mcp_server.py`
- Transport: stdio
- Server framework: `FastMCP` from Python `mcp` SDK

### Exposed tools

1. `health()`
   - No side effects.
   - Returns non-secret readiness metadata:
     - `provider`
     - `acme_directory`
     - `llm_provider`
     - `challenge_mode`
     - `managed_domain_count`
     - `warnings`

2. `expiring_in_30_days(domains?: string[])`
  - No side effects.
  - Reuses `main.list_domains_expiring_within(days=30, ...)`.
  - Returns:
    - `window_days`
    - `expiring_domains`

3. `domain_status(domains: string[])`
  - No side effects.
  - Reuses `main.get_domain_statuses(...)`.
  - Returns:
    - `domain_statuses`

4. `renew_once(domains?: string[], checkpoint?: bool)`
   - Calls existing renewal flow via `main.run_once(...)`.
   - Returns compact outcome:
     - `completed_renewals`
     - `failed_renewals`
     - `error_log`

5. `revoke_cert(domains: string[], reason?: 0|1|4|5, checkpoint?: bool)`
   - Calls existing revocation flow via `main.run_revocation(...)`.
   - Validates reason code in MCP layer.
   - Returns compact outcome:
     - `revoked_domains`
     - `failed_revocations`
     - `error_log`

6. `generate_test_cert(domain: string, days: int)`
   - Generates self-signed test certificate for a domain.
   - Supports negative `days` to create expired test certs.
   - Validates domain to prevent path traversal attacks.
   - Stores in configured `CERT_STORE_PATH` (never arbitrary paths).
   - Applies process-wide operation lock (serialized mutation).
   - Returns certificate details:
     - `domain`
     - `validity_days`
     - `cert_status` (EXPIRED | EXPIRING SOON | VALID)
     - `days_remaining`
     - `output_directory`
     - `files` (paths to cert.pem, key.pem, chain.pem)

7. `list_managed_domains()`
   - No side effects.
   - Returns the full `MANAGED_DOMAINS` list from active config.
   - Returns: `managed_domains`, `count`.

8. `expiring_within(days: int, domains?: string[])`
   - No side effects.
   - Generalises `expiring_in_30_days` with a configurable look-ahead window (1–3650 days).
   - Reuses `main.list_domains_expiring_within(days=N, ...)`.
   - Returns: `window_days`, `expiring_domains`.

9. `read_cert_details(domains: string[])`
   - No side effects.
   - Parses each domain's `cert.pem` using `cryptography.x509` and returns rich fields.
   - CA detection: checks `metadata.json` first (written by `storage_manager`), falls back to X.509 issuer inspection via `acme.ca_detection.detect_ca_from_cert()`.
   - Returns per domain:
     - `subject_cn`
     - `sans`
     - `issuer_org`
     - `detected_ca`
     - `serial` (colon-separated hex)
     - `not_before`, `not_after`
     - `days_until_expiry`
     - `status` (`valid` | `expiring_soon` | `expired`)
     - `expired`

## Architectural alignment

The MCP layer reuses existing `main.py` entrypoints and does not alter graph topology.

- Renewal path: existing `build_graph()` flow unchanged.
- Revocation path: existing `build_revocation_graph()` flow unchanged.
- Retry semantics remain in existing nodes (`error_handler` + `retry_scheduler`).
- No new ACME concurrency introduced.

## Dependency changes

- `pyproject.toml`
  - Added `mcp>=1.6` in `dependency-groups.dev`.
- `requirements.txt`
  - Added `mcp>=1.6`.
- `uv.lock`
  - Updated by `uv sync`.

## VS Code integration

- File: `.vscode/mcp.json`
- Added server entry:

```json
"local/acme-certificate-lifecycle-agent": {
  "type": "stdio",
  "command": "uv",
  "args": ["run", "python", "mcp_server.py"]
}
```

This allows MCP-enabled VS Code chat/agent tooling to launch the project server from workspace configuration.

## Smoke test implementation

- File: `scripts/mcp_smoke_test.py`
- Uses MCP Python client (`stdio_client` + `ClientSession`) to validate:
  1. Server initializes
  2. Expected tools are registered (`health`, `renew_once`, `revoke_cert`, `generate_test_cert`, `list_managed_domains`, `expiring_in_30_days`, `expiring_within`, `domain_status`, `read_cert_details`)
  3. `health` tool executes successfully

### Safe default command

```bash
uv run python scripts/mcp_smoke_test.py
```

### Optional mutating checks

```bash
uv run python scripts/mcp_smoke_test.py --run-renew
uv run python scripts/mcp_smoke_test.py --run-revoke --revoke-domains example.com --reason 4
```

## Documentation updates made

- `README.md`
  - Added docs table link to MCP server usage.
- `doc/USAGE.md`
  - Added MCP server run section.
- `doc/MCP_SERVER.md`
  - Added VS Code workspace configuration and smoke-test instructions.

## Validation performed

1. Import validation:

```bash
uv run python -c "import mcp_server; print('mcp_server import ok')"
```

2. VS Code MCP config JSON validation:

```bash
uv run python -m json.tool .vscode/mcp.json >/dev/null && echo 'mcp.json valid'
```

3. End-to-end smoke test:

```bash
uv run python scripts/mcp_smoke_test.py
```

Observed result: pass (server started, tools listed, `health` call succeeded).

## Intentional exclusions

- `run_scheduled(...)` is not exposed as an MCP tool.
  - Reason: it is long-running daemon behavior and not a request/response style MCP tool.
