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
  2. Expected tools are registered (`health`, `expiring_in_30_days`, `domain_status`, `renew_once`, `revoke_cert`)
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
