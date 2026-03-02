# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## Quality & Testing

**Code Coverage:** 451 total tests (442 unit tests in CI + 9 Pebble integration tests)
- **Unit tests (CI):** 442 tests, ~200ms runtime via `xdist` parallel execution
- **Line coverage:** **91%** (5,651 / 6,220 statements covered)
- **Integration tests:** 9 tests against Pebble ACME mock server (excluded from CI)
- **Recent improvements:** `router` 60%→100%, `storage` 23%→96%, `finalizer` 22%→88%, `error_handler` 26%→98%
- **Coverage:** `acme/`, `agent/`, `storage/`, `llm/`, `config.py`, `mcp_server.py` fully tested
- See [CI_TEST_COVERAGE.md](doc/CI_TEST_COVERAGE.md) for complete breakdown and coverage details

## Documentation

| Topic | Link |
|---|---|
| Docs wiki home | [WIKI_HOME.md](doc/WIKI_HOME.md) |
| How it works | [HOW_IT_WORKS.md](doc/HOW_IT_WORKS.md) |
| Project structure | [PROJECT_STRUCTURE.md](doc/PROJECT_STRUCTURE.md) |
| Setup (includes prerequisites) | [SETUP.md](doc/SETUP.md) |
| Running with Docker | [DOCKER.md](doc/DOCKER.md) |
| Usage | [USAGE.md](doc/USAGE.md) |
| MCP server usage | [MCP_SERVER.md](doc/MCP_SERVER.md) |
| Pebble testing server | [PEBBLE_TESTING_SERVER.md](doc/PEBBLE_TESTING_SERVER.md) |
| Configuration reference | [CONFIGURATION.md](doc/CONFIGURATION.md) |
| Certificate revocation | [REVOCATION_IMPLEMENTATION.md](doc/REVOCATION_IMPLEMENTATION.md) |
| Certificate storage layout | [CERTIFICATE_STORAGE.md](doc/CERTIFICATE_STORAGE.md) |
| HTTP-01 challenge modes | [HTTP_CHALLENGE_MODES.md](doc/HTTP_CHALLENGE_MODES.md) |
| HTTP-01 validation explained | [HTTP_01_VALIDATION_EXPLAINED.md](doc/HTTP_01_VALIDATION_EXPLAINED.md) |
| LLM nodes and provider support | [LLM_NODES.md](doc/LLM_NODES.md) |
| Let's Encrypt | [LETS_ENCRYPT.md](doc/LETS_ENCRYPT.md) |
| Observability | [OBSERVABILITY.md](doc/OBSERVABILITY.md) |
| Security considerations | [SECURITY.md](doc/SECURITY.md) |
| Dependencies | [DEPENDENCIES.md](doc/DEPENDENCIES.md) |

## Quick CLI examples

```bash
python main.py --once
python main.py --schedule
python main.py --expiring-in-30-days
python main.py --domain-status my.local api.example.com
python main.py --generate-test-cert example.com --days 90
python main.py --revoke-cert example.com --reason 4
python mcp_server.py
```


## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
