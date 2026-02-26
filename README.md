# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## Documentation

| Topic | Link |
|---|---|
| Docs wiki home | [WIKI_HOME.md](doc/WIKI_HOME.md) |
| How it works | [HOW_IT_WORKS.md](doc/README_HOW_IT_WORKS.md) |
| Project structure | [PROJECT_STRUCTURE.md](doc/README_PROJECT_STRUCTURE.md) |
| Prerequisites | [PREREQUISITES.md](doc/README_PREREQUISITES.md) |
| Setup | [SETUP.md](doc/README_SETUP.md) |
| Running with Docker | [DOCKER.md](doc/README_DOCKER.md) |
| Usage | [USAGE.md](doc/README_USAGE.md) |
| MCP server usage | [MCP_SERVER.md](doc/README_MCP_SERVER.md) |
| MCP implementation details | [MCP_IMPLEMENTATION_DETAILS.md](doc/README_MCP_IMPLEMENTATION_DETAILS.md) |
| Pebble testing server | [PEBBLE_TESTING_SERVER.md](doc/PEBBLE_TESTING_SERVER.md) |
| Configuration reference | [CONFIGURATION.md](doc/README_CONFIGURATION.md) |
| Certificate revocation | [REVOCATION_IMPLEMENTATION.md](doc/REVOCATION_IMPLEMENTATION.md) |
| Certificate storage layout | [CERTIFICATE_STORAGE.md](doc/README_CERTIFICATE_STORAGE.md) |
| HTTP-01 challenge modes | [HTTP_CHALLENGE_MODES.md](doc/README_HTTP_CHALLENGE_MODES.md) |
| HTTP-01 validation explained | [HTTP_01_VALIDATION_EXPLAINED.md](doc/HTTP_01_VALIDATION_EXPLAINED.md) |
| LLM nodes and provider support | [LLM_NODES.md](doc/README_LLM_NODES.md) |
| Let's Encrypt | [LETS_ENCRYPT.md](doc/README_LETS_ENCRYPT.md) |
| Observability | [OBSERVABILITY.md](doc/README_OBSERVABILITY.md) |
| Security considerations | [SECURITY.md](doc/README_SECURITY.md) |
| Dependencies | [DEPENDENCIES.md](doc/README_DEPENDENCIES.md) |

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
