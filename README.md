# ACME Certificate Lifecycle Agent

An intelligent, agentic TLS certificate manager built on **LangGraph** and **Claude**. It monitors certificate expiry across multiple domains, uses an LLM to plan and prioritize renewals, executes the full **ACME RFC 8555** flow against **any RFC 8555-compliant CA** (DigiCert, Let's Encrypt, or custom), and stores issued certificates as PEM files on the local filesystem — all on a configurable daily schedule.

Designed for the coming **47-day TLS mandate (2029)**, where automated renewal is not optional.

---

## Documentation

| Topic | Link |
|---|---|
| How it works | [HOW_IT_WORKS.md](doc/HOW_IT_WORKS.md) |
| Project structure | [PROJECT_STRUCTURE.md](doc/PROJECT_STRUCTURE.md) |
| Prerequisites | [PREREQUISITES.md](doc/PREREQUISITES.md) |
| Setup | [SETUP.md](doc/SETUP.md) |
| Running with Docker | [DOCKER.md](doc/DOCKER.md) |
| Usage | [USAGE.md](doc/USAGE.md) |
| Configuration reference | [CONFIGURATION.md](doc/CONFIGURATION.md) |
| Certificate storage layout | [CERTIFICATE_STORAGE.md](doc/CERTIFICATE_STORAGE.md) |
| HTTP-01 challenge modes | [HTTP_CHALLENGE_MODES.md](doc/HTTP_CHALLENGE_MODES.md) |
| LLM nodes and provider support | [LLM_NODES.md](doc/LLM_NODES.md) |
| Let's Encrypt | [LETS_ENCRYPT.md](doc/LETS_ENCRYPT.md) |
| Observability | [OBSERVABILITY.md](doc/OBSERVABILITY.md) |
| Security considerations | [SECURITY.md](doc/SECURITY.md) |
| Dependencies | [DEPENDENCIES.md](doc/DEPENDENCIES.md) |
