🚀 Built a production-grade TLS Certificate Lifecycle Agent in 2 days — with Claude Code as my co-engineer.

Here's what we shipped together:

**The agent:**
- LangGraph + Claude — stateful ACME RFC 8555 workflow with LLM-driven renewal planning, error reasoning, and reporting
- Multi-CA support — DigiCert (EAB), Let's Encrypt (production + staging), or any custom ACME endpoint, switchable with a single env var
- Full lifecycle — issue → expiry detection → renewal → revocation, all automated on a daily schedule

**The engineering:**
- Proper OOP hierarchy: `AcmeClient` base → `DigiCertAcmeClient` / `LetsEncryptAcmeClient` subclasses, with a `make_client()` factory — zero CA branching in the agent layer
- 23 tests, all green: unit (mocked HTTP), integration (full graph against Pebble), and lifecycle (issue → renew → revoke end-to-end)
- Docs, env examples, test results, and commit history — all kept in sync as the code evolved

**What Claude Code actually did:**
Planned the architecture, wrote the refactor, caught a Pylance type bug in `make_client()`, wrote the tests, updated every doc, and batched logical commits — all in natural conversation.

This isn't autocomplete. It's a collaborator that holds context across the entire codebase.

With the 47-day TLS mandate coming in 2029, automated cert lifecycle management isn't optional. We built the foundation in a weekend.

\#AI \#DevTools \#ClaudeCode \#Anthropic \#TLS \#ACME \#LangGraph \#Python \#LetsEncrypt
