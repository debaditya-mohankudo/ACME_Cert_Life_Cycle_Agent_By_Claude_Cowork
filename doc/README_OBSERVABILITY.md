# Observability

## Log output

All nodes emit structured log lines via Python's standard `logging`:

```
2026-02-19 06:00:01 INFO  agent.nodes.scanner   — api.example.com → expires 2026-02-24 (5 days) — URGENT
2026-02-19 06:00:03 INFO  agent.nodes.account   — Retrieved existing ACME account: https://acme.digicert.com/...
2026-02-19 06:00:07 INFO  agent.nodes.challenge — Authorization https://... is VALID
2026-02-19 06:00:12 INFO  agent.nodes.storage   — Stored PEM files for api.example.com (expires 2026-05-20)
```

## LangSmith tracing (optional)

Add to `.env` to trace every LLM call and node transition in the LangSmith UI:

```dotenv
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls__...
LANGCHAIN_PROJECT=acme-cert-agent
```

> **Security:** The ACME account private key is never stored in `AgentState` and will not appear in LangSmith traces. It is loaded from disk only within the node functions that need it.
