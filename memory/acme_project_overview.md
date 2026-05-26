---
name: acme-project-overview
description: What the ACME Cert Agent does, key entry points, and primary flows
metadata:
  type: project
  domain: acme
  priority: 1
  tags: overview, entry-point, agent, langgraph
---

LangGraph StateGraph + Claude-powered agent that automates TLS certificate renewal via ACME RFC 8555.

Entry point: `main.py` — CLI flags `--once`, `--schedule`, `--revoke-cert`.
Agent graph: `agent/graph.py` — nodes are cert lifecycle stages (planner → scanner → account → order → challenge → csr → finalizer → storage → reporter).
ACME client: `acme/client.py` — stateless, one nonce per POST.
Config: `config.py` — all settings from `.env`, never mutate at runtime.

Supports DigiCert, ZeroSSL, Sectigo (EAB), Let's Encrypt, Let's Encrypt Staging, Custom CAs.
Challenge modes: standalone (HTTP-01), webroot (HTTP-01), dns (DNS-01 via Cloudflare/Route53/GCloud).
