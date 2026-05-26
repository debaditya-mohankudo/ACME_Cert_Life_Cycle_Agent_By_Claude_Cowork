---
name: acme-jws-signing
description: JWS signing is stateful — nonce must be fetched fresh per request
metadata:
  type: feedback
  domain: acme
  priority: 10
  tags: jws, nonce, stateful, gotcha
---

JWS signing requires a fresh nonce for every ACME POST — nonces are single-use and server-issued.

**Why:** ACME RFC 8555 §6.5 — replay attack prevention. Reusing a nonce causes a `badNonce` error and the request is rejected.

**How to apply:** Never cache or reuse `current_nonce`. It flows through `AgentState` so every node picks up the latest value. `acme/jws.py` signs with it and the response header carries the next nonce — update state immediately.
