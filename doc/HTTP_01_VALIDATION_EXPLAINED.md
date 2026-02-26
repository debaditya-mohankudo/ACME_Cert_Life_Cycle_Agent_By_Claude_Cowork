# HTTP-01 Challenge Validation: Domain Ownership Without Authentication

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- HTTP challenge configuration: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)

**Why HTTP-01 works despite the ACME server being unauthenticated**

---

## Executive Summary

HTTP-01 proves domain ownership **without requiring the ACME server to authenticate us**. Instead of authenticating the person making the HTTP request, we prove we **control the domain's HTTP server** by placing a specific file at a specific location. The ACME server (acting as an unauthenticated HTTP client) verifies the file exists with the correct content.

**Key principle:** Control of the HTTP server = proof of domain ownership.

---

## The HTTP-01 Challenge Flow

### Complete End-to-End Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. We (ACME client) create CSR with domain                  │
│    → Send to ACME server: "Renew cert for example.com"      │
│    → Include: domain name, public key, signature            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. ACME server generates challenge                          │
│    → Sends back: "Prove you own example.com"                │
│    → Challenge token: "abc123xyz..." (random, one-time)     │
│    → Our account JWK thumbprint: (SHA-256 hash of pubkey)   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. WE write proof file to OUR web server                    │
│    → File path: /.well-known/acme-challenge/{token}         │
│    → File content: {token}.{thumbprint}                     │
│    → Must be publicly accessible via HTTP (not HTTPS)       │
│    → Example:                                               │
│      abc123xyz.J7z3H8d9k2L5m4n6p0q1r2s3t4u5v6w7x8y9z0a1b2c3 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. We tell ACME server "ready to validate"                  │
│    → POST /challenge with JWS signature                     │
│    → Signature proves we know our private key               │
│    → (Proves we're the same entity that created the CSR)    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. ACME server makes UNAUTHENTICATED HTTP GET               │
│    → GET http://example.com/.well-known/acme-challenge/abc… │
│    → No credentials sent (Authorization header not needed)  │
│    → Reads response body                                    │
│    → Compares to: {token}.{thumbprint}                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 6a. If content matches → Authorization VALID                │
│     → Proof established: we own example.com's HTTP server    │
│                                                              │
│ 6b. If content missing/wrong → Authorization INVALID         │
│     → Someone else prevented us from writing the file        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. Only with VALID authorization can we finalize the order  │
│    → POST /finalize with CSR                                │
│    → CA issues the certificate                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Why Authentication Isn't Needed

### The Security Model

HTTP-01 security **does not** depend on:
- ❌ The ACME server authenticating us (the HTTP client)
- ❌ Username/password on the HTTP endpoint
- ❌ Mutual TLS between ACME server and domain's HTTP server
- ❌ Digital signatures in the HTTP response

HTTP-01 security **does** depend on:
- ✅ **We control the domain's HTTP server** (can write files)
- ✅ **ACME server can reach the domain** via DNS + HTTP
- ✅ **Content match proves control** (cryptographically tied to our account via thumbprint)

### Why This Works: Three Scenarios

#### Scenario 1: Attacker tries to renew `example.com`

```
Attacker's flow:
  1. Submit CSR for example.com
  2. Receive challenge token "xyz789"
  3. Try to prove ownership...
     → Can't write to example.com's web server (attacker doesn't control it)
     → ACME server requests /.well-known/acme-challenge/xyz789
     → Finds nothing or wrong content
  4. ❌ ACME server marks authorization INVALID
  5. ❌ Certificate not issued
```

**Why it fails:** Attacker doesn't control example.com's HTTP server.

#### Scenario 2: Real owner (us) renews `example.com`

```
Our flow:
  1. Submit CSR for example.com
  2. Receive challenge token "xyz789"
  3. Write proof file:
     → File: /.well-known/acme-challenge/xyz789
     → Content: xyz789.{our_thumbprint}
  4. Tell ACME: "ready to validate"
  5. ACME server requests /.well-known/acme-challenge/xyz789
     → Hits our web server (we control the IP)
     → Reads content: xyz789.{our_thumbprint}
     → ✅ Content matches!
  6. ✅ ACME server marks authorization VALID
  7. ✅ Certificate issued
```

**Why it succeeds:** We control example.com's HTTP server.

#### Scenario 3: Attacker with MITM tries to intercept

```
Attacker intercepts request:
  1. ACME server tries to GET http://example.com/.well-known/acme-challenge/xyz789
  2. Attacker intercepts the DNS/TCP connection
  3. Attacker sends back fake content: "attacker_token.fake_thumbprint"
  4. ACME server receives response
     → Expects: xyz789.{real_thumbprint}
     → Receives: attacker_token.fake_thumbprint
  5. ❌ Content doesn't match
  6. ❌ Authorization INVALID
```

**Why attacker fails:** They'd need to know our thumbprint (which is public, but the token is one-time) AND somehow send the correct response. Even if they control the network, they can't forge the cryptographic proof.

---

## The Role of the Thumbprint

The **JWK thumbprint** ties the proof to our account:

```
JWK Thumbprint = SHA-256(sorted_json(public_key))

Example:
  Public key: {"e":"AQAB","kty":"RSA","n":"0vx7a..."}
  Thumbprint: J7z3H8d9k2L5m4n6p0q1r2s3t4u5v6w7x8y9z0a1b2c3

Challenge token: abc123xyz (random, one-time)
Key authorization: abc123xyz.J7z3H8d9k2L5m4n6p0q1r2s3t4u5v6w7x8y9z0a1b2c3

Why this matters:
- Only WE know our private key
- Only WE can generate signatures that prove we own the account
- The thumbprint ties the challenge to our account
- An attacker can't reuse our challenge with a different account
- An attacker can't forge the thumbprint without our private key
```

---

## HTTP-01 in the ACME RFC 8555

### The Protocol Definition

**RFC 8555 § 8.3 — HTTP Challenge:**

> The ACME server verifies the challenge by making an HTTP request to
> the URI constructed by concatenating:
> `http://<domain>/.well-known/acme-challenge/<token>`
>
> The ACME server then checks that the HTTP response body is exactly
> the key authorization string.

**Key phrase:** "exactly the key authorization string" — no authentication needed, just string matching.

### Why HTTP (Not HTTPS)?

HTTP-01 uses **HTTP, not HTTPS** because:

1. **Bootstrap problem:** We need a cert to use HTTPS, but we're trying to get a cert (chicken-and-egg)
2. **Port 80 is standard for validation:** ACME servers expect port 80
3. **No secrecy needed:** The token and thumbprint are public (already sent to ACME)
4. **ACME server uses HTTPS to talk to us:** Our CSR and signatures are protected by TLS

---

## HTTP-01 in the Agent's Code

### Implementation Overview

The agent handles HTTP-01 in two modes:

#### Mode 1: Standalone (Agent Runs Its Own Server)

```python
# config.py
HTTP_CHALLENGE_MODE = "standalone"
# Port 80 must be accessible from the internet

# agent/nodes/challenge.py → challenge_setup()
from acme.http_challenge import StandaloneChallenge

challenge = StandaloneChallenge(
    challenge_token="abc123xyz",
    key_authorization="abc123xyz.J7z3H8d9k2L5m4n6p0q1r2s3t4u5v6w7x8y9z0a1b2c3",
    port=80,
)
challenge.start()  # Starts HTTP server listening on port 80

# ACME server will now GET http://domain/.well-known/acme-challenge/abc123xyz
# Our server responds with the key_authorization
```

**Code location:** [`acme/http_challenge.py`](../acme/http_challenge.py)

```python
class StandaloneChallenge:
    """Run a simple HTTP server on port 80 to serve challenge."""

    def start(self):
        # Listen on port 80
        # Serve /.well-known/acme-challenge/{token} → {key_auth}
        # All other requests → 404
        ...

    def stop(self):
        # Shut down server after ACME validates
        ...
```

#### Mode 2: Webroot (Agent Writes to Existing Server)

```python
# config.py
HTTP_CHALLENGE_MODE = "webroot"
WEBROOT_PATH = "/var/www/html"

# agent/nodes/challenge.py → challenge_setup()
token = state["current_order"]["challenge_tokens"][0]
key_auth = state["current_order"]["key_authorizations"][0]

# Write file to existing web server directory
challenge_file = Path(WEBROOT_PATH) / ".well-known" / "acme-challenge" / token
challenge_file.parent.mkdir(parents=True, exist_ok=True)
challenge_file.write_text(key_auth)

# Existing nginx/apache serves the file when ACME requests it
```

### Challenge Verification

```python
# agent/nodes/challenge.py → challenge_verifier()

while True:
    # Poll ACME server for challenge status
    order = client.get_order(order_url, account_key, nonce, directory)

    # ACME server has already tried to validate:
    # GET http://example.com/.well-known/acme-challenge/{token}
    # Checked if response == {token}.{thumbprint}

    if order.status == "valid":
        # ✅ ACME found the file with correct content
        break
    elif order.status == "invalid":
        # ❌ ACME couldn't find file or content didn't match
        raise AcmeError("Challenge failed")

    time.sleep(1)  # Poll again
```

---

## Why HTTP-01 is Secure

### Attack Vectors and Why They Fail

| Attack | How It Works | Why It Fails |
|--------|--------------|-------------|
| **Attacker renews cert for example.com** | Submit CSR with example.com | ACME server requests file from example.com's server. Attacker can't write to it. ❌ |
| **Attacker intercepts HTTP request** | MITM the HTTP GET | They'd need to send response with our thumbprint (which requires our private key). ❌ |
| **Attacker replays old token** | Use a token from an old challenge | ACME tokens are one-time use. Each challenge gets a fresh random token. ❌ |
| **Attacker DNS spoofs example.com** | Respond to DNS query with attacker IP | ACME server would GET their server, which doesn't have the file. ❌ |
| **Attacker uses wrong thumbprint** | Send back a different thumbprint | ACME server expects our specific thumbprint (tied to our account). ❌ |

### The Security Proof

HTTP-01 security reduces to a single question:

> **Can the challenger write arbitrary content to `http://domain/.well-known/acme-challenge/`?**

- **Yes** → They control the domain's HTTP server → Proof of ownership ✅
- **No** → They don't control the server → Can't prove ownership ❌

There's no escaping this: to pass HTTP-01, you must control the domain's web server.

---

## Limitations of HTTP-01

| Limitation | Impact | Workaround |
|-----------|--------|-----------|
| **Requires port 80 open to internet** | Some firewalls block port 80 | Use DNS-01 instead (but requires API access to DNS provider) |
| **Only for HTTP domains** | Can't validate `https://example.com` only | Use certificate with multiple SANs, validate all via HTTP-01 |
| **Single domain per challenge** | Can't validate wildcard or root + subdomain together | Issue separate certs or use DNS-01 |
| **Validation visible to public** | Anyone can see the challenge file for 30 seconds | Security through obscurity not needed (token is random) |

---

## RFC References

### RFC 8555 — ACME Protocol
- **§ 8.3:** HTTP Challenge — token URL format, key-authorization content, and CA verification behaviour
- **§ 6.5:** Replay-Nonce — one-time nonce requirement (why challenge tokens are single-use)
- **§ 7.3:** Account Management — `newAccount` endpoint
- **§ 7.3.2:** Account JWK — public key used to derive the JWK thumbprint

### RFC 7638 — JSON Web Key Thumbprint
- **§ 3:** JWK Thumbprint Computation — SHA-256 over the canonical JSON serialisation of the account public key; result base64url-encoded and appended to the challenge token

---

## Related Documentation

- **[HTTP-01 Challenge Modes](HTTP_CHALLENGE_MODES.md)** — Standalone vs. webroot setup
- **[ACME Agent Plan](ACME_AGENT_PLAN.md)** — Full ACME protocol flow (§ 3)
- **[Challenge Setup Node](../agent/nodes/challenge.py)** — Implementation in agent
- **[HTTP Challenge Server](../acme/http_challenge.py)** — Standalone HTTP server code

---

## Summary

**HTTP-01 doesn't require authenticating the HTTP request because it's not about authenticating the requester — it's about proving control of the server.**

The ACME server is just a dumb HTTP client that:
1. Makes an unauthenticated GET request
2. Reads the response
3. Checks if it matches the token + thumbprint
4. Issues a certificate if it does

Only the domain's HTTP server owner can write the file with the correct content, therefore **control of the HTTP server = proof of domain ownership.**

🔐 **This is secure because:** No credential required ≠ No security. The security comes from the cryptographic proof (thumbprint) and the fact that only the domain owner can place a file on their server.
