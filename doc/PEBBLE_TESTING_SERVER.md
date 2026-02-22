# Pebble: ACME Testing Server & Why ACME_INSECURE is Required

**Understanding Pebble, why it exists, and why we disable TLS certificate verification for testing**

---

## What is Pebble?

Pebble is a **minimal, fake ACME server** built by Let's Encrypt for testing ACME client implementations. It implements RFC 8555 but with testing shortcuts.

```
Production ACME Server (Let's Encrypt, DigiCert)
    ↓
    [RFC 8555 compliant]
    [Real certificate issuance]
    [Validates your domain really owns the cert]
    [Strict TLS certificate validation]

Pebble Testing Server
    ↓
    [RFC 8555 mostly compliant]
    [Fake certificate issuance (doesn't matter, it's test)]
    [Auto-approves challenges (testing shortcut)]
    [Self-signed TLS certificate (testing shortcut)]
```

### Project Details

- **Source:** https://github.com/letsencrypt/pebble
- **Container:** `ghcr.io/letsencrypt/pebble:latest`
- **In this project:** [`docker-compose.pebble.yml`](../docker-compose.pebble.yml)
- **Start:** `docker compose -f docker-compose.pebble.yml up -d`

---

## Why Pebble Exists

ACME clients need a safe place to test without hitting production servers that:
- 🚫 Rate-limit heavily (50 certs per domain per week on Let's Encrypt)
- 🚫 Issue real certificates (expensive in testing)
- 🚫 Require real domain control (can't test with `localhost`)
- 🚫 Have strict validation (no shortcuts for testing)

Pebble solves this by providing **a local ACME server that:**

✅ Runs in Docker locally
✅ Accepts unlimited requests (no rate limits)
✅ Issues fake certs (not trusted, but tests the full flow)
✅ Auto-approves challenges (shortcuts DNS/HTTP verification)
✅ Has predictable behavior (intentional failures for retry testing)

---

## Pebble Configuration in Our Project

### Docker Compose Settings

```yaml
# docker-compose.pebble.yml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    ports:
      - "14000:14000"   # ACME directory API
      - "15000:15000"   # Management API (for test control)
    environment:
      PEBBLE_VA_NOSLEEP: "1"         # Don't wait between retries (faster testing)
      PEBBLE_VA_ALWAYS_VALID: "1"    # Auto-approve all challenges (shortcuts HTTP-01)
```

| Environment Variable | What It Does | Why For Testing |
|---|---|---|
| `PEBBLE_VA_NOSLEEP` | Skip delays between validation checks | Speeds up test runs |
| `PEBBLE_VA_ALWAYS_VALID` | Auto-approve all challenges (no real HTTP-01) | Don't need real DNS or port 80 |

### ACME_INSECURE Setting

```env
# docker-compose.pebble.yml → acme-test container
CA_PROVIDER=custom
ACME_DIRECTORY_URL=https://pebble:14000/dir
ACME_INSECURE=true
```

---

## The TLS Certificate Problem

### Why Pebble Uses Self-Signed Certificates

Pebble listens on **HTTPS** (port 14000) but uses a **self-signed TLS certificate**:

```
Pebble's certificate chain:
  CN=pebble
  Issuer: pebble (self-signed)
  Valid for: testing only
  ✅ Encrypts traffic (TLS works)
  ❌ Not signed by a trusted CA (verification fails)
  ❌ Not in the system certificate store
```

### What Happens Without ACME_INSECURE

When the agent connects to `https://pebble:14000/dir`:

```python
import requests

# ACME_INSECURE = False (default production behavior)
response = requests.get("https://pebble:14000/dir", verify=True)
# Python's requests library checks the certificate chain:
# ❌ "pebble" cert is self-signed (not signed by trusted CA)
# ❌ Raises: requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
# ❌ Connection refused
```

The agent can't reach Pebble because it rejects self-signed certificates.

### What ACME_INSECURE Does

```python
# ACME_INSECURE = True (testing behavior)
response = requests.get("https://pebble:14000/dir", verify=False)
# Python's requests library skips certificate verification:
# ✅ Connection succeeds (no validation)
# ✅ TLS still encrypts the traffic
# ✅ Can proceed with ACME flow
```

---

## ACME_INSECURE in the Code

### Where It's Used

**`acme/client.py` — AcmeClient.__init__()**

```python
def __init__(
    self,
    directory_url: str,
    timeout: int = 30,
    ca_bundle: str = "",
    insecure: bool = False,
) -> None:
    self.directory_url = directory_url
    self.timeout = timeout
    self._session = requests.Session()
    self._session.headers.update({"User-Agent": "acme-cert-agent/1.0"})

    if insecure:
        # TESTING: Skip TLS certificate verification
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._session.verify = False  # ← This allows self-signed certs
    elif ca_bundle:
        # Custom CA bundle (for production with private CA)
        self._session.verify = ca_bundle
    # else: Use system certificate store (default production)
```

### How It's Passed Through

**`acme/client.py` — make_client()**

```python
def make_client() -> AcmeClient:
    """Factory that reads settings and creates the appropriate ACME client."""
    ca_bundle = settings.ACME_CA_BUNDLE
    insecure = settings.ACME_INSECURE  # ← Read from config/env

    if settings.CA_PROVIDER == "digicert":
        return DigiCertAcmeClient(ca_bundle=ca_bundle, insecure=insecure)
    elif settings.CA_PROVIDER == "zerossl":
        return ZeroSSLAcmeClient(ca_bundle=ca_bundle, insecure=insecure)
    # ... etc
    elif settings.CA_PROVIDER == "custom":
        return AcmeClient(
            directory_url=settings.ACME_DIRECTORY_URL,
            ca_bundle=ca_bundle,
            insecure=insecure,  # ← Passed to base client
        )
```

### Configuration in config.py

```python
class Settings(BaseSettings):
    ACME_INSECURE: bool = Field(
        default=False,
        description="Skip TLS verification (TESTING ONLY: local Pebble server). "
                    "Never enable in production.",
    )
```

---

## ACME_INSECURE vs. Production

### Testing (Pebble with ACME_INSECURE=true)

```
Agent Connection to Pebble:
  GET https://pebble:14000/dir
  ├─ TLS handshake
  ├─ Server presents self-signed certificate
  ├─ Agent skips verification (ACME_INSECURE=true)
  ├─ ✅ Connection succeeds
  └─ Proceeds with ACME flow (issuing fake test cert)
```

**Safety:** Local Docker container, self-signed cert, testing only. No real certificates issued.

### Production (Let's Encrypt)

```
Agent Connection to Let's Encrypt:
  GET https://acme-v02.api.letsencrypt.org/directory
  ├─ TLS handshake
  ├─ Server presents certificate signed by DigiCert CA
  ├─ Agent verifies against system CA store
  ├─ ✅ Certificate valid, connection succeeds
  └─ Proceeds with ACME flow (issuing real certs)
```

**Safety:** Let's Encrypt cert signed by trusted CA, verified by system.

### Custom Production CA

```
Agent Connection to Private ACME CA:
  GET https://private-ca.company.internal/directory
  ├─ TLS handshake
  ├─ Server presents certificate signed by company CA
  ├─ Agent verifies against custom CA bundle (ACME_CA_BUNDLE=/path/to/ca.pem)
  ├─ ✅ Certificate valid, connection succeeds
  └─ Proceeds with ACME flow
```

**Safety:** Company CA bundle provided, verified against it.

---

## The Security Trade-Off

### ACME_INSECURE = False (Production Safe)

```
✅ Prevents MITM attacks
✅ Validates CA certificates
✅ Rejects self-signed certs
✅ Standard security practice

❌ Can't test with Pebble (self-signed)
❌ Requires setting up trusted certs
```

### ACME_INSECURE = True (Testing Only)

```
✅ Allows Pebble testing locally
✅ Skips setup of fake CAs
✅ Makes testing fast and simple
✅ Still uses TLS encryption

❌ Vulnerable to MITM attacks (don't use on untrusted networks!)
❌ Would accept any self-signed cert
❌ MUST NEVER be enabled in production
```

### Why It's Safe for Pebble

1. **Local Docker container** — Pebble runs locally in Docker, not over the internet
2. **No network exposure** — Container-to-container communication (internal only)
3. **Testing certificates only** — Pebble's certs don't validate real domains
4. **No production secrets** — Test environment, no real ACME credentials at stake
5. **Intentional bypass** — We know we're testing, explicitly opt-in to ACME_INSECURE

---

## Pebble's Testing Shortcuts

### Challenge Auto-Approval (PEBBLE_VA_ALWAYS_VALID)

In production, the ACME server actually performs HTTP-01 or DNS-01 validation:

```
Production (Let's Encrypt):
  1. You write challenge file to /.well-known/acme-challenge/token
  2. ACME server ACTUALLY GETs http://your-domain/...
  3. ACME server ACTUALLY checks DNS for TXT record
  4. If validation passes → challenge approved

Pebble (with PEBBLE_VA_ALWAYS_VALID):
  1. You send challenge endpoint message to Pebble
  2. Pebble automatically marks it VALID (no real HTTP/DNS check)
  3. Challenge approved immediately
  → No need for port 80 or DNS configuration
```

### Nonce No-Sleep (PEBBLE_VA_NOSLEEP)

In production, validation checks have delays (to avoid spam):

```
Production:
  Challenge submitted → Wait 1-2 seconds → Poll status
  (Prevents hammering the server)

Pebble:
  Challenge submitted → Poll status immediately
  (Faster test runs, no artificial delays)
```

---

## How to Use Pebble

### Start Pebble

```bash
docker compose -f docker-compose.pebble.yml up -d
```

This starts:
- Pebble ACME server on `localhost:14000` (inside Docker: `pebble:14000`)
- Test agent container (if running integration tests)

### Run Tests Against Pebble

```bash
# Unit tests (no Pebble needed)
pytest tests/test_unit_acme.py -v

# Integration tests (Pebble required)
pytest tests/test_integration_pebble.py -v
pytest tests/test_lifecycle_pebble.py -v
pytest tests/test_revocation_pebble.py -v
```

### Run Agent Manually with Pebble

```bash
# Set Pebble as ACME provider
export CA_PROVIDER=custom
export ACME_DIRECTORY_URL=https://localhost:14000/dir
export ACME_INSECURE=true
export MANAGED_DOMAINS=acme-test.localhost

# Run one renewal cycle
python main.py --once
```

### Stop Pebble

```bash
docker compose -f docker-compose.pebble.yml down
```

---

## Why Not Disable TLS Entirely?

You might ask: "Why use HTTPS at all in testing? Why not just HTTP?"

**Pebble uses HTTPS because:**

1. **RFC 8555 compliance** — ACME servers MUST use HTTPS (protocol requirement)
2. **Mirrors production** — Tests HTTPS/TLS code paths just like production
3. **Test TLS handling** — Ensures TLS connection logic works
4. **Security practice** — Tests that the agent can handle TLS errors gracefully

Disabling HTTPS would skip testing the entire TLS layer, which is important for catching bugs that only appear with HTTPS.

---

## Common Issues

### Issue: SSL Certificate Verify Failed

```
requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate
```

**Cause:** ACME_INSECURE not set (or set to `false`)

**Fix:**
```bash
export ACME_INSECURE=true
```

Or in Docker:
```yaml
environment:
  ACME_INSECURE: "true"
```

### Issue: Connection Refused

```
ConnectionError: Error connecting to Pebble on https://pebble:14000/dir
```

**Cause:** Pebble not running

**Fix:**
```bash
docker compose -f docker-compose.pebble.yml up -d
```

### Issue: Challenge Auto-Approval Not Working

```
Challenge status: invalid
```

**Cause:** PEBBLE_VA_ALWAYS_VALID not set in Pebble environment

**Fix:** Ensure docker-compose.pebble.yml has:
```yaml
environment:
  PEBBLE_VA_ALWAYS_VALID: "1"
```

---

## Related Files

- **[`docker-compose.pebble.yml`](../docker-compose.pebble.yml)** — Docker Compose config for Pebble
- **[`acme/client.py`](../acme/client.py)** — Where ACME_INSECURE is used (line 63-68)
- **[`config.py`](../config.py)** — ACME_INSECURE setting definition
- **[`tests/test_integration_pebble.py`](../tests/test_integration_pebble.py)** — Pebble integration tests
- **[`tests/conftest.py`](../tests/conftest.py)** — Pebble fixture setup

---

## Summary

| Aspect | Pebble | Production |
|--------|--------|-----------|
| **Server** | Local Docker container | Let's Encrypt / DigiCert / custom CA |
| **TLS Certificate** | Self-signed (not trusted) | Signed by trusted CA |
| **Certificate Verification** | Disabled (ACME_INSECURE=true) | Enabled (ACME_INSECURE=false) |
| **Challenge Validation** | Auto-approved (no real HTTP/DNS) | Real HTTP-01 or DNS-01 validation |
| **Rate Limits** | None (unlimited) | Strict (50 certs/domain/week) |
| **Certificates Issued** | Fake (for testing) | Real (trusted, can't use for production) |
| **Use Case** | Testing, CI/CD, development | Production certificate renewal |

**Key takeaway:** `ACME_INSECURE=true` disables TLS certificate verification to allow testing with Pebble's self-signed certificate. This is safe for local testing but must never be enabled against production servers.

🔒 **Never use ACME_INSECURE in production!** It defeats TLS security and makes you vulnerable to MITM attacks.
