# RFC Compliance & Feature Scope

This document maps every implemented protocol operation to its RFC section, lists explicit constraints and design decisions, and records what is intentionally out of scope.

---

## RFCs Referenced

| RFC | Title | Role in this project |
|-----|-------|----------------------|
| **RFC 8555** | Automatic Certificate Management Environment (ACME) | Core protocol |
| **RFC 8739** | External Account Binding for ACME (EAB) | DigiCert, ZeroSSL, Sectigo account creation |
| **RFC 7638** | JSON Web Key (JWK) Thumbprint | HTTP-01 and DNS-01 key-authorization computation |
| **RFC 5280** | X.509 PKI Certificate and CRL Profile | Revocation reason codes |

---

## RFC 8555 — ACME Protocol

### Directory & Nonce

| Operation | Endpoint | §Section | Status |
|-----------|----------|---------|--------|
| Discover endpoint URLs | `GET /directory` | §7.1 | ✅ Implemented |
| Fetch anti-replay nonce | `HEAD /newNonce` | §7.2 | ✅ Implemented |

Nonce discipline (§6.5):
- Each `_post_signed()` call consumes exactly one nonce.
- `current_nonce` flows through `AgentState` so every graph node picks up a fresh value.
- On `badNonce` error the client retries up to `_NONCE_RETRIES = 3` times, extracting a fresh nonce from the error response `Replay-Nonce` header rather than making a separate round-trip.
- Parallel domain processing is permanently prohibited because a shared nonce cannot be safely split across concurrent requests.

### Account Management

| Operation | Notes | §Section | Status |
|-----------|-------|---------|--------|
| Create account | `termsOfServiceAgreed=true` | §7.3 | ✅ Implemented |
| Lookup existing account | `onlyReturnExisting=true` | §7.3.1 | ✅ Implemented |
| EAB-wrapped account creation | HS256 outer JWS; used by DigiCert, ZeroSSL, Sectigo | RFC 8739 | ✅ Implemented |

Account private key is **never** stored in `AgentState`. It lives on disk only (`ACCOUNT_KEY_PATH`, mode 0o600). This prevents it appearing in LangSmith traces or checkpoint snapshots.

### Orders & Authorizations

| Operation | Endpoint | §Section | Status |
|-----------|----------|---------|--------|
| Create order | `POST /newOrder` | §7.4 | ✅ Implemented |
| Fetch order (poll) | `POST-as-GET /order/{id}` | §7.4 | ✅ Implemented |
| Fetch authorization | `POST-as-GET /authz/{id}` | §7.5 | ✅ Implemented |
| Reuse existing authorization | Skips challenge if status=`valid` | §7.5 | ✅ Implemented |

### Challenges

| Operation | Endpoint | §Section | Status |
|-----------|----------|---------|--------|
| Respond to challenge | `POST /challenge/{id}` | §7.5.1 | ✅ Implemented |
| Poll authorization until `valid`/`invalid` | `POST-as-GET /authz/{id}` | §7.5.1 | ✅ Implemented |

### Finalization & Certificate Download

| Operation | Endpoint | §Section | Status |
|-----------|----------|---------|--------|
| Submit CSR | `POST /finalize` (DER-encoded) | §7.4 | ✅ Implemented |
| Poll order until `certificate` URL ready | `POST-as-GET /order/{id}` | §7.4 | ✅ Implemented |
| Download full PEM chain | `POST-as-GET /certificate` | §7.4.2 | ✅ Implemented |

### Revocation

| Operation | Endpoint | §Section | Status |
|-----------|----------|---------|--------|
| Revoke certificate | `POST /revokeCert` | §7.6 | ✅ Implemented |

Reason codes follow RFC 5280 §5.3.1 (0–10). The `reason` field is omitted from the payload when the code is 0 (unspecified), per §7.6 which makes it optional.

---

## RFC 8739 — External Account Binding

Applies to: **DigiCert**, **ZeroSSL**, **Sectigo**.

Implementation in `acme/client.py` (`EabAcmeClient`):

- Outer JWS protected header: `{"alg": "HS256", "kid": <eab_key_id>, "url": <newAccount_url>}`
- Payload: the account public key as JWK
- Signature: HMAC-SHA256 over `base64url(protected) + "." + base64url(payload)` using the decoded HMAC key
- Minimum HMAC key length: 16 bytes (128 bits) — validated at startup; shorter keys raise `ValueError`

---

## RFC 7638 — JWK Thumbprint

Used to derive the key-authorization suffix for both HTTP-01 and DNS-01.

Canonical JSON form for RSA keys (§3.2): members `{e, kty, n}` in lexicographic order, no whitespace. SHA-256 digest, base64url-encoded.

Key-authorization format: `{token}.{thumbprint}`

---

## RFC 5280 — Revocation Reason Codes

| Code | Reason |
|------|--------|
| 0 | unspecified (payload field omitted) |
| 1 | keyCompromise |
| 2 | cACompromise |
| 3 | affiliationChanged |
| 4 | superseded |
| 5 | cessationOfOperation |
| 6 | certificateHold |
| 7 | removeFromCRL |
| 8 | privilegeWithdrawn |
| 9 | aACompromise |
| 10 | weakSignatureAlgorithm |

Codes outside 0–10 are rejected at the CLI before any ACME request is made.

---

## Challenge Types

### HTTP-01 (RFC 8555 §8.3)

Token file served at: `http://{domain}/.well-known/acme-challenge/{token}`
Content: `{token}.{jwk_thumbprint}`

| Mode | Mechanism | Config |
|------|-----------|--------|
| `standalone` | Binds a minimal HTTP server on port 80 | `HTTP_CHALLENGE_MODE=standalone` |
| `webroot` | Writes token file into an existing webroot | `HTTP_CHALLENGE_MODE=webroot` + `WEBROOT_PATH` |

### DNS-01 (RFC 8555 §8.4)

TXT record name: `_acme-challenge.{domain}`
TXT record value: `base64url(SHA-256(key_authorization))`

| Provider | Library | Config |
|----------|---------|--------|
| Cloudflare | `cloudflare>=3.0` | `DNS_PROVIDER=cloudflare` + `CLOUDFLARE_API_TOKEN` |
| AWS Route53 | `boto3>=1.34` | `DNS_PROVIDER=route53` + AWS credentials |
| Google Cloud DNS | `google-cloud-dns>=0.34` | `DNS_PROVIDER=google` + `GOOGLE_PROJECT_ID` + credentials |

DNS provider operations (create/delete) are idempotent — safe to retry.

### TLS-ALPN-01

Not implemented. Out of scope.

---

## CA Providers

| Provider | Directory URL | EAB |
|----------|---------------|-----|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | No |
| `letsencrypt_staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | No |
| `digicert` | `https://acme.digicert.com/v2/DV/directory` | Yes |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` | Yes |
| `sectigo` | `https://acme.sectigo.com/v2/DV` | Yes |
| `custom` | `ACME_DIRECTORY_URL` (any RFC 8555 server) | Optional |

---

## Cryptography

| Artifact | Algorithm | Notes |
|----------|-----------|-------|
| Account key | RSA (PKCS8 PEM) | Generated once; stored at `ACCOUNT_KEY_PATH` |
| Domain key | RSA-2048 | Generated per domain; configurable key size |
| JWS signing | RS256 | Used for all ACME POST requests |
| EAB HMAC | HS256 | Outer JWS for EAB-required CAs |
| JWK thumbprint | SHA-256 | Per RFC 7638 §3.2 |
| DNS-01 TXT value | SHA-256 + base64url | Per RFC 8555 §8.4 |
| CSR encoding | DER | Sent to `/finalize`; stored as hex in `AgentState` |
| Certificate storage | PEM | Full chain written atomically |

---

## Storage Safety

All certificate and key file writes go through `storage/atomic.py`:

1. Write to a sibling temp file
2. `fsync` the temp file descriptor
3. `os.replace()` — atomic on POSIX

This guarantees no partial writes are ever visible, even on power loss mid-write.

---

## Explicit Out-of-Scope Items

| Feature | Reason |
|---------|--------|
| TLS-ALPN-01 challenge | Not required by target CAs; would need TLS stack integration |
| Wildcard certificates (`*.example.com`) | DNS-01 is required; automation is provider-specific; domains must be listed explicitly |
| Pre-authorization | ACME extension, not in RFC 8555 core |
| Parallel domain processing | Incompatible with shared `current_nonce` in `AgentState`; sequential processing is a permanent invariant |
| Batch revocation | No RFC 8555 standard for it |
| Root + subdomain in a single SAN cert via HTTP-01 | HTTP-01 requires a separate challenge per name; use DNS-01 or issue separate certs |
| Certificate issuance via OV/EV profiles | Only DV (domain-validated) certificate workflows are implemented |

---

## Key Source Files

| File | Protocol responsibility |
|------|------------------------|
| `acme/client.py` | RFC 8555 full flow + RFC 8739 EAB + revocation |
| `acme/jws.py` | JWS signing, EAB outer JWS, RFC 7638 thumbprint |
| `acme/crypto.py` | RSA key generation + CSR construction |
| `acme/http_challenge.py` | HTTP-01 standalone server + webroot writer |
| `acme/dns_challenge.py` | DNS-01 TXT value computation + provider adapters |
| `agent/state.py` | `AcmeOrder` shape; RFC 5280 reason code enum |
| `agent/nodes/challenge.py` | Challenge setup/teardown; reusable auth check |
| `agent/nodes/revoker.py` | `POST /revokeCert` node |
| `storage/atomic.py` | Atomic file writes |
