# DNS-01 Challenge Support — Implementation Plan

## See also

- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- HTTP-01 configuration: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)

## Context

The agent currently supports HTTP-01 challenges only (standalone HTTP server and webroot modes). DNS-01 is required for:
- Domains where port 80 is firewalled or unreachable
- Internal/private domains with no public HTTP endpoint
- Wildcard certificates (`*.example.com`) — HTTP-01 cannot validate these; DNS-01 can

This plan adds DNS-01 via **Cloudflare**, **AWS Route53**, and **Google Cloud DNS** — the three most widely adopted DNS providers in ACME/DevOps deployments.

**No graph topology changes.** DNS-01 uses the same nodes as HTTP-01 (`challenge_setup`, `challenge_verifier`, `_cleanup_challenge`). `challenge_verifier` is byte-for-byte identical for both modes — `respond_to_challenge()` and `poll_authorization()` are ACME protocol operations that don't care about the challenge type.

---

## DNS-01 Protocol (RFC 8555 §8.4)

```
1. Create ACME order → ACME server returns authorization with dns-01 challenge
2. Extract: token, challenge URL
3. key_authorization = "{token}.{jwk_thumbprint}"  ← same as HTTP-01
4. DNS TXT record name:  _acme-challenge.{domain}
5. DNS TXT record value: base64url(SHA-256(key_authorization.encode()))  ← differs from HTTP-01
6. Create TXT record via DNS provider API
7. Wait for DNS propagation (DNS_PROPAGATION_WAIT_SECONDS, default 60s)
8. POST to challenge URL (same respond_to_challenge() as HTTP-01)
9. ACME server queries _acme-challenge.{domain}, validates TXT value
10. Poll authorization until valid/invalid (same poll_authorization() as HTTP-01)
11. Delete TXT record (cleanup)
```

---

## Implementation Steps (dependency order)

### Step 1 — `agent/state.py` — Add 2 fields to `AcmeOrder`

```python
class AcmeOrder(TypedDict):
    order_url: str
    status: str
    auth_urls: List[str]
    auth_domains: List[str]         # NEW — domain per authorization (e.g. "api.example.com")
    challenge_urls: List[str]
    challenge_tokens: List[str]
    key_authorizations: List[str]
    dns_txt_values: List[str]       # NEW — base64url(SHA-256(key_auth)) per domain; [] for HTTP-01
    finalize_url: str
    certificate_url: Optional[str]
    csr_der_hex: str
```

**Why `auth_domains`:** `challenge_setup` needs to know the domain per authorization to construct `_acme-challenge.{domain}`. The authorization URL is opaque. The domain lives in the authorization body (`authz["identifier"]["value"]`) already fetched by `order_initializer`. Storing it avoids a hidden second `get_authorization()` network call in `challenge_setup`, which would violate Design Principle 10.

**Why `dns_txt_values`:** Pre-computed in `order_initializer` (alongside all other challenge data) rather than in `challenge_setup`. Design Principle 9 says `challenge_setup` should not contain ACME protocol knowledge — the TXT value formula is RFC 8555 protocol, not DNS infrastructure.

---

### Step 2 — `config.py` — New settings

**Extend `HTTP_CHALLENGE_MODE` validator:**
```python
# Before: {"standalone", "webroot"}
# After:  {"standalone", "webroot", "dns"}
```

**New fields:**
```python
# ── DNS-01 Challenge ──────────────────────────────────────────────────
DNS_PROVIDER: Literal["cloudflare", "route53", "google"] = "cloudflare"
DNS_PROPAGATION_WAIT_SECONDS: int = 60   # seconds to wait after TXT record creation

# Cloudflare
CLOUDFLARE_API_TOKEN: str = ""
CLOUDFLARE_ZONE_ID: str = ""             # optional; auto-discovered from domain if empty

# AWS Route53
AWS_ACCESS_KEY_ID: str = ""
AWS_SECRET_ACCESS_KEY: str = ""
AWS_REGION: str = "us-east-1"
AWS_ROUTE53_HOSTED_ZONE_ID: str = ""     # optional; auto-discovered if empty

# Google Cloud DNS
GOOGLE_PROJECT_ID: str = ""
GOOGLE_APPLICATION_CREDENTIALS: str = "" # path to service account JSON; or use env var
GOOGLE_CLOUD_DNS_ZONE_NAME: str = ""     # GCP managed zone name (not the DNS zone name)
```

**New model_validator `validate_dns_config`:**
- `HTTP_CHALLENGE_MODE == "dns"` → `DNS_PROVIDER` must be set
- `DNS_PROVIDER == "cloudflare"` → `CLOUDFLARE_API_TOKEN` required
- `DNS_PROVIDER == "google"` → `GOOGLE_PROJECT_ID` required
- `DNS_PROVIDER == "route53"` → no mandatory fields (boto3 uses credential chain / instance role)

---

### Step 3 — `acme/dns_challenge.py` (new file)

Follows the same structural pattern as `acme/http_challenge.py`. Factory function mirrors `make_client()` in `acme/client.py`.

#### Helper function
```python
def compute_dns_txt_value(key_authorization: str) -> str:
    """
    RFC 8555 §8.4 — compute the DNS TXT record value for a DNS-01 challenge.
    digest = SHA-256(key_authorization.encode('utf-8'))
    txt_value = base64url(digest)  [no padding]
    Differs from HTTP-01 which uses key_authorization directly.
    """
    digest = hashlib.sha256(key_authorization.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
```

#### Abstract base class
```python
class DnsProvider(abc.ABC):
    @abc.abstractmethod
    def create_txt_record(self, domain: str, txt_value: str) -> None:
        """Create TXT at _acme-challenge.{domain}. Must be idempotent."""

    @abc.abstractmethod
    def delete_txt_record(self, domain: str, txt_value: str) -> None:
        """Delete TXT at _acme-challenge.{domain}. Best-effort; must not raise."""
```

#### `CloudflareDnsProvider`
- **Package:** `cloudflare>=3.0`
- **Auth:** `CLOUDFLARE_API_TOKEN` (scoped: Zone:DNS:Edit)
- **Zone:** `CLOUDFLARE_ZONE_ID` or auto-discovered via `cf.zones.list(name=candidate)`
- `create_txt_record` — checks for duplicate before creating (idempotent)
- `delete_txt_record` — finds record by name+content, deletes; swallows all errors

#### `Route53DnsProvider`
- **Package:** `boto3>=1.34`
- **Auth:** `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` OR boto3 credential chain (instance role, env vars, `~/.aws/credentials`)
- **Zone:** `AWS_ROUTE53_HOSTED_ZONE_ID` or auto-discovered via `list_hosted_zones_by_name()`
- `create_txt_record` — uses `UPSERT` action (idempotent); wraps TXT value in `"..."` (Route53 convention)
- `delete_txt_record` — uses `DELETE` action; swallows all errors

#### `GoogleCloudDnsProvider`
- **Package:** `google-cloud-dns>=3.0`
- **Auth:** `GOOGLE_APPLICATION_CREDENTIALS` path OR `GOOGLE_APPLICATION_CREDENTIALS` env var OR Application Default Credentials
- **Zone:** `GOOGLE_CLOUD_DNS_ZONE_NAME` (GCP managed zone name, not DNS zone name)
- `create_txt_record` — `resource_record_set()` + `changes.add_record_set()` + `changes.create()`
- `delete_txt_record` — `delete_record_set()` + `changes.create()`; swallows all errors

#### Factory function
```python
def make_dns_provider() -> DnsProvider:
    from config import settings  # late import — mirrors make_client() pattern
    if settings.DNS_PROVIDER == "cloudflare":
        return CloudflareDnsProvider(api_token=settings.CLOUDFLARE_API_TOKEN, zone_id=settings.CLOUDFLARE_ZONE_ID)
    if settings.DNS_PROVIDER == "route53":
        return Route53DnsProvider(hosted_zone_id=settings.AWS_ROUTE53_HOSTED_ZONE_ID, ...)
    if settings.DNS_PROVIDER == "google":
        return GoogleCloudDnsProvider(project_id=settings.GOOGLE_PROJECT_ID, ...)
    raise ValueError(f"Unsupported DNS_PROVIDER: {settings.DNS_PROVIDER}")
```

---

### Step 4 — `agent/nodes/order.py` — Mode-aware challenge type

```python
from config import settings
from acme.dns_challenge import compute_dns_txt_value

# Replace hardcoded "http-01":
challenge_type = "dns-01" if settings.HTTP_CHALLENGE_MODE == "dns" else "http-01"
challenge_obj = next((c for c in challenges if c["type"] == challenge_type), None)

# In per-authorization loop, add:
auth_domains.append(authz["identifier"]["value"])
if settings.HTTP_CHALLENGE_MODE == "dns":
    dns_txt_values.append(compute_dns_txt_value(key_auth))

# In current_order dict, add:
"auth_domains": auth_domains,
"dns_txt_values": dns_txt_values,
```

---

### Step 5 — `agent/nodes/challenge.py` — DNS-01 branches

**Module-level state** (mirrors `_standalone_server` pattern):
```python
_dns_provider: DnsProvider | None = None
```

**`challenge_setup()` DNS branch:**
```python
elif mode == "dns":
    global _dns_provider
    _dns_provider = make_dns_provider()
    for domain, txt_value in zip(order["auth_domains"], order["dns_txt_values"]):
        _dns_provider.create_txt_record(domain, txt_value)
        logger.info("Created DNS TXT record: _acme-challenge.%s", domain)
    wait = settings.DNS_PROPAGATION_WAIT_SECONDS
    if wait > 0:
        logger.info("Waiting %d seconds for DNS propagation...", wait)
        time.sleep(wait)
    # returns {} — same as other modes
```

**`_cleanup_challenge()` DNS branch:**
```python
elif settings.HTTP_CHALLENGE_MODE == "dns" and _dns_provider is not None:
    for domain, txt_value in zip(order.get("auth_domains", []), order.get("dns_txt_values", [])):
        try:
            _dns_provider.delete_txt_record(domain, txt_value)
            logger.info("Deleted DNS TXT record for %s", domain)
        except Exception as exc:
            logger.warning("Failed to delete TXT record for %s: %s", domain, exc)
    _dns_provider = None
```

**`challenge_verifier()` — unchanged.** The existing `respond_to_challenge()` + `poll_authorization()` calls are protocol-agnostic. The standalone server rotation condition (`if mode == "standalone" and i > 0`) is already a no-op when `mode == "dns"`.

---

### Step 6 — `pyproject.toml` — Optional dependencies

```toml
[project.optional-dependencies]
dns-cloudflare = ["cloudflare>=3.0"]
dns-route53    = ["boto3>=1.34"]
dns-google     = ["google-cloud-dns>=3.0"]
dns-all        = ["cloudflare>=3.0", "boto3>=1.34", "google-cloud-dns>=3.0"]
```

Install only what you need:
```bash
uv add cloudflare          # Cloudflare
uv add boto3               # Route53
uv add google-cloud-dns    # Google Cloud DNS
```

---

### Step 7 — Tests

#### `tests/test_dns_challenge.py` (new file)

All DNS provider calls mocked via `unittest.mock.MagicMock` — no real DNS credentials needed.

| Group | Tests |
|-------|-------|
| `compute_dns_txt_value()` | SHA-256 correctness, known vector, determinism, differs from HTTP-01 value |
| `make_dns_provider()` factory | Dispatch for all 3 providers; `ImportError` with install hint when library missing |
| `CloudflareDnsProvider` | Create with explicit zone; create with auto-discovery; create idempotent (no duplicate); delete; error swallowed |
| `Route53DnsProvider` | Create UPSERT with `""` wrapping; zone auto-discovery; delete DELETE; error swallowed |
| `GoogleCloudDnsProvider` | Create chain; delete chain; error swallowed |
| `order_initializer` DNS mode | dns-01 challenge selected; `dns_txt_values` correct; `auth_domains` populated; error on missing dns-01 |
| `challenge_setup` DNS branch | `create_txt_record` called for all domains; propagation sleep called; sleep skipped when 0 |
| `_cleanup_challenge` DNS branch | Delete called for all domains; loop continues on partial failure; safe when `_dns_provider` is None |
| Config validation | `"dns"` accepted; missing token caught; missing project ID caught; standalone/webroot unchanged |

#### `tests/test_integration_pebble.py` — Add DNS-01 integration test

Pebble with `PEBBLE_VA_ALWAYS_VALID=1` auto-approves `dns-01` without checking real DNS.

```python
def test_full_renewal_flow_dns01(pebble_settings, mock_llm_nodes):
    # Patch challenge mode and mock DNS provider
    settings.HTTP_CHALLENGE_MODE = "dns"
    settings.DNS_PROVIDER = "cloudflare"
    settings.DNS_PROPAGATION_WAIT_SECONDS = 0  # no sleep in tests

    mock_provider = MagicMock()
    with patch("agent.nodes.challenge.make_dns_provider", return_value=mock_provider):
        graph = build_graph()
        state = initial_state(...)
        final = graph.invoke(state)

    assert "acme-test.localhost" in final["completed_renewals"]
    mock_provider.create_txt_record.assert_called_once()
    mock_provider.delete_txt_record.assert_called_once()
    assert (Path(settings.CERT_STORE_PATH) / "acme-test.localhost" / "cert.pem").exists()
```

Add `dns_settings` fixture to `conftest.py` (extends `pebble_settings` with DNS-01 overrides; restores on teardown).

---

## Files Modified / Created

| File | Action | Summary |
|------|--------|---------|
| `agent/state.py` | Modify | Add `auth_domains: List[str]`, `dns_txt_values: List[str]` to `AcmeOrder` |
| `config.py` | Modify | Extend `HTTP_CHALLENGE_MODE` validator; 10 new DNS settings; `validate_dns_config` |
| `acme/dns_challenge.py` | **Create** | `compute_dns_txt_value`, `DnsProvider` ABC, 3 providers, `make_dns_provider` |
| `agent/nodes/order.py` | Modify | Mode-aware challenge type; populate `auth_domains`, `dns_txt_values` |
| `agent/nodes/challenge.py` | Modify | DNS-01 branches in `challenge_setup`, `_cleanup_challenge`; `_dns_provider` module var |
| `pyproject.toml` | Modify | Optional DNS dependency groups |
| `tests/test_dns_challenge.py` | **Create** | Full unit test suite (~35 tests) |
| `tests/conftest.py` | Modify | `dns_settings` fixture |
| `tests/test_integration_pebble.py` | Modify | `test_full_renewal_flow_dns01` |
| `doc/DNS_CHALLENGE_MODES.md` | **Create** | DNS-01 user guide: flow, credentials per provider, zone discovery, propagation tuning |
| `doc/DESIGN_PRINCIPLES.md` | Modify | DNS provider factory note under Principle 9 |
| `doc/CONFIGURATION.md` | Modify | DNS-01 config section |
| `CLAUDE.md` | Modify | `HTTP_CHALLENGE_MODE` valid values, project structure |
| `README.md` | Modify | DNS-01 in feature list and documentation table |

**Unchanged:** `agent/graph.py` (no topology change), `acme/client.py`, `acme/jws.py`, `acme/crypto.py`, `challenge_verifier` body

---

## Invariant Compliance

| CLAUDE.md Invariant | How satisfied |
|---|---|
| Account key never in state | No change — challenge nodes don't touch account key |
| One POST → one nonce | No change — DNS provider calls are not ACME POSTs |
| Every network call = named node | DNS API calls in `challenge_setup` node (same pattern as HTTP server start) |
| No concurrent ACME | Sequential per-domain loop unchanged |
| Retry only in error_handler | No retry in DNS challenge — failures propagate to `error_handler` |
| Topology change → DESIGN_PRINCIPLES.md | No topology change; doc updated for factory pattern |

---

## Verification

```bash
# 1. Unit tests only (no DNS credentials, no Pebble)
pytest tests/test_dns_challenge.py -v

# 2. Full suite — confirm zero regressions (runs in parallel with xdist)
pytest -v -n auto -m "not integration"

# 3. Pebble integration (Pebble running, DNS provider mocked)
docker compose -f docker-compose.pebble.yml up -d
pytest tests/test_integration_pebble.py::test_full_renewal_flow_dns01 -v

# 4. Manual smoke test with real DNS provider
export HTTP_CHALLENGE_MODE=dns
export DNS_PROVIDER=cloudflare
export CLOUDFLARE_API_TOKEN=<your-token>
export MANAGED_DOMAINS=api.example.com
python main.py --once
```

---

## Related Documentation

- [`doc/HTTP_CHALLENGE_MODES.md`](HTTP_CHALLENGE_MODES.md) — HTTP-01 standalone/webroot modes
- [`doc/HTTP_01_VALIDATION_EXPLAINED.md`](HTTP_01_VALIDATION_EXPLAINED.md) — How HTTP-01 security works
- [`doc/CONFIGURATION.md`](CONFIGURATION.md) — Full configuration reference
- [`doc/DESIGN_PRINCIPLES.md`](DESIGN_PRINCIPLES.md) — Architectural invariants
