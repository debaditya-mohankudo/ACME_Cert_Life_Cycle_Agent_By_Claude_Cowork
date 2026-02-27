# Wiki Quick Fixes — Actionable In One Session

**Goal**: 3 hours of focused work → 30% improvement in discoverability

**Status**: Ready to implement
**Estimated Effort**: 2–3 hours (can be done in multiple 30-min sessions)

---

## Fix 1: Populate WIKI_OPERATIONS.md — Domain-Specific Features (30 min) 🔴 CRITICAL

### Current state:
```markdown
## Domain-specific Features


## Retrieval keywords
```

### Action:
Replace empty section with:

```markdown
## Domain-Specific Features

### Challenge Modes

- **HTTP-01 (Standalone)** — Built-in HTTP server on port 80
  - Setup: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
  - Config: `HTTP_CHALLENGE_MODE=standalone`
  - Short intro: [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md)

- **HTTP-01 (Webroot)** — Serve tokens from existing web server
  - Setup: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
  - Config: `HTTP_CHALLENGE_MODE=webroot` + `WEBROOT_PATH=/path/to/webroot`
  - Internals: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)

- **DNS-01 (DNS CNAME)** — Cloudflare, Route53, Google Cloud DNS
  - Setup: [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md)
  - Supported providers: Cloudflare (`DNS_PROVIDER=cloudflare`), Route53 (`dns-route53`), Google Cloud DNS (`dns-google`)
  - Config: `HTTP_CHALLENGE_MODE=dns` + provider-specific env vars

### Revocation

- **Certificate Revocation** — On-demand revocation via CLI
  - Implementation: [REVOCATION_IMPLEMENTATION.md](REVOCATION_IMPLEMENTATION.md)
  - Usage: `python main.py --revoke-cert domain1.com domain2.com --reason 4`
  - Reason codes: 0=unspecified, 1=keyCompromise, 4=superseded, 5=cessation (see [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md))

### CA Providers

- Complete list with setup: [CA_PROVIDERS.md](CA_PROVIDERS.md) (if created via Fix 3)
- Let's Encrypt: [LETS_ENCRYPT.md](LETS_ENCRYPT.md)
- Others: Configured in [acme/client.py](../acme/client.py) class hierarchy

### Advanced Features

- Model Inference via MCP: [MCP_SERVER.md](MCP_SERVER.md)
```

**Time**: 15 min

---

## Fix 2: Add Retrieval Hints to SECURITY.md (20 min) 🔴 CRITICAL

### Current state:
Document starts with "# Security Design and Controls" with no retrieval hints.

### Action:
Add after title, before "## See also":

```markdown
## When to use this page

- "Is this system secure?"
- "What are the security controls?"
- "How are keys protected?"
- "What about certificate storage safety?"

## Canonicality

- **Canonical for**: Security design, key isolation, atomic writes, LLM validation, audit trail
- **Not canonical for**: RFC compliance details (→ [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)), test coverage (→ [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md)), configuration (→ [CONFIGURATION.md](CONFIGURATION.md))

## Retrieval keywords

`security`, `key isolation`, `atomic writes`, `private key`, `account key`, `LLM validation`, `checkpoint safety`, `audit trail`, `encryption`, `file permissions`

[negative keywords / not-this-doc]
configuration, performance, throughput, scheduling, async, testing, CI, MCP, DNS, HTTP, challenge, ACME, protocol, RFC, nonce, LangGraph, concurrency, parallel
```

**Time**: 10 min

---

## Fix 3: Create Minimal FEATURE_MATRIX.md (45 min) 🟡 HIGH

### Action:
Create new file `doc/FEATURE_MATRIX.md`:

```markdown
# Feature Matrix — Availability & Status

| Feature | Status | Quick Setup | Config Env Var | Test Coverage | Notes |
|---------|--------|-------------|---|---|---|
| HTTP-01 (Standalone) | ✅ Production | [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) | `HTTP_CHALLENGE_MODE=standalone` | ✅ Full (test_http_01) | Built-in server on port 80 |
| HTTP-01 (Webroot) | ✅ Production | [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md) | `HTTP_CHALLENGE_MODE=webroot` | ✅ Full | Requires existing web server |
| DNS-01 (Cloudflare) | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=cloudflare` | ✅ Full | Via `dns-cloudflare` package |
| DNS-01 (Route53) | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=route53` | ✅ Full | Requires AWS credentials |
| DNS-01 (Google Cloud DNS) | ✅ Production | [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) | `HTTP_CHALLENGE_MODE=dns` + `DNS_PROVIDER=google` | ✅ Full | Requires GCP credentials |
| Certificate Revocation | ✅ Production | [REVOCATION_IMPLEMENTATION.md](REVOCATION_IMPLEMENTATION.md) | CLI: `--revoke-cert` | ✅ Full | On-demand via CLI |
| CA: Let's Encrypt | ✅ Production | [LETS_ENCRYPT.md](LETS_ENCRYPT.md) | `CA_PROVIDER=letsencrypt` | ✅ Full | Free, trusted |
| CA: Let's Encrypt Staging | ✅ Production | [LETS_ENCRYPT.md](LETS_ENCRYPT.md) | `CA_PROVIDER=letsencrypt_staging` | ✅ Full | For testing |
| CA: DigiCert (EAB) | ✅ Production | [acme/client.py](../acme/client.py) | `CA_PROVIDER=digicert` + EAB env vars | ✅ Full | Requires API credentials |
| CA: ZeroSSL (EAB) | ✅ Production | [acme/client.py](../acme/client.py) | `CA_PROVIDER=zerossl` + EAB env vars | ✅ Full | Requires API credentials |
| CA: Sectigo (EAB) | ✅ Production | [acme/client.py](../acme/client.py) | `CA_PROVIDER=sectigo` + EAB env vars | ✅ Full | Requires API credentials |
| CA: Custom ACME | ✅ Production | [CONFIGURATION.md](CONFIGURATION.md) | `CA_PROVIDER=custom` + `ACME_DIRECTORY_URL` | ⚠️ Limited | For non-standard CAs |
| Checkpoint/Resume | ✅ Production | [CHECKPOINT_TESTS.md](CHECKPOINT_TESTS.md) | `--checkpoint` flag | ✅ Full | Via LangGraph MemorySaver |
| Scheduled Renewal | ✅ Production | [USAGE.md](USAGE.md) | `python main.py --schedule` | ✅ Full | Daily loop, configurable interval |
| Docker Runtime | ✅ Production | [DOCKER.md](DOCKER.md) | See docker-compose | ✅ Full | Hardened non-root image available |
| MCP Server Mode | ✅ Production | [MCP_SERVER.md](MCP_SERVER.md) | See MCP config | ✅ Full | LLM-callable tools |
| Per-Run Logging (UUID) | 🔶 Proposed | [LOGGER_IMPLEMENTATION_PLAN.md](LOGGER_IMPLEMENTATION_PLAN.md) | Not yet implemented | ❌ None | See implementation plan |

## Legend

- ✅ = Implemented, fully tested, documented
- 🔶 = Proposed or partially implemented
- ⚠️ = Implemented but limited scope or testing
- ❌ = Not tested or incomplete documentation

## See also

- Setup: [SETUP.md](SETUP.md)
- Usage: [USAGE.md](USAGE.md)
- Configuration: [CONFIGURATION.md](CONFIGURATION.md)
- Test coverage: [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md)
```

**Time**: 30 min

---

## Fix 4: Create Minimal CA_PROVIDERS.md (30 min) 🟡 HIGH

### Action:
Create new file `doc/CA_PROVIDERS.md`:

```markdown
# CA Providers — Selection and Setup

Use this page to choose and configure your ACME Certificate Authority.

## Quick Selection

| CA | Requires EAB | Cost | Use When | Config |
|---|---|---|---|---|
| **Let's Encrypt** | No | Free | Public internet, free certificates | `CA_PROVIDER=letsencrypt` |
| **Let's Encrypt Staging** | No | Free | Testing (doesn't count against rate limits) | `CA_PROVIDER=letsencrypt_staging` |
| **DigiCert** | Yes | Paid | Enterprise, high-trust certs | `CA_PROVIDER=digicert` |
| **ZeroSSL** | Yes | Mixed | Alternative EAB provider | `CA_PROVIDER=zerossl` |
| **Sectigo** | Yes | Paid | Legacy/compatibility | `CA_PROVIDER=sectigo` |
| **Custom** | Varies | Varies | Non-standard ACME endpoints | `CA_PROVIDER=custom` + `ACME_DIRECTORY_URL` |

## Detailed Setup

### Let's Encrypt

- **Endpoint**: `https://acme-v02.api.letsencrypt.org/directory` (production)
- **Rate Limits**: 50 certs/domain/week (generous)
- **Setup**: [LETS_ENCRYPT.md](LETS_ENCRYPT.md)
- **No API credentials needed** — registration happens via email

### Let's Encrypt Staging

- **Endpoint**: `https://acme-staging-v02.api.letsencrypt.org/directory`
- **Use for**: Testing before production
- **Certs not trusted** but test rate limits are much higher
- **Setup**: Same as production, just change `CA_PROVIDER`

### DigiCert (EAB)

- **Endpoint**: `https://acme.digicert.com/v2/DV/directory`
- **Requires**: EAB Key ID + HMAC Key (from DigiCert portal)
- **Config**:
  ```
  CA_PROVIDER=digicert
  ACME_EAB_KEY_ID=your_key_id
  ACME_EAB_HMAC_KEY=your_hmac_key
  ```
- **Cost**: Contact DigiCert for pricing

### ZeroSSL (EAB)

- **Endpoint**: `https://acme.zerossl.com/v2/DV90/directory`
- **Requires**: EAB Key ID + HMAC Key (from ZeroSSL account)
- **Config**:
  ```
  CA_PROVIDER=zerossl
  ACME_EAB_KEY_ID=your_key_id
  ACME_EAB_HMAC_KEY=your_hmac_key
  ```
- **Cost**: Free tier available

### Sectigo (EAB)

- **Endpoint**: `https://acme.sectigo.com/v2/DV/directory`
- **Requires**: EAB Key ID + HMAC Key (from Sectigo account)
- **Config**:
  ```
  CA_PROVIDER=sectigo
  ACME_EAB_KEY_ID=your_key_id
  ACME_EAB_HMAC_KEY=your_hmac_key
  ```

### Custom ACME Endpoint

- **Use when**: Your CA is not in the list above
- **Config**:
  ```
  CA_PROVIDER=custom
  ACME_DIRECTORY_URL=https://your-ca.example.com/acme/directory
  ```
- **CA Detection**: The agent will attempt to detect which CA issued existing certs and warn if there's a mismatch
- **See**: [acme/ca_detection.py](../acme/ca_detection.py)

## Switching CAs

- Simply change `CA_PROVIDER` and restart
- Existing certificates from the old CA are not affected
- New renewals use the new CA

## See also

- Configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- RFC compliance: [RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)
- Setup guide: [SETUP.md](SETUP.md)
```

**Time**: 25 min

---

## Fix 5: Add Metadata & Status to DESIGN_PRINCIPLES.md (15 min) 🟡 HIGH

### Current state:
Document starts with title and "See also" but no metadata.

### Action:
Add at the end of document (before or after "Quick Reference"):

```markdown
## Metadata

- **Owner**: Architecture team
- **Status**: active (constitutional layer — no breaking changes without explicit justification)
- **Last reviewed**: 2026-02-27
- **Next review due**: 2026-05-27 (quarterly)
```

**Time**: 5 min per canonical source

**Do this for all canonical sources (8 total)**:
1. ✅ DESIGN_PRINCIPLES.md (above)
2. RFC_COMPLIANCE.md
3. SECURITY.md
4. CI_TEST_COVERAGE.md
5. CONFIGURATION.md
6. HOW_IT_WORKS.md
7. CERTIFICATE_STORAGE.md
8. PROJECT_STRUCTURE.md

**Total time**: 15 min (batch edit)

---

## Fix 6: Add "See Also" Back-Links (20 min) 🟡 MEDIUM

### Current state:
Some docs are one-way links.

### Action:
1. Open `HTTP_CHALLENGE_CONFIGURATION.md`
2. Verify it has a "See also" linking to `HTTP_CHALLENGE_MODES.md`
3. If missing, add:
   ```markdown
   ## See also

   - Quick intro: [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md)
   - Validation internals: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)
   - Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
   ```

4. Do the same for:
   - DNS_01_IMPLEMENTATION_PLAN.md (add to WIKI_OPERATIONS)
   - REVOCATION_IMPLEMENTATION.md (ensure bidirectional with related docs)

**Time**: 15 min

---

## Fix 7: Mark ACME_AGENT_PLAN.md Status Clearly (5 min) ✅ DONE

### Current state:
Already has disclaimer at top:
```markdown
> **Note:** This is the original design specification written before implementation...
```

### Verify status is:
```markdown
## Metadata

- **Status**: historical (superseded by [HOW_IT_WORKS.md](HOW_IT_WORKS.md))
- **Use for**: Historical context only; refers to pre-implementation design
- **Current source**: [HOW_IT_WORKS.md](HOW_IT_WORKS.md) + [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
```

**Already done.** ✅ No action needed.

**Time**: 0 min

---

## Summary: Time Breakdown

| Fix | Priority | Effort | Impact | Status |
|-----|----------|--------|--------|--------|
| Fix 1: WIKI_OPERATIONS domain features | 🔴 CRITICAL | 15 min | High | Ready |
| Fix 2: SECURITY.md retrieval hints | 🔴 CRITICAL | 10 min | High | Ready |
| Fix 3: FEATURE_MATRIX.md | 🟡 HIGH | 30 min | High | Ready |
| Fix 4: CA_PROVIDERS.md | 🟡 HIGH | 25 min | Medium | Ready |
| Fix 5: Metadata on canonical sources | 🟡 MEDIUM | 15 min | Low | Ready |
| Fix 6: Back-links (DNS, Revocation) | 🟡 MEDIUM | 15 min | Medium | Ready |
| Fix 7: Status on ACME_AGENT_PLAN.md | ✅ DONE | 0 min | Low | Done |
| **Total** | — | **110 min** (1.8 hours) | — | — |

---

## Recommended Session Plan

### Session 1 (45 min) — Critical Fixes
1. Fix 1: WIKI_OPERATIONS domain features (15 min)
2. Fix 2: SECURITY.md retrieval hints (10 min)
3. Fix 5: Add metadata to 2–3 canonical sources (20 min)

**Result**: WIKI_OPERATIONS is now useful hub; SECURITY is discoverable

### Session 2 (60 min) — Feature Documentation
1. Fix 3: FEATURE_MATRIX.md (30 min)
2. Fix 4: CA_PROVIDERS.md (25 min)
3. Fix 6: DNS-01 and Revocation back-links (5 min)

**Result**: Feature discoverability + CA setup clarity

### Session 3 (15 min) — Completion
1. Fix 5: Add metadata to remaining 5–6 canonical sources (15 min)
2. Commit: "docs: wiki structural improvements — features, matrix, CA setup"

---

## Files to Create/Edit

```
NEW:  doc/FEATURE_MATRIX.md
NEW:  doc/CA_PROVIDERS.md

EDIT: doc/WIKI_OPERATIONS.md          (populate "Domain-specific Features")
EDIT: doc/SECURITY.md                 (add retrieval hints + metadata)
EDIT: doc/RFC_COMPLIANCE.md           (add metadata)
EDIT: doc/CI_TEST_COVERAGE.md         (add metadata)
EDIT: doc/CONFIGURATION.md            (add metadata)
EDIT: doc/HOW_IT_WORKS.md             (add metadata)
EDIT: doc/CERTIFICATE_STORAGE.md      (add metadata)
EDIT: doc/PROJECT_STRUCTURE.md        (add metadata)
EDIT: doc/DNS_01_IMPLEMENTATION_PLAN.md (add "See also" back-link to WIKI_OPERATIONS)
EDIT: doc/REVOCATION_IMPLEMENTATION.md (verify "See also" back-links)
EDIT: doc/HTTP_CHALLENGE_CONFIGURATION.md (verify bidirectional link)
```

---

## Validation Checklist

After completing all fixes:

- [ ] WIKI_OPERATIONS.md has populated "Domain-specific Features" section
- [ ] FEATURE_MATRIX.md exists and is linked from WIKI_OPERATIONS
- [ ] CA_PROVIDERS.md exists and is linked from WIKI_OPERATIONS
- [ ] SECURITY.md has retrieval keywords + metadata
- [ ] RFC_COMPLIANCE.md has metadata
- [ ] CI_TEST_COVERAGE.md has metadata
- [ ] All 8 canonical sources have metadata (status, owner, review dates)
- [ ] HTTP-01 docs link bidirectionally
- [ ] DNS-01 doc is linked from WIKI_OPERATIONS
- [ ] Revocation doc is linked from WIKI_OPERATIONS
- [ ] No dead links in doc/ directory

---

## See also

- Full analysis: [WIKI_STRUCTURAL_ANALYSIS.md](WIKI_STRUCTURAL_ANALYSIS.md)
- Navigation map: [WIKI_NAVIGATION_MAP.md](WIKI_NAVIGATION_MAP.md)
- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Template guide: [WIKI_TEMPLATE.md](WIKI_TEMPLATE.md)
