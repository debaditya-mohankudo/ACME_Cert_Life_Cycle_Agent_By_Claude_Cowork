# Wiki Structure Analysis & Improvement Recommendations

**Status**: Strategic assessment of doc/directory organization
**Last Updated**: 2026-02-27

---

## Executive Summary

Your wiki uses a **hub-based navigation model** with three main entry points (WIKI_HOME + 3 hubs) and a clear constitutional layer (DESIGN_PRINCIPLES). **Strengths:** clear intent-based routing, canonical source designation, retrieval hints. **Gaps:** inconsistent template adherence, document size variance, some cross-linking friction, and incomplete integration of newer features (DNS-01, revocation).

**Recommendation**: Implement a **three-phase refactor** with high ROI and low disruption:
1. **Phase 1 (Low effort)**: Template compliance + consistent "See also" structure
2. **Phase 2 (Medium effort)**: Domain-specific sub-hubs + feature integration
3. **Phase 3 (Optional future)**: Dependency graph visualization + automated health checks

---

## Current State Assessment

### Hub Architecture (Excellent)

| Hub | Entry Points | Scope | Status |
|-----|--------------|-------|--------|
| **WIKI_HOME.md** | routing table + canonical sources | Decision tree for agent use | ✅ Strong |
| **WIKI_ARCHITECTURE.md** | design + constraints | Protocol, graph, invariants | ✅ Clear but incomplete |
| **WIKI_OPERATIONS.md** | setup + runtime | CLI, config, infra | ✅ Well-organized |
| **WIKI_SECURITY_QUALITY.md** | security + testing | Posture, observability, quality | ✅ Well-structured |

**Verdict**: Hub model is sound and scalable.

---

## Problem Areas

### 1. **Template Adherence ⚠️ MEDIUM**

**Issue**: Not all docs follow the standard template. Inconsistent structure hampers discoverability.

**Example non-conformances**:
- No "When to use this page" section in RFC_COMPLIANCE.md, SECURITY.md, CI_TEST_COVERAGE.md
- Missing "Canonicality" statement in many docs
- No "Failure modes" sections in operational guides
- "Metadata" (owner, status, review date) missing from nearly all docs

**Impact**: New contributors may not know which doc is authoritative or when to use it.

**Recommendation**:
- **Phase 1**: Add template sections to the 8 canonical sources listed in WIKI_HOME (RFC_COMPLIANCE, SECURITY, CI_TEST_COVERAGE, CONFIGURATION, HOW_IT_WORKS, CERTIFICATE_STORAGE, PROJECT_STRUCTURE, DESIGN_PRINCIPLES).
- **Priority**: SECURITY.md, RFC_COMPLIANCE.md, CI_TEST_COVERAGE.md (highest user impact)
- **Effort**: 30 min per doc (1 doc/session)

---

### 2. **Inconsistent "See Also" Chains ⚠️ MEDIUM**

**Issue**: Related docs don't always link back to each other, creating one-way references.

**Examples**:
- DESIGN_PROTOCOL_PATTERN.md references DESIGN_PRINCIPLES, but reverse link is missing
- HTTP_CHALLENGE_MODES.md (short) and HTTP_CHALLENGE_CONFIGURATION.md (long) have inconsistent cross-references
- DNS_01_IMPLEMENTATION_PLAN.md is not mentioned in any hub
- REVOCATION_IMPLEMENTATION.md only linked from one hub

**Impact**: Users may miss related pages or see incomplete context.

**Recommendation**:
- Implement **bidirectional linking**: if A → B, ensure B → A (via "See also" section)
- Add a **quick link** strategy: keep short orientation docs (like HTTP_CHALLENGE_MODES.md) with a single "→ Detailed guide: [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)" line
- Ensure DNS-01 and revocation docs are explicitly mentioned in WIKI_OPERATIONS (under "Domain-specific Features" section, which currently exists but is empty)

---

### 3. **Missing "Domain-Specific Features" Sub-Hub ⚠️ HIGH**

**Issue**: WIKI_ARCHITECTURE.md has a section "## Domain-specific Features" that is **empty**. Similarly, WIKI_OPERATIONS.md lacks explicit organization of challenge/CA/feature variants.

**Current fragmentation**:
- HTTP-01: HTTP_CHALLENGE_MODES.md (short) + HTTP_CHALLENGE_CONFIGURATION.md (long) + HTTP_01_VALIDATION_EXPLAINED.md (deep dive)
- DNS-01: DNS_01_IMPLEMENTATION_PLAN.md (linked nowhere except memory)
- CAs: LETS_ENCRYPT.md (single CA doc, others embedded in CLIENT.md code)
- Revocation: REVOCATION_IMPLEMENTATION.md (buried in Operations hub)

**Impact**: Users looking for "how do I use DNS-01?" or "what are CA options?" must navigate three docs or grep the code.

**Recommendation**:
1. **Create FEATURE_MATRIX.md** — quick reference table:
   ```markdown
   | Feature | Status | Setup Doc | Config | Tests | Notes |
   |---------|--------|-----------|--------|-------|-------|
   | HTTP-01 (standalone) | ✅ | HTTP_CHALLENGE_CONFIGURATION.md | HTTP_CHALLENGE_MODE=standalone | ... | ... |
   | HTTP-01 (webroot) | ✅ | ... | ... | ... | ... |
   | DNS-01 (Cloudflare) | ✅ | DNS_01_IMPLEMENTATION_PLAN.md | ... | ... | ... |
   | DNS-01 (Route53) | ✅ | ... | ... | ... | ... |
   | Revocation | ✅ | REVOCATION_IMPLEMENTATION.md | ... | ... | ... |
   | CA: DigiCert | ✅ | ... | ... | ... | ... |
   | CA: Let's Encrypt | ✅ | LETS_ENCRYPT.md | ... | ... | ... |
   | MCP Mode | ✅ | MCP_SERVER.md | ... | ... | ... |
   ```

2. **Update WIKI_OPERATIONS.md** — replace empty "Domain-specific Features" with:
   ```markdown
   - Feature matrix: [FEATURE_MATRIX.md](FEATURE_MATRIX.md)
   - HTTP-01 challenges: [HTTP_CHALLENGE_MODES.md](HTTP_CHALLENGE_MODES.md) → [HTTP_CHALLENGE_CONFIGURATION.md](HTTP_CHALLENGE_CONFIGURATION.md)
   - DNS-01 challenges: [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md)
   - Revocation: [REVOCATION_IMPLEMENTATION.md](REVOCATION_IMPLEMENTATION.md)
   - CA-specific setup: [LETS_ENCRYPT.md](LETS_ENCRYPT.md), [acme/client.py](../acme/client.py) for others
   ```

3. **Create CA_PROVIDERS.md** — short doc listing all CAs with links:
   ```markdown
   # CA Providers

   | CA | ACME Directory | EAB Required | Setup Doc | Config |
   |---|---|---|---|---|
   | Let's Encrypt | letsencrypt.org | No | [LETS_ENCRYPT.md](LETS_ENCRYPT.md) | CA_PROVIDER=letsencrypt |
   | DigiCert | digicert.com | **Yes** | [acme/client.py](../acme/client.py) | CA_PROVIDER=digicert |
   | ...
   ```

4. **Update WIKI_ARCHITECTURE.md**:
   ```markdown
   ## Domain-specific Features

   - Feature availability: [FEATURE_MATRIX.md](FEATURE_MATRIX.md)
   - CA selection and setup: [CA_PROVIDERS.md](CA_PROVIDERS.md)
   ```

**Effort**: 2–3 hours (one session)

---

### 4. **Orphaned Deep-Dive Docs ⚠️ MEDIUM**

**Issue**: Several implementation deep-dives are not referenced from hubs:
- HTTP_01_VALIDATION_EXPLAINED.md — only discoverable via grep
- MCP_TOOL_SERIALIZATION.md — niche but useful
- LOGGER_IMPLEMENTATION_PLAN.md — future work, unclear status
- DESIGN_ASYNC_SCHEDULER_PLAN.md — "plan" status unclear

**Impact**: Valuable context is hard to find.

**Recommendation**:
1. Add **"Deep Dives"** section to hubs:
   ```markdown
   ## Deep Dives (Advanced Implementation Details)

   - HTTP-01 validation internals: [HTTP_01_VALIDATION_EXPLAINED.md](HTTP_01_VALIDATION_EXPLAINED.md)
   - MCP tool serialization rationale: [MCP_TOOL_SERIALIZATION.md](MCP_TOOL_SERIALIZATION.md)
   - Async scheduler design notes: [DESIGN_ASYNC_SCHEDULER_PLAN.md](DESIGN_ASYNC_SCHEDULER_PLAN.md)
   ```

2. Mark status explicitly in docs:
   - "**Status: Current implementation**" (in-use)
   - "**Status: Design proposal**" (not yet implemented)
   - "**Status: Historical context**" (past design, superseded)

3. Move LOGGER_IMPLEMENTATION_PLAN.md to a "Proposed Features" section if not yet implemented.

**Effort**: 1 hour

---

### 5. **Retrieval Hints Inconsistency ⚠️ LOW**

**Issue**: Only some docs include retrieval keywords and negative keywords. Makes automated doc recommendation harder.

**Examples**:
- DESIGN_PRINCIPLES.md ✅ has both
- SECURITY.md ❌ missing both
- CI_TEST_COVERAGE.md ❌ missing both
- LETS_ENCRYPT.md ❌ missing both

**Recommendation**:
- Add retrieval hints to all docs in "Start Here" (SETUP, USAGE, CONFIGURATION, SECURITY, RFC_COMPLIANCE, DESIGN_PRINCIPLES)
- **Effort**: 30 min total (batch edit)

---

### 6. **Document Size Variance (≤ Healthy) ✅**

**Longest docs** (300+ lines):
- ACME_AGENT_PLAN.md (616) — historical, flagged appropriately
- DESIGN_ASYNC_SCHEDULER_PLAN.md (584)
- SECURITY.md (581)
- DESIGN_STATEFUL_CLIENT_ANALYSIS.md (560)
- PEBBLE_TESTING_SERVER.md (459)
- CI_TEST_COVERAGE.md (452)

**Assessment**: Long docs are deep dives or canonical references (appropriate). No decomposition needed.

---

### 7. **Missing Navigation Features 🔍 OPTIONAL**

**Potential enhancements** (not critical, but valuable):

1. **Keyword index** (auto-generated or manual):
   ```
   ## Keyword Index

   - **ACME protocol**: RFC_COMPLIANCE.md, HOW_IT_WORKS.md, DESIGN_PROTOCOL_PATTERN.md
   - **Retry/backoff**: DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md, CI_TEST_COVERAGE.md
   - **Nonce management**: DESIGN_NONCE_MANAGEMENT_STRATEGY.md, DESIGN_PRINCIPLES.md
   - ...
   ```

2. **Dependency graph** (text-based):
   ```
   WIKI_HOME.md
   ├─ DESIGN_PRINCIPLES.md
   │  ├─ RFC_COMPLIANCE.md
   │  ├─ DESIGN_NONCE_MANAGEMENT_STRATEGY.md
   │  └─ ...
   ├─ WIKI_ARCHITECTURE.md
   │  ├─ HOW_IT_WORKS.md
   │  └─ DESIGN_PROTOCOL_PATTERN.md
   └─ WIKI_OPERATIONS.md
      ├─ SETUP.md
      └─ USAGE.md
   ```

3. **Page dependency checker** (Python script in CI):
   - Flag dead links
   - Warn about docs not referenced from any hub
   - Suggest missing "See also" sections

---

## Action Plan (Prioritized)

### Phase 1: Quick Wins (2–3 hours, high ROI)

**[Priority 1] Add retrieval hints to canonical sources** (30 min)
- Edit: SECURITY.md, RFC_COMPLIANCE.md, CI_TEST_COVERAGE.md, CONFIGURATION.md
- Add: `## Retrieval keywords` + `[negative keywords / not-this-doc]` sections

**[Priority 2] Populate "Domain-specific Features" section** (1 hour)
- Create FEATURE_MATRIX.md (or embed in WIKI_OPERATIONS.md)
- Add explicit links for DNS-01 + Revocation + CA variants
- Add CA_PROVIDERS.md reference

**[Priority 3] Create bidirectional links** (1 hour)
- Ensure HTTP-01 short + long docs link to each other
- Add DNS-01 to WIKI_OPERATIONS
- Add Revocation to WIKI_OPERATIONS "See also"

### Phase 2: Template Compliance (4–5 hours, medium ROI)

**[Priority 4] Expand template adherence** (4–5 hours)
- Add missing sections to top 8 canonical sources:
  - "When to use this page"
  - "Canonicality" statement
  - Metadata (status, review date)
  - "Failure modes / troubleshooting" (where applicable)
- Order: SECURITY.md → RFC_COMPLIANCE.md → CI_TEST_COVERAGE.md → CONFIGURATION.md → HOW_IT_WORKS.md → DESIGN_PRINCIPLES.md → CERTIFICATE_STORAGE.md → PROJECT_STRUCTURE.md

### Phase 3: Nice-to-Have (Optional, lower ROI)

**[Priority 5] Create keyword index** (1–2 hours)
- Add "Quick reference by topic" section to WIKI_HOME or separate INDEX.md

**[Priority 6] Auto-checker script** (2–3 hours)
- Python script in CI: validate links, flag orphaned docs, suggest missing cross-refs
- Run on PR to catch new docs without hub references

---

## Before/After Scenarios

### Scenario 1: "How do I set up DNS-01 with Route53?"

**Today**: User must:
1. Go to WIKI_HOME → WIKI_OPERATIONS (mentioned in routing table)
2. Search for "DNS" → no section found
3. Fall back to grep or memory → find DNS_01_IMPLEMENTATION_PLAN.md
4. Read full doc (359 lines) to find Route53 section

**After Phase 1–2**:
1. Go to WIKI_HOME → WIKI_OPERATIONS → "Domain-specific Features" → DNS-01
2. Click [DNS_01_IMPLEMENTATION_PLAN.md](DNS_01_IMPLEMENTATION_PLAN.md) → Route53 section
3. Or use FEATURE_MATRIX.md as quick reference

**Effort saved**: 2–3 min per query

---

### Scenario 2: "Is this feature tested and how secure is it?"

**Today**: User must:
1. Go to WIKI_HOME → search routing table
2. Find "WIKI_SECURITY_QUALITY.md"
3. Read SECURITY.md (missing when-to-use) + CI_TEST_COVERAGE.md (missing when-to-use)
4. Manually correlate feature name with test names

**After Phase 1**:
1. Go to WIKI_HOME → WIKI_SECURITY_QUALITY.md
2. Each doc now has "When to use" and "Canonicality" sections
3. Optional: FEATURE_MATRIX.md lists test coverage per feature

**Clarity improvement**: 30%

---

## Maintenance Checklist

After implementing improvements, maintain with:

- [ ] Template sections present in all canonical sources
- [ ] Bidirectional links working ("See also" chains complete)
- [ ] No orphaned docs (all linked from at least one hub)
- [ ] Retrieval keywords updated when scope changes
- [ ] Metadata (status, last reviewed) kept current
- [ ] New docs added to appropriate hub before merge
- [ ] Feature matrix updated whenever feature status changes

---

## Files Affected

| File | Change Type | Effort | Priority |
|------|-------------|--------|----------|
| WIKI_HOME.md | Add "Domain-specific Features" section | 30 min | 2 |
| WIKI_OPERATIONS.md | Populate "Domain-specific Features" | 30 min | 2 |
| WIKI_ARCHITECTURE.md | Populate "Domain-specific Features" | 15 min | 2 |
| FEATURE_MATRIX.md | Create new | 1 hour | 1 |
| CA_PROVIDERS.md | Create new | 30 min | 1 |
| SECURITY.md | Add template sections + retrieval hints | 30 min | 3 |
| RFC_COMPLIANCE.md | Add template sections + retrieval hints | 30 min | 3 |
| CI_TEST_COVERAGE.md | Add template sections + retrieval hints | 30 min | 3 |
| CONFIGURATION.md | Add template sections | 15 min | 3 |
| HTTP_CHALLENGE_CONFIGURATION.md | Add bidirectional link | 5 min | 2 |
| DNS_01_IMPLEMENTATION_PLAN.md | Add bidirectional link from hub | (above) | 2 |
| REVOCATION_IMPLEMENTATION.md | Update cross-refs | 10 min | 2 |

**Total effort**: ~6 hours over 2–3 weeks

---

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Authoring rules: [WIKI_TEMPLATE.md](WIKI_TEMPLATE.md)
- Architecture hub: [WIKI_ARCHITECTURE.md](WIKI_ARCHITECTURE.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Security & quality hub: [WIKI_SECURITY_QUALITY.md](WIKI_SECURITY_QUALITY.md)
