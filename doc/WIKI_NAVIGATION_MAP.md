# Wiki Navigation Map — Current vs. Proposed

**Purpose**: Visual reference for doc organization before and after structural improvements.

---

## Current State: Hub-Based Navigation

```
                              WIKI_HOME.md
                           (routing table +
                          canonical sources)
                                  │
                    ┌─────────────┼─────────────┬──────────────┐
                    │             │             │              │
                    ▼             ▼             ▼              ▼
            WIKI_          WIKI_           WIKI_          WIKI_
         ARCHITECTURE    OPERATIONS      SECURITY_        (others)
              hub            hub          QUALITY hub
                    │             │             │              │
    ┌───────────────┼─────────┐   │   ┌────────┼─────┐        │
    │               │         │   │   │        │     │        │
Design          Protocol    Setup/  Config   Security Testing   │
Principles   Constraints    Runtime  Refs    & Audit  & Trace   │
RFC_COMP     HOW_IT_WORKS   SETUP                      │        │
DESIGN_*     PROJECT_*      USAGE           SECURITY.md │     MCP_*
             *               CONFIGURATION  RFC_COMP.md │     LOGGER_*
                            HTTP_CHALLENGE CI_TEST.md  │     DOCKER_*
                            PEBBLE.md      │           │
                            DOCKER.md      └───────────┘

⚠️ PROBLEM: Some docs are orphaned or hard to find
  - DNS_01_IMPLEMENTATION_PLAN.md — not in any hub!
  - HTTP_01_VALIDATION_EXPLAINED.md — not in any hub!
  - REVOCATION_IMPLEMENTATION.md — buried in WIKI_OPERATIONS
  - CA setup instructions scattered (LETS_ENCRYPT.md + code)
  - Status of "DESIGN_ASYNC_SCHEDULER_PLAN.md" unclear
```

---

## Proposed: Enhanced Hub with Feature Matrix

```
                              WIKI_HOME.md
                           (routing table +
                          canonical sources)
                                  │
                    ┌─────────────┼─────────────┬──────────────┐
                    │             │             │              │
                    ▼             ▼             ▼              ▼
            WIKI_          WIKI_           WIKI_          WIKI_
         ARCHITECTURE    OPERATIONS      SECURITY_        (others)
              hub            hub          QUALITY hub
                    │             │             │              │
    ┌───────────────┼──────┐      │   ┌────────┼─────┐        │
    │               │      │      │   │        │     │        │
Design          Protocol   Domain │   │     Security Testing   │
Principles   Constraints  Specific config   & Audit  & Trace   │
RFC_COMP     HOW_IT_WORKS Features         SECURITY.md         │
DESIGN_*     PROJECT_*    (NEW)            RFC_COMP.md        MCP_*
             *              │              CI_TEST.md         LOGGER_*
                          Feature          LLM_NODES.md       DOCKER_*
                          Matrix (NEW)     OBSERVABILITY.md
                          CA_PROVIDERS
                          (NEW)
                            │
                    ┌───────┼─────────┐
                    │       │         │
              HTTP-01   DNS-01    Revocation
              Challenges Challenges (NEW)
              │         │         │
        [short]─→[long] │      [impl]
        HTTP_CHALLENGE_ │      REVOCATION_
        MODES.md   CONFIG.md  IMPLEMENTATION.md
                    │         │
                    └──────┬──┘
               DNS_01_    (both linked
               IMPL.md    from hub now)

✅ IMPROVEMENT: Every feature visible from hub
  - Feature matrix provides quick reference
  - Bidirectional links between related docs
  - Clear "short intro" → "detailed config" flow
  - CA options centralized in CA_PROVIDERS.md
  - Status explicitly marked on all docs
```

---

## Navigation Flows: Key Scenarios

### Scenario 1: Feature Discovery

**Today:**
```
User: "What features does this support?"
  ↓
WIKI_HOME.md (routing table)
  → Mentions routing table but no feature list
  → User must grep or read code
```

**After improvement:**
```
User: "What features does this support?"
  ↓
WIKI_HOME.md
  → Click "WIKI_OPERATIONS.md"
  → See "Domain-specific Features" section
  → Click "FEATURE_MATRIX.md" for quick overview
  → Click specific feature for detailed setup
```

---

### Scenario 2: Deep Question on a Feature

**Today:**
```
User: "How does DNS-01 work with Route53?"
  ↓
Google → grep docs
  → Find DNS_01_IMPLEMENTATION_PLAN.md
  → Read 359 lines to find Route53 section
  → (15 minutes)
```

**After improvement:**
```
User: "How does DNS-01 work with Route53?"
  ↓
WIKI_HOME.md
  → WIKI_OPERATIONS.md
  → "Domain-specific Features" → DNS-01
  → DNS_01_IMPLEMENTATION_PLAN.md (now linked)
  → Search within doc for "Route53"
  → (3 minutes)
```

---

### Scenario 3: "Is X secure and tested?"

**Today:**
```
User: "Is DNS-01 secure and well-tested?"
  ↓
WIKI_HOME.md (routing table mentions WIKI_SECURITY_QUALITY)
  → WIKI_SECURITY_QUALITY.md
  → Must read SECURITY.md + CI_TEST_COVERAGE.md
  → Must manually find tests mentioning "dns"
  → No metadata about review status
  → (10 minutes)
```

**After improvement:**
```
User: "Is DNS-01 secure and well-tested?"
  ↓
WIKI_HOME.md → WIKI_SECURITY_QUALITY.md
  → FEATURE_MATRIX.md shows test coverage per feature
  → Click [SECURITY.md](SECURITY.md) (now has "Canonicality" section)
  → Click [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md) (now has metadata)
  → See "Last reviewed: 2026-02-27" + explicit test counts
  → (5 minutes)
```

---

## Hub Reference Card (One-Pager)

### WIKI_HOME.md
**Purpose:** Decision tree + routing table
**When to use:** First stop; agent use rules
**Key sections:**
- Agent routing table (user intent → entry point)
- Canonical sources (source-of-truth refs)
- Start here (new contributor path)
- Wiki hubs (three main gateways)
- Fast paths (keyword jump links)
**Exit to:** One of the three hubs below

---

### WIKI_ARCHITECTURE.md
**Purpose:** System design, constraints, invariants
**When to use:** "How does it work?" and "Why is it designed this way?"
**Key sections:**
- Agent use rules (how to ask questions)
- Core design (DESIGN_PRINCIPLES, RFC_COMPLIANCE, HOW_IT_WORKS)
- Architecture deep dives (nonce, backoff, stateful vs stateless)
- **Domain-specific features** (Challenge modes, CA options, etc.) — **NOW POPULATED**
- See also (links to Operations & Security hubs)

---

### WIKI_OPERATIONS.md
**Purpose:** Setup, usage, configuration, infrastructure
**When to use:** "How do I run this?" and "What setting controls X?"
**Key sections:**
- Agent use rules (which doc answers which question)
- Setup & bootstrapping (SETUP.md, DEPENDENCIES.md)
- Runtime usage (USAGE.md, HOW_IT_WORKS.md, PROJECT_STRUCTURE.md)
- Configuration (CONFIGURATION.md, HTTP_CHALLENGE docs)
- Docker & local infra (DOCKER.md, Pebble, test flow)
- MCP operations (server, impl, serialization)
- **Domain-specific features** (HTTP-01, DNS-01, Revocation) — **NOW POPULATED**
- See also (links to Architecture & Security hubs)

---

### WIKI_SECURITY_QUALITY.md
**Purpose:** Security posture, testing, observability
**When to use:** "Is this safe?" and "What tests cover this?"
**Key sections:**
- Agent use rules (security + testing questions)
- Security (SECURITY.md, RFC_COMPLIANCE.md, CERTIFICATE_STORAGE.md)
- Observability (OBSERVABILITY.md, logging)
- Testing & CI (CI_TEST_COVERAGE.md, checkpoint tests, planner validation tests)
- LLM-specific quality (LLM_NODES.md constraints)
- See also (links to Architecture & Operations hubs)

---

## Document Ownership Matrix (Optional Addition)

Consider adding to each canonical source:

```markdown
## Metadata

- **Owner**: (Team name or person email)
- **Status**: active | draft | deprecated | historical
- **Last Reviewed**: YYYY-MM-DD
- **Next Review Due**: YYYY-MM-DD
```

**Examples:**
- DESIGN_PRINCIPLES.md → Owner: Architecture team | Status: active | Next review: 2026-05-27
- CONFIGURATION.md → Owner: DevOps team | Status: active | Last reviewed: 2026-02-20
- ACME_AGENT_PLAN.md → Owner: (legacy) | Status: historical | Note: Superseded by HOW_IT_WORKS.md

---

## Dependency Graph (Text Format)

```
START: WIKI_HOME.md (routing table)
│
├─→ WIKI_ARCHITECTURE.md
│   ├─→ DESIGN_PRINCIPLES.md (constitutional layer)
│   │   ├─→ RFC_COMPLIANCE.md
│   │   ├─→ DESIGN_NONCE_MANAGEMENT_STRATEGY.md
│   │   ├─→ DESIGN_BACKOFF_INTEGRATION_ANALYSIS.md
│   │   ├─→ DESIGN_STATEFUL_CLIENT_ANALYSIS.md
│   │   ├─→ DESIGN_PROTOCOL_PATTERN.md
│   │   └─→ DESIGN_RENEWAL_PLANNER_LLM_RATIONALE.md
│   │
│   ├─→ HOW_IT_WORKS.md (current graph flow)
│   │   └─→ RFC_COMPLIANCE.md
│   │
│   ├─→ ACME_AGENT_PLAN.md (historical, pre-implementation)
│   │
│   └─→ (NEW) FEATURE_MATRIX.md
│       ├─→ HTTP-01 docs
│       ├─→ DNS-01 docs
│       ├─→ REVOCATION_IMPLEMENTATION.md
│       └─→ CA_PROVIDERS.md
│
├─→ WIKI_OPERATIONS.md
│   ├─→ SETUP.md
│   ├─→ USAGE.md
│   ├─→ CONFIGURATION.md
│   ├─→ HTTP-01 (short) → HTTP-01 (long)
│   ├─→ DNS-01 (implementation plan)
│   ├─→ REVOCATION_IMPLEMENTATION.md
│   ├─→ DOCKER.md, PEBBLE.md, etc.
│   └─→ MCP_SERVER.md, MCP_IMPLEMENTATION_DETAILS.md
│
├─→ WIKI_SECURITY_QUALITY.md
│   ├─→ SECURITY.md
│   ├─→ RFC_COMPLIANCE.md
│   ├─→ CERTIFICATE_STORAGE.md
│   ├─→ CI_TEST_COVERAGE.md
│   ├─→ CHECKPOINT_TESTS.md
│   ├─→ PLANNER_VALIDATION_TESTS.md
│   ├─→ LLM_NODES.md
│   └─→ OBSERVABILITY.md
│
└─→ (Orphaned / Deep Dives)
    ├─→ HTTP_01_VALIDATION_EXPLAINED.md (NOW → Architecture hub)
    ├─→ MCP_TOOL_SERIALIZATION.md (NOW → Operations hub as deep dive)
    ├─→ LOGGER_IMPLEMENTATION_PLAN.md (status unclear; propose deep dives section)
    └─→ DESIGN_ASYNC_SCHEDULER_PLAN.md (status unclear; mark as "design proposal")
```

---

## Quick Implementation Checklist

- [ ] **FEATURE_MATRIX.md** created (lists all features + setup links)
- [ ] **CA_PROVIDERS.md** created (quick ref for CA selection)
- [ ] **WIKI_OPERATIONS.md** → "Domain-specific Features" section populated
- [ ] **WIKI_ARCHITECTURE.md** → "Domain-specific Features" section populated
- [ ] **Bidirectional links** added (HTTP-01 short ↔ long, DNS-01 to hub, Revocation to hub)
- [ ] **Retrieval hints** added to canonical sources (SECURITY, RFC, CI_TEST, CONFIG)
- [ ] **Metadata sections** added to all canonical sources (status, owner, review date)
- [ ] **Deep dives section** added to hubs (status clarified for async scheduler, logger plan, etc.)
- [ ] **Orphaned docs** linked from at least one hub

---

## See also

- Analysis document: [WIKI_STRUCTURAL_ANALYSIS.md](WIKI_STRUCTURAL_ANALYSIS.md)
- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Template guide: [WIKI_TEMPLATE.md](WIKI_TEMPLATE.md)
