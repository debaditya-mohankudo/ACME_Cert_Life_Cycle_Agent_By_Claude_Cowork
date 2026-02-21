# Why Keep the LLM for Renewal Planner

**Date:** 2026-02-21
**Status:** Architectural Decision
**Category:** Agent Design Pattern

---

## Overview

The `renewal_planner` node uses an LLM (Claude Haiku) to classify domains into three categories:
- **urgent**: expires in < 7 days or already expired
- **routine**: expires in 7–`threshold` days (configurable)
- **skip**: healthy (> threshold remaining)

This document explains why an LLM is the right choice despite the simplicity of the base logic.

---

## What the Planner Does

```
Input:  cert_records (domain, expiry_date, days_until_expiry)
        managed_domains (whitelist)
        renewal_threshold_days (config)

Process:
  1. Analyze certificate expiry data
  2. Classify each domain into urgency bucket
  3. Return ordered JSON with notes
  4. Validate output (prevent hallucination)

Output: pending_renewals (ordered list), renewal_plan (JSON with reasoning)
```

**Key detail:** The planner also generates `notes` explaining *why* domains were classified a certain way—this observability is crucial for operators.

---

## The Deterministic Alternative (and Why It Fails)

A pure threshold-based approach looks simple:

```python
def renewal_planner_deterministic(state):
    urgent = [d for d in domains if days_until_expiry < 7]
    routine = [d for d in domains if 7 <= days_until_expiry <= threshold]
    skip = [d for d in domains if days_until_expiry > threshold]
    return {"pending_renewals": urgent + routine}
```

**This works for the baseline case.** But it immediately breaks when you need:

### 1. Domain-Specific Rules
- Production domains: renew at 30 days
- Staging domains: renew at 60 days
- Internal-only domains: renew at 90 days
- **Deterministic solution:** Hard-code domain → rule mappings, maintain in code

### 2. SLA-Aware Classification
- Critical API (99.99% SLA): urgent if < 15 days
- Standard service: urgent if < 7 days
- Dev environment: urgent if < 2 days
- **Deterministic solution:** Create a rule engine, add domain metadata, rebuild on each change

### 3. Anomaly Detection
- "This domain renewed 3 times in 2 weeks—flag for investigation"
- "Certificate was just renewed 10 days ago, something's wrong"
- "Multiple SANs share one cert, treat as a unit"
- **Deterministic solution:** Write custom logic for each case, ship code

### 4. Failure Pattern Learning
- "This domain's CA is flaky Tuesdays 2–4 PM UTC, adjust schedule"
- "Previous renewal failed due to DNS timeout, try earlier in the week"
- "This domain's ACME server rejects challenges intermittently, add retry logic"
- **Deterministic solution:** Build a state machine to track failure history

---

## Why the LLM Solution Is Better

### ✅ 1. Extensibility Without Code Changes
Add new rules to the prompt, no deployment needed:

```python
# Current prompt (threshold-only)
PLANNER_USER = """
Classify each domain:
- urgent: < 7 days
- routine: 7–{threshold} days
- skip: > {threshold} days
"""

# Future: Add domain metadata
PLANNER_USER = """
Domain metadata:
{domain_metadata}

Classify each domain considering criticality, SLA, and failure history...
"""

# Result: New behavior without touching code
```

### ✅ 2. Built-In Observability
The LLM's `notes` field explains decisions:

```json
{
  "urgent": ["api.production.com"],
  "routine": ["web.staging.com"],
  "skip": ["internal.example.com"],
  "notes": "api.production.com is CRITICAL (SLA 99.99%) and < 15 days. web.staging is routine schedule. internal has > 90 days remaining."
}
```

**Operators can read and understand why domains were prioritized.** This is invaluable for auditing, debugging, and building trust in the system.

### ✅ 3. Graceful Fallback
Validation layer ensures safety:

```python
def _parse_and_validate(raw: str, managed_domains: set[str]) -> dict:
    # If JSON parse fails → renew all domains (safe default)
    # If domains hallucinated → strip them (no false positives)
    # If domains missing → add to "routine" (never silently skip)
```

The LLM can fail gracefully—worst case, you renew everything (safe).

### ✅ 4. Future-Proof for LLM Improvements
LLMs are getting smarter rapidly. By 2026 (and beyond):
- Better structured reasoning
- Multi-step classification logic
- Cost-effective domain analysis
- Anomaly detection built-in

**Your agent automatically benefits** when the model improves. No code change needed.

### ✅ 5. Cost Is Negligible
- **Model:** Claude Haiku (fastest, cheapest)
- **Tokens:** ~300–400 per call (cert summary + prompt)
- **Cost:** ~$0.0001 per renewal cycle
- **Frequency:** Daily (or less)
- **Annual cost:** ~$0.03 per agent (essentially free)

Compared to the value of intelligent prioritization, the LLM cost is rounding error.

---

## Comparison: Deterministic vs. LLM

| Dimension | Deterministic | LLM (Current) |
|-----------|---|---|
| **Threshold logic** | 🟢 Simple | 🟢 Works |
| **Domain rules** | 🔴 Code change + deploy | 🟢 Prompt update |
| **SLA awareness** | 🔴 Requires rule engine | 🟢 Natural language |
| **Anomaly detection** | 🔴 Custom logic per case | 🟢 Can reason about it |
| **Observability** | 🔴 Silent decisions | 🟢 Explains reasoning |
| **Extensibility** | 🔴 Stuck at threshold | 🟢 Open-ended |
| **Cost** | 🟢 Zero | 🟢 ~$0.0001/call |
| **Future capabilities** | 🔴 No automatic benefit | 🟢 Scales with models |
| **Failure handling** | 🔴 Edge case management | 🟢 Graceful fallback |
| **Maintenance burden** | 🟡 Rules → config drift | 🟢 Prompt as source of truth |

---

## Real-World Scenarios

### Scenario 1: Emergency SLA Requirement
**Situation:** Customer escalates: "Our API cert is critical (99.99% SLA). We need renewals to start at 30 days, not 7."

**Deterministic:** Create `domain_rules.json`, add `api.critical.com`, deploy code, restart agent. **2–3 hours.**

**LLM:** Add domain metadata to state:
```python
state["domain_metadata"]["api.critical.com"] = {"criticality": "CRITICAL", "sla_percentage": 99.99}
```
Update prompt: "For CRITICAL domains, urgent if < 30 days." **5 minutes**, no deploy.

### Scenario 2: Unexpected Renewal Loop
**Situation:** Ops team notices `staging.example.com` renewed 3 times in 2 weeks. Something's broken.

**Deterministic:** Write debug script, trace logs, add exception handling. **Ongoing debugging.**

**LLM:** Prompt includes renewal history:
```
{
  "staging.example.com": {
    "renewed": [
      {"date": "2026-02-15", "reason": "initial"},
      {"date": "2026-02-18", "reason": "unknown"},
      {"date": "2026-02-21", "reason": "unknown"}
    ]
  }
}
```
LLM detects anomaly in `notes`: "staging.example.com renewed 3x in 7 days—possible credential leak or challenge failure. Investigate." **Automatic detection.**

### Scenario 3: Multi-Region Strategy
**Situation:** Add 15 new domains across 3 regions, each with different renewal windows.

**Deterministic:** Write rules for each region, manage config complexity, risk of errors. **Complex.**

**LLM:** Provide region metadata in state. Prompt naturally handles classification by region without code. **Simple.**

---

## Future Extensibility (Roadmap)

### Near-term (Months)
```python
state["domain_metadata"] = {
    "api.prod.com": {
        "criticality": "CRITICAL",
        "owner": "platform@company.com",
        "sla": "99.99%",
        "renewal_window_days": 30,
    }
}

# Prompt automatically considers this
PLANNER_USER = """
Domain metadata:
{domain_metadata}

For CRITICAL domains, mark urgent if < renewal_window_days.
For standard domains, use default threshold.
"""
```

### Medium-term (Quarters)
```python
state["renewal_history"] = {
    "api.prod.com": {
        "last_renewal": "2026-02-10",
        "failures": 2,
        "average_duration_hours": 45,
        "trend": "success_rate_declining"
    }
}

# LLM can reason about historical patterns
PLANNER_USER = """
Renewal history:
{renewal_history}

Domains with declining success rates should be prioritized earlier.
If last renewal was < 30 days ago, investigate for anomalies.
"""
```

### Long-term (Years)
```python
# LLM can handle multi-dimensional prioritization
PLANNER_USER = """
Classify domains considering:
1. Expiry timeline (urgency)
2. SLA criticality (importance)
3. Failure history (reliability)
4. Regional load (scheduling)
5. Certificate dependencies (ordering)

Provide a JSON plan that optimizes for all factors.
"""
```

**Deterministic approach:** Would require a full constraint-satisfaction solver by this point.
**LLM approach:** Works naturally as you add dimensions.

---

## Validation & Safety

The planner uses **defensive validation** to prevent hallucination:

```python
def _parse_and_validate(raw: str, managed_domains: set[str]) -> dict:
    # 1. Parse JSON (fallback to safe default if invalid)
    # 2. Strip hallucinated domains not in managed_domains
    # 3. Fill any missing domains (add to "routine")
    # 4. Return validated plan
```

This means:
- ✅ LLM can't add domains you don't manage
- ✅ LLM can't silently drop domains
- ✅ Failed parsing → safe default (renew everything)
- ✅ No security risk from "smart" classification

---

## Decision

**Keep the LLM for renewal_planner.**

**Rationale:**
1. Base logic (threshold) is simple, but real-world scenarios demand flexibility
2. LLM provides extensibility without code deployments
3. Cost is negligible (~$0.0001/call)
4. Built-in observability (notes) is valuable for operators
5. LLMs are improving rapidly—automatic benefit from model upgrades
6. Validation layer ensures safety
7. Graceful fallback on failure

**Alternative considered:** Deterministic with domain metadata config.
**Rejected because:** Loses observability, requires custom rule engine, less flexible for future scenarios.

---

## Related Documents

- [`ACME_AGENT_PLAN.md`](ACME_AGENT_PLAN.md) — Agent architecture overview
- [`agent/nodes/planner.py`](../agent/nodes/planner.py) — Implementation
- [`agent/prompts.py`](../agent/prompts.py) — Prompt templates
- [`TEST_RESULTS.md`](../TEST_RESULTS.md) — Planner validation tests
