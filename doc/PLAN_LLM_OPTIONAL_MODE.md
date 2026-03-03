# Plan: Optional LLM Mode Configuration

**Status:** Planning  
**Priority:** Medium  
**Scope:** Configuration + three LLM nodes + tests + docs  
**Estimated Effort:** 3-4 focused sessions

---

## 1. Objective

Add a configuration flag `LLM_DISABLED` to allow the agent to run in fully deterministic mode without any LLM calls. This enables:

- **Air-gapped installations** without LLM API access
- **Cost optimization** for teams who want no API calls
- **Predictable, auditable renewal logic** (no LLM variability)
- **Faster iteration** for testing and development

---

## 2. High-Level Design

### Current State (LLM-Required)

- `renewal_planner` (LLM): Classifies domains as urgent/routine based on expiry
- `error_handler` (LLM): Recommends retry/skip/abort actions
- `summary_reporter` (LLM): Generates human-readable summary

### New State (LLM-Optional)

When `LLM_DISABLED=true`:

- `renewal_planner`: Deterministic → renew ALL domains (no prioritization)
- `error_handler`: Deterministic → retry N times, then skip
- `summary_reporter`: Deterministic → simple formatted summary (no LLM)

When `LLM_DISABLED=false` (default):

- Behavior unchanged; operates as today

---

## 3. Core Constraints (from DESIGN_PRINCIPLES.md)

1. **RFC compliance** — must not change nonce handling, ACME flow, or cert storage
2. **Deterministic behavior** — when disabled, output must be fully predictable given same inputs
3. **LLM advisory, never authoritative** — LLM bypass must not introduce side effects
4. **Idempotent nodes** — disabled mode must also be safe to retry/resume
5. **State must be serializable** — no hidden state in LLM disabled mode either

---

## 4. Changes Required

### 4.1 Configuration Change

**File:** `config.py`

Add new boolean setting:

```python
# ── LLM Control ────────────────────────────────────────────────────────────
LLM_DISABLED: bool = False  # If True, use deterministic fallbacks for planner/error_handler/reporter
```

**Constraints:**
- Default is `False` (maintain backward compatibility)
- Cannot be used with `LLM_PROVIDER` misconfiguration (but doesn't enforce API key presence)
- Works with any `CA_PROVIDER` and challenge mode

**Validation:** None needed — this is purely a feature flag

---

### 4.2 Planner Node Logic Change

**File:** `agent/nodes/planner.py`

**Current (LLM) logic:**
1. Send cert records to LLM with managed domains
2. LLM classifies as urgent/routine/skip
3. Validate and strip hallucinated domains
4. Queue urgent + routine as pending_renewals

**New (Deterministic) logic when LLM_DISABLED:**
1. Scan cert_records
2. Split by renewal decision:
   - **Renew:** domains expiring within `RENEWAL_THRESHOLD_DAYS` + domains with NO certificate
   - **Skip:** domains with fresh certs (safer than renewing too often)
3. Queue ALL renewals in order: no-cert first, then by expiry date (ascending)

**Implementation:**

```python
def _renewal_planner_deterministic(cert_records, managed_domains, threshold_days):
    """
    Deterministic renewal planner when LLM is disabled.
    
    Returns pending_renewals: list[str] in deterministic order.
    Order: [no_cert_domains, expiring_soon_domains_by_date]
    """
    no_cert = []
    expiring_soon = []
    
    for rec in cert_records:
        domain = rec["domain"]
        days = rec["days_until_expiry"]
        
        if days is None:
            no_cert.append(domain)
        elif days <= threshold_days:
            expiring_soon.append((domain, days, rec["expiry_date"]))
    
    # Sort expiring_soon by days ascending (closest expiry first)
    expiring_soon.sort(key=lambda x: (x[1], x[2]))
    expiring_soon_domains = [d for d, _, _ in expiring_soon]
    
    # Return order: no_cert_domains, then expiring_soon
    return no_cert + expiring_soon_domains
```

**State updates:**
- `renewal_plan`: string description of deterministic decision
- `pending_renewals`: list of domains in order
- `messages`: logs only (no LLM messages)

---

### 4.3 Error Handler Node Logic Change

**File:** `agent/nodes/error_handler.py`

**Current (LLM) logic:**
1. Send error context to LLM
2. LLM decides: retry / skip / abort
3. LLM suggests delay

**New (Deterministic) logic when LLM_DISABLED:**
1. Check `retry_count < MAX_RETRIES`
2. If yes → **retry** with exponential backoff
   - Delay = `min(retry_delay * 2^retry_count, 300)` seconds
3. If no → **skip** domain

**No abort action** (deterministic mode — prefer skip to give operators a chance to intervene manually)

**Implementation:**

```python
def _error_handler_deterministic(retry_count, max_retries, retry_delay_seconds):
    """
    Deterministic error handler when LLM is disabled.
    
    Returns: action ("retry" or "skip"), new_delay_seconds
    """
    if retry_count < max_retries:
        # Exponential backoff: delay * 2^retry_count, capped at 300s
        exponent = retry_count + 1
        new_delay = min(retry_delay_seconds * (2 ** exponent), 300)
        return "retry", int(new_delay)
    else:
        return "skip", 0
```

**State updates:**
- `error_analysis`: description of deterministic decision
- Action routing unchanged (retry → retry_scheduler, skip → pick_next_domain)

---

### 4.4 Reporter Node Logic Change

**File:** `agent/nodes/reporter.py`

**Current (LLM) logic:**
1. Gather completion stats, error logs
2. Send to LLM
3. LLM generates prose summary

**New (Deterministic) logic when LLM_DISABLED:**
1. Simple formatted summary:
   ```
   ═════════════════════════════════════════
   ACME Certificate Renewal Summary
   ═════════════════════════════════════════
   Renewed:   <count>: comma-separated list
   Failed:    <count>: comma-separated list
   Skipped:   <count>: comma-separated list
   Errors:    <count> entries in log
   Status:    SUCCESS / PARTIAL / FAILED
   ═════════════════════════════════════════
   ```

**Implementation:**

```python
def _summary_reporter_deterministic(completed, failed, managed_domains, error_log):
    """
    Deterministic summary reporter when LLM is disabled.
    """
    renewed_and_failed = set(completed) | set(failed)
    skipped = [d for d in managed_domains if d not in renewed_and_failed]
    
    status = "SUCCESS" if not failed else ("PARTIAL" if completed else "FAILED")
    
    summary = (
        "═" * 50 + "\n"
        "ACME Certificate Renewal Summary\n"
        + "═" * 50 + "\n"
        f"Renewed:   {len(completed)}: {', '.join(completed) or '(none)'}\n"
        f"Failed:    {len(failed)}: {', '.join(failed) or '(none)'}\n"
        f"Skipped:   {len(skipped)}: {', '.join(skipped) or '(none)'}\n"
        f"Errors:    {len(error_log)}\n"
        f"Status:    {status}\n"
        + "═" * 50
    )
    return summary
```

---

### 4.5 Node Implementation Changes

Each node (`planner.py`, `error_handler.py`, `reporter.py`) will follow this pattern:

```python
def run(self, state: AgentState) -> dict:
    # Check config flag
    if config.settings.LLM_DISABLED:
        return self._run_deterministic(state)
    else:
        return self._run_llm(state)

def _run_llm(self, state: AgentState) -> dict:
    """Current implementation (LLM-based)."""
    # ... existing code ...

def _run_deterministic(self, state: AgentState) -> dict:
    """New deterministic implementation."""
    # ... new code ...
```

**Rationale:** Keeps LLM code isolated; no modification to existing logic path

---

## 5. Testing Strategy

### 5.1 New Tests (One File Per Node)

#### `tests/test_planner_deterministic.py`

```python
class TestPlannerDeterministic:
    """Test renewal_planner in LLM_DISABLED mode."""
    
    def test_renews_all_no_cert_domains(self, pebble_settings):
        """Domains with no cert are always renewed."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
        
    def test_renews_all_domains_under_threshold(self, pebble_settings):
        """Domains expiring within threshold are renewed."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_skips_fresh_certs_above_threshold(self, pebble_settings):
        """Domains beyond threshold are skipped."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_prioritizes_no_cert_before_expiring(self, pebble_settings):
        """No-cert domains queued before expiring domains."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_sorts_expiring_by_days(self, pebble_settings):
        """Expiring domains sorted by days_until_expiry ascending."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_returns_plain_string_renewal_plan(self, pebble_settings):
        """renewal_plan contains no LLM output, just description."""
```

#### `tests/test_error_handler_deterministic.py`

```python
class TestErrorHandlerDeterministic:
    """Test error_handler in LLM_DISABLED mode."""
    
    def test_retries_while_under_max_retries(self, pebble_settings):
        """Returns 'retry' action if retry_count < max_retries."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange state with retry_count=0, max_retries=3 ...
        # ... assert action == "retry" ...
    
    def test_skips_when_max_retries_exceeded(self, pebble_settings):
        """Returns 'skip' action if retry_count >= max_retries."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange state with retry_count=3, max_retries=3 ...
        # ... assert action == "skip" ...
    
    def test_exponential_backoff_delay(self, pebble_settings):
        """Suggested delay doubles with each retry."""
        pebble_settings.LLM_DISABLED = True
        # retry_count=0 → delay ≈ retry_delay * 2
        # retry_count=1 → delay ≈ retry_delay * 4
        # etc.
    
    def test_delay_capped_at_300_seconds(self, pebble_settings):
        """Delay never exceeds 300 seconds."""
        pebble_settings.LLM_DISABLED = True
        # ... with many retries ...
        # ... assert suggested_delay <= 300 ...
    
    def test_error_analysis_is_readable_text(self, pebble_settings):
        """error_analysis is plain text, not JSON."""
        pebble_settings.LLM_DISABLED = True
        # ... assert isinstance(error_analysis, str) ...
        # ... assert not error_analysis.startswith("{") ...
```

#### `tests/test_reporter_deterministic.py`

```python
class TestReporterDeterministic:
    """Test summary_reporter in LLM_DISABLED mode."""
    
    def test_reports_all_completed_domains(self, pebble_settings):
        """Summary includes all completed renewals."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange with completed=["api.example.com", "shop.example.com"] ...
    
    def test_reports_all_failed_domains(self, pebble_settings):
        """Summary includes all failed domains."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_status_is_success_when_no_failures(self, pebble_settings):
        """Status field is 'SUCCESS' when failed=[]. """
        pebble_settings.LLM_DISABLED = True
        # ... arrange with failed=[] ...
    
    def test_status_is_partial_when_some_failures(self, pebble_settings):
        """Status field is 'PARTIAL' when failed has entries."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_status_is_failed_when_all_failures(self, pebble_settings):
        """Status field is 'FAILED' when completed=[] and failed=[...]."""
        pebble_settings.LLM_DISABLED = True
        # ... arrange ...
    
    def test_summary_is_plain_text_no_json(self, pebble_settings):
        """Summary is formatted text, not JSON."""
```

### 5.2 Existing Test Updates

For any test that currently mocks an LLM node, add a parameterized check:

```python
@pytest.mark.parametrize("llm_disabled", [False, True])
def test_planner_node_strips_hallucinated_from_pending_renewals(llm_disabled, monkeypatch):
    """Verify hallucination stripping works for both LLM and deterministic mode."""
    pebble_settings.LLM_DISABLED = llm_disabled
    # ... rest of test ...
```

### 5.3 Integration Test (Optional)

**File:** `tests/test_integration_llm_disabled.py` (optional, if workflow test is desired)

End-to-end test:
1. Set `LLM_DISABLED=true`
2. Run agent against Pebble with multiple domains
3. Verify:
   - All domains are renewed
   - Deterministic retry logic works on simulated errors
   - Final summary is deterministic text format

---

## 6. Documentation Changes

### 6.1 Update `doc/CONFIGURATION.md`

Add new section:

```markdown
### LLM_DISABLED

- **Type:** `bool`
- **Default:** `false`
- **Description:** When `true`, disables all LLM calls and uses deterministic fallbacks.

#### Deterministic Behavior

When `LLM_DISABLED=true`:

- **Renewal Planner:** Renews ALL domains with certificates expiring within `RENEWAL_THRESHOLD_DAYS`, plus all domains missing certificates. No prioritization.
- **Error Handler:** Retries up to `MAX_RETRIES` times with exponential backoff (capped at 300s). After max retries, skips the domain.
- **Summary Reporter:** Outputs plain-text formatted summary (no LLM-generated prose).
- **No LLM API calls:** No `LLM_PROVIDER`, `LLM_MODEL_*`, or API key validation required.

#### Use Cases

- Air-gapped environments without LLM API access
- Cost optimization (no API calls)
- Reproducible, auditable renewal logic
- Development/testing environments

#### Example

```env
LLM_DISABLED=true
CA_PROVIDER=letsencrypt
MANAGED_DOMAINS=api.example.com,shop.example.com
```
```

### 6.2 Update `README.md` - Quick Start

Add bullet under "Features":

```markdown
- **Deterministic mode** (`LLM_DISABLED=true`): No LLM API calls; fully auditable renewal logic
```

### 6.3 Update `CLAUDE.md` - Hard Invariants

Verify that LLM being optional doesn't violate hard invariants (it doesn't).

Add one line to `.history`:

```
feature | config,planner,error_handler,reporter | Add LLM_DISABLED config flag for deterministic renewal (no API calls required)
```

---

## 7. Implementation Checklist

### Phase 1: Configuration & Utilities (½ session)

- [ ] Add `LLM_DISABLED: bool = False` to `config.py`
- [ ] Create utility helper functions in each node's module

### Phase 2: Node Core Logic (1.5 sessions)

- [ ] Implement `_renewal_planner_deterministic()` in `planner.py`
- [ ] Implement `_error_handler_deterministic()` in `error_handler.py`
- [ ] Implement `_summary_reporter_deterministic()` in `reporter.py`
- [ ] Update `run()` methods in all three nodes to check `LLM_DISABLED` flag

### Phase 3: Tests (1 session)

- [ ] Write `tests/test_planner_deterministic.py` (~6 tests)
- [ ] Write `tests/test_error_handler_deterministic.py` (~5 tests)
- [ ] Write `tests/test_reporter_deterministic.py` (~6 tests)
- [ ] Run all tests: `pytest -v -n auto -m "not integration"`

### Phase 4: Documentation (½ session)

- [ ] Update `doc/CONFIGURATION.md`
- [ ] Update `README.md`
- [ ] Append to `.history`

### Phase 5: Final Validation (½ session)

- [ ] Test with `.env` file: `LLM_DISABLED=true` + real domain list
- [ ] Verify no LLM API calls occur (check logs)
- [ ] Run integration tests (if available)

---

## 8. Edge Cases & Validation

| Scenario | Expected Behavior |
|----------|-------------------|
| `LLM_DISABLED=true` but `LLM_PROVIDER` not set | Works fine; LLM provider ignored |
| `LLM_DISABLED=true` but `ANTHROPIC_API_KEY` missing | Works fine; no API call attempted |
| Network error in LLM mode | Existing fallback logic (planner retries, reporter uses default) |
| Network error in deterministic mode | N/A — no network calls |
| Max retries exceeded | Skip domain (deterministic); user must manually retry or intervene |
| Empty `MANAGED_DOMAINS` | Renew nothing (consistent with LLM mode) |
| `LLM_DISABLED=true` + `--revoke-cert` | LLM nodes in revocation graph also skip LLM (future work if needed) |

---

## 9. Future Extensions

- [ ] Extend to revocation graph (`revocation_graph.py`)
- [ ] Add domain-level priority hints via config (e.g., `"api.example.com:urgent"`)
- [ ] Add custom retry policy config (e.g., max delay, backoff formula)
- [ ] Add template system for reporter output (plain text, JSON, YAML)

---

## 10. Success Criteria

✅ Agent runs with `LLM_DISABLED=true` without any LLM API calls  
✅ All three nodes have deterministic implementations  
✅ Unit tests pass: `pytest -v -n auto -m "not integration"`  
✅ Integration test passes (if run)  
✅ Documentation is updated and accurate  
✅ Configuration validates correctly  
✅ Backward compatibility: default behavior unchanged (`LLM_DISABLED=false`)  

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Deterministic planner too aggressive (renews everything) | Document use case; operators can tune `RENEWAL_THRESHOLD_DAYS` |
| Retry delays too long | Exponential backoff is standard; 300s cap is reasonable for unattended ops |
| Summary format too plain | Can extend later; deterministic output is auditable by design |
| Operator confusion: LLM vs. deterministic | Clear docs + example `.env`; log messages indicate mode at startup |

