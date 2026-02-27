"""
LLM system and user prompts for each LLM node in the agent graph.

All prompts are plain Python strings using .format() placeholders.
"""

# ── renewal_planner ───────────────────────────────────────────────────────────

PLANNER_SYSTEM = """\
You are a TLS Certificate Lifecycle Manager assistant. Produce a JSON renewal
plan for the supplied managed domains only. Output valid JSON only — no
prose, no markdown fences, no extra domains."""

PLANNER_USER = """\
Cert summary:
{cert_summary}

Managed domains (authoritative):
{managed_domains}

For each managed domain assign exactly one label:
- "urgent": expires in < 7 days or already expired
- "routine": expires in 7–{threshold} days
- "skip": >= {threshold} days

Return one JSON object with keys: "urgent", "routine", "skip", "notes".
Requirements: every managed domain appears exactly once; lists ordered by
urgency (most urgent first); emit no extra keys or prose."""

# ── error_handler ─────────────────────────────────────────────────────────────

ERROR_HANDLER_SYSTEM = """\
You diagnose TLS renewal failures. Use ACME RFC 8555 knowledge and common
failure modes. Output valid JSON only — no prose or markdown."""

ERROR_HANDLER_USER = """\
Renewal failed.
Domain: {domain}
Error: {error}
Retry: {retry_count}/{max_retries}
Order status: {order_status}

Choose one action: "retry", "skip", or "abort".
Return exactly:
{{
  "action": "retry|skip|abort",
  "reason": "One-sentence rationale",
  "suggested_delay_seconds": <integer, 0 if skip/abort>
}}
"""

# ── summary_reporter ──────────────────────────────────────────────────────────

REPORTER_SYSTEM = """\
Generate a concise operations summary of a TLS renewal run. Be factual,
brief, and use plain text only (no JSON, no markdown)."""

REPORTER_USER = """\
Certificate renewal run completed.

Completed: {completed}
Failed:    {failed}
Skipped:   {skipped}
Errors:
{error_log}

Write 3–5 sentences covering: overall result (success/partial/failure), any
domains needing immediate attention, and a recommended next check or action.
"""

# ── revocation_reporter ────────────────────────────────────────────────────

REVOCATION_REPORTER_USER = """\
Certificate revocation run completed.

Revoked: {revoked}
Failed:  {failed}
Reason:  {reason}
Errors:
{error_log}

Write 2–4 sentences: overall result, failures needing operator attention, and
whether a renewal cycle should follow.
"""
