"""
LLM system and user prompts for each LLM node in the agent graph.

All prompts are plain Python strings using .format() placeholders.
"""

# ── renewal_planner ───────────────────────────────────────────────────────────

PLANNER_SYSTEM = """\
You are a TLS Certificate Lifecycle Manager assistant.
Your job is to analyze certificate expiry data and produce a JSON renewal plan.
You must ONLY include domains from the provided domain list — never hallucinate or add extra domains.
Respond with valid JSON only, no markdown fences, no prose."""

PLANNER_USER = """\
I have scanned the following domains and their certificate status:

{cert_summary}

Managed domains (authoritative list — only include these):
{managed_domains}

Classify each managed domain into exactly one category:
- "urgent": expires in < 7 days or already expired
- "routine": expires in 7–{threshold} days
- "skip": healthy (> {threshold} days remaining) or no renewal needed

Return a JSON object with this exact schema:
{{
  "urgent": ["domain1.com"],
  "routine": ["domain2.com"],
  "skip": ["domain3.com"],
  "notes": "Human-readable summary of your reasoning"
}}

Rules:
1. Every managed domain must appear in exactly one list.
2. Order each list most-urgent first.
3. "skip" any domain that is not in the managed_domains list.
"""

# ── error_handler ─────────────────────────────────────────────────────────────

ERROR_HANDLER_SYSTEM = """\
You are diagnosing a TLS certificate renewal failure.
You have deep knowledge of the ACME RFC 8555 protocol and common failure modes.
Respond with valid JSON only, no markdown fences, no prose."""

ERROR_HANDLER_USER = """\
A certificate renewal attempt has failed.

Domain:         {domain}
Error:          {error}
Retry attempt:  {retry_count} of {max_retries}
ACME order status: {order_status}

Decide the best course of action:
- "retry"  — transient issue (DNS propagation, temporary network failure, rate limit — back off and try again)
- "skip"   — this domain cannot be renewed right now but others should continue
- "abort"  — credential failure, CA policy violation, or systemic issue affecting all domains

Respond with exactly:
{{
  "action": "retry|skip|abort",
  "reason": "One sentence explaining your decision",
  "suggested_delay_seconds": <integer, 0 if skip/abort>
}}
"""

# ── summary_reporter ──────────────────────────────────────────────────────────

REPORTER_SYSTEM = """\
You are generating a concise TLS certificate renewal run summary for an operations team.
Be factual and brief. Respond with plain text (no JSON, no markdown headers)."""

REPORTER_USER = """\
Certificate renewal run completed.

Completed renewals:  {completed}
Failed renewals:     {failed}
Skipped (healthy):   {skipped}
Errors logged:
{error_log}

Write a 3–5 sentence summary covering:
1. Overall result (success / partial / failure)
2. Any domains that need immediate operator attention
3. A recommendation for the next check (e.g., "check again tomorrow" or "lower renewal threshold")
"""
