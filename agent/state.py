"""
Agent state definition for the ACME certificate lifecycle agent.

Key design decisions vs. the original plan:
  - AcmeOrder uses List fields (auth_urls, challenge_urls, etc.) to support
    multi-domain SAN certificates where each domain gets its own authorization.
  - acme_account_key is NOT stored in state (security: would leak into
    LangSmith traces).  The account key is loaded from disk by the account
    node and passed through a secure side-channel (the key path is in state).
  - retry_delay_seconds is included for exponential-backoff logic.
  - cert_metadata stores per-domain metadata dicts populated by storage_manager.
"""
from __future__ import annotations

from typing import Annotated, Dict, List, Optional

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class CertRecord(TypedDict):
    domain: str
    cert_path: Optional[str]          # Path to existing cert.pem (None if not found)
    key_path: Optional[str]           # Path to privkey.pem
    expiry_date: Optional[str]        # ISO-8601 UTC string parsed from cert
    days_until_expiry: Optional[int]  # Computed at scan time
    needs_renewal: bool               # True when < renewal_threshold_days remain


class AcmeOrder(TypedDict):
    """
    Represents one ACME order, potentially covering multiple domains (SANs).

    For a single-domain order:
      auth_urls       = [one auth url]
      challenge_urls  = [one challenge url]
      challenge_tokens = [one token]
      key_authorizations = [one key auth string]

    For a multi-domain SAN order, all lists are parallel (same length).
    """
    order_url: str
    status: str                       # pending | ready | processing | valid | invalid
    auth_urls: List[str]              # One per identifier (domain)
    challenge_urls: List[str]         # HTTP-01 challenge URL per authorization
    challenge_tokens: List[str]       # HTTP-01 token per authorization
    key_authorizations: List[str]     # token + "." + thumbprint per authorization
    finalize_url: str
    certificate_url: Optional[str]    # Set after order is valid


class AgentState(TypedDict):
    # ── Configuration ──────────────────────────────────────────────────────
    managed_domains: List[str]
    renewal_threshold_days: int
    cert_store_path: str
    account_key_path: str             # Path to account private key on disk
    webroot_path: Optional[str]

    # ── Scan results ───────────────────────────────────────────────────────
    cert_records: List[CertRecord]
    pending_renewals: List[str]       # Domains needing renewal, ordered by urgency

    # ── Active ACME flow ───────────────────────────────────────────────────
    current_domain: Optional[str]
    current_order: Optional[AcmeOrder]
    acme_account_url: Optional[str]   # Cached after first registration
    current_nonce: Optional[str]      # Last-used ACME nonce (refreshed each request)

    # ── LLM reasoning ──────────────────────────────────────────────────────
    messages: Annotated[List[BaseMessage], add_messages]
    renewal_plan: Optional[str]       # LLM's JSON renewal strategy
    error_analysis: Optional[str]     # LLM's failure reasoning

    # ── Progress tracking ──────────────────────────────────────────────────
    completed_renewals: List[str]
    failed_renewals: List[str]
    error_log: List[str]
    retry_count: int
    retry_delay_seconds: int          # Current delay; doubles on each retry
    max_retries: int

    # ── Per-domain metadata ────────────────────────────────────────────────
    cert_metadata: Dict[str, dict]    # domain → metadata dict from storage_manager
