"""
ACME Certificate Lifecycle Agent — CLI entry point.

Usage:
  python main.py --once                 # Run one renewal cycle immediately
  python main.py --schedule             # Run on the configured schedule (default 06:00 UTC)
  python main.py --once --checkpoint    # Run with MemorySaver checkpointing
  python main.py --domains a.com b.com  # Override managed domains for this run
"""
from __future__ import annotations

import argparse
import logging
import sys

import structlog

# ── Logging setup ─────────────────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Agent runner ──────────────────────────────────────────────────────────────


def run_once(domains: list[str] | None = None, use_checkpoint: bool = False) -> dict:
    """Execute one full certificate lifecycle cycle and return final state."""
    from agent.graph import build_graph, initial_state
    from config import settings

    effective_domains = domains or settings.MANAGED_DOMAINS
    if not effective_domains:
        log.error("No managed domains configured. Set MANAGED_DOMAINS in .env or pass --domains.")
        sys.exit(1)

    _required_keys = {"anthropic": settings.ANTHROPIC_API_KEY, "openai": settings.OPENAI_API_KEY}
    if settings.LLM_PROVIDER in _required_keys and not _required_keys[settings.LLM_PROVIDER]:
        log.error(
            "%s_API_KEY is not set for LLM_PROVIDER=%r. Add it to .env.",
            settings.LLM_PROVIDER.upper(),
            settings.LLM_PROVIDER,
        )
        sys.exit(1)

    log.info("Starting certificate lifecycle agent for %d domain(s): %s",
             len(effective_domains), ", ".join(effective_domains))

    graph = build_graph(use_checkpointing=use_checkpoint)
    state = initial_state(
        managed_domains=effective_domains,
        cert_store_path=settings.CERT_STORE_PATH,
        account_key_path=settings.ACCOUNT_KEY_PATH,
        renewal_threshold_days=settings.RENEWAL_THRESHOLD_DAYS,
        max_retries=settings.MAX_RETRIES,
        webroot_path=settings.WEBROOT_PATH,
    )

    config = {"configurable": {"thread_id": "main"}} if use_checkpoint else {}

    final_state = graph.invoke(state, config=config)

    completed = final_state.get("completed_renewals", [])
    failed = final_state.get("failed_renewals", [])
    log.info("Run complete — renewed: %s | failed: %s", completed or "none", failed or "none")

    return final_state


def run_revocation(domains: list[str], reason: int = 0, use_checkpoint: bool = False) -> dict:
    """Execute a certificate revocation run and return final state."""
    from agent.revocation_graph import build_revocation_graph, revocation_initial_state
    from config import settings

    # Validate reason code
    if reason not in {0, 1, 4, 5}:
        log.error("Invalid revocation reason %d. Must be one of: 0, 1, 4, 5", reason)
        sys.exit(1)

    if not domains:
        log.error("No domains specified for revocation.")
        sys.exit(1)

    # Warn about unmanaged domains (informational only)
    managed = set(settings.MANAGED_DOMAINS)
    unmanaged = [d for d in domains if d not in managed]
    if unmanaged:
        log.warning("Revoking unmanaged domains: %s", ", ".join(unmanaged))

    _required_keys = {"anthropic": settings.ANTHROPIC_API_KEY, "openai": settings.OPENAI_API_KEY}
    if settings.LLM_PROVIDER in _required_keys and not _required_keys[settings.LLM_PROVIDER]:
        log.error(
            "%s_API_KEY is not set for LLM_PROVIDER=%r. Add it to .env.",
            settings.LLM_PROVIDER.upper(),
            settings.LLM_PROVIDER,
        )
        sys.exit(1)

    log.info("Starting revocation run for %d domain(s): %s (reason=%d)",
             len(domains), ", ".join(domains), reason)

    graph = build_revocation_graph(use_checkpointing=use_checkpoint)
    state = revocation_initial_state(
        domains=domains,
        reason=reason,
        cert_store_path=settings.CERT_STORE_PATH,
        account_key_path=settings.ACCOUNT_KEY_PATH,
    )

    config = {"configurable": {"thread_id": "revocation"}} if use_checkpoint else {}

    final_state = graph.invoke(state, config=config)

    revoked = final_state.get("revoked_domains", [])
    failed = final_state.get("failed_revocations", [])
    log.info("Revocation run complete — revoked: %s | failed: %s", revoked or "none", failed or "none")

    return final_state


def run_scheduled(domains: list[str] | None = None, use_checkpoint: bool = False) -> None:
    """Run the agent on a recurring schedule."""
    import schedule
    import time
    from config import settings

    schedule_time = settings.SCHEDULE_TIME
    log.info("Scheduling daily certificate check at %s UTC", schedule_time)

    def job() -> None:
        log.info("Scheduled run triggered")
        try:
            run_once(domains=domains, use_checkpoint=use_checkpoint)
        except Exception as exc:
            log.exception("Scheduled run failed: %s", exc)

    schedule.every().day.at(schedule_time).do(job)

    log.info("Running initial check immediately...")
    job()

    log.info("Entering schedule loop — press Ctrl+C to stop")
    while True:
        schedule.run_pending()
        time.sleep(60)


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ACME Certificate Lifecycle Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --once
  python main.py --schedule
  python main.py --once --domains api.example.com shop.example.com
  python main.py --once --checkpoint
  python main.py --revoke-cert example.com api.example.com
  python main.py --revoke-cert example.com --reason 4
        """,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one renewal cycle immediately and exit",
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Run on the configured daily schedule (SCHEDULE_TIME in .env)",
    )
    parser.add_argument(
        "--revoke-cert",
        nargs="+",
        metavar="DOMAIN",
        help="Revoke certificates for one or more domains",
    )
    parser.add_argument(
        "--reason",
        type=int,
        default=0,
        metavar="CODE",
        help="RFC 5280 revocation reason code (default: 0=unspecified; also: 1=keyCompromise, 4=superseded, 5=cessationOfOperation)",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        metavar="DOMAIN",
        help="Override managed domains for renewal run",
    )
    parser.add_argument(
        "--checkpoint",
        action="store_true",
        help="Enable MemorySaver checkpointing for resumable runs",
    )

    args = parser.parse_args()

    if not args.once and not args.schedule and not args.revoke_cert:
        parser.print_help()
        sys.exit(1)

    if args.revoke_cert:
        run_revocation(domains=args.revoke_cert, reason=args.reason, use_checkpoint=args.checkpoint)
    elif args.once:
        run_once(domains=args.domains, use_checkpoint=args.checkpoint)
    elif args.schedule:
        run_scheduled(domains=args.domains, use_checkpoint=args.checkpoint)


if __name__ == "__main__":
    main()
