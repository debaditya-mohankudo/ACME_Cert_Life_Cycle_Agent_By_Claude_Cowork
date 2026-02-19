"""
csr_generator node — generate an RSA-2048 private key and CSR for the
current domain, storing the key PEM in the cert directory.
"""
from __future__ import annotations

import logging
from pathlib import Path

from acme.crypto import create_csr, generate_rsa_key, private_key_to_pem
from agent.state import AgentState

logger = logging.getLogger(__name__)


def csr_generator(state: AgentState) -> dict:
    """
    Generate a domain private key and CSR.

    Saves privkey.pem to the cert directory (mode 0o600) so storage_manager
    can find it after finalization.

    Returns updates to: current_order (csr_der stored as hex in state),
                        error_log on failure.
    """
    import os
    import stat

    domain = state["current_domain"]
    if not domain:
        return {"error_log": ["csr_generator called with no current_domain"]}
    cert_store_path = state["cert_store_path"]

    logger.info("Generating RSA-2048 key and CSR for %s", domain)

    domain_key = generate_rsa_key(key_size=2048)
    key_pem = private_key_to_pem(domain_key)

    # Sanitize domain for use as a directory name:
    #   - wildcards: "*.example.com" → "wildcard.example.com"
    #   - strip any path separators to prevent traversal
    safe_domain = domain.replace("*.", "wildcard.").replace("/", "").replace("\\", "")
    key_dir = Path(cert_store_path) / safe_domain
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "privkey.pem"
    key_path.write_text(key_pem, encoding="utf-8")
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    logger.info("Private key written to %s", key_path)

    csr_der = create_csr(domain_key, domain)

    # Store CSR as hex string in the order so it can travel through state
    order = state.get("current_order") or {}
    updated_order = {**order, "csr_der_hex": csr_der.hex()}

    return {"current_order": updated_order}
