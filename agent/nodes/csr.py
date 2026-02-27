"""
csr_generator node — generate an RSA private key and CSR (key size from
settings.DOMAIN_KEY_SIZE) for the current domain, storing the key PEM in the
cert directory with atomic writes.

The CSR is DER-encoded (RFC 8555 §7.4 requires DER for POST /finalize) and
stored as a hex string in AgentState so it can be serialised safely through
LangGraph checkpoints.  The private key never enters state.
"""
from __future__ import annotations

from pathlib import Path

import config
from acme.crypto import create_csr, generate_ec_key, generate_rsa_key, private_key_to_pem
from agent.state import AgentState
from storage.atomic import atomic_write_text
from storage.filesystem import sanitize_domain_for_path

from logger import logger


class CsrGeneratorNode:
    """Callable CSR generator implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
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

        key_type = config.settings.KEY_TYPE
        if key_type == "ecc":
            curve_name = config.settings.ECC_CURVE
            logger.info("Generating ECC (%s) key and CSR for %s", curve_name, domain)
            domain_key = generate_ec_key(curve_name=curve_name)
        else:
            key_size = config.settings.DOMAIN_KEY_SIZE
            logger.info("Generating RSA-%d key and CSR for %s", key_size, domain)
            domain_key = generate_rsa_key(key_size=key_size)
        key_pem = private_key_to_pem(domain_key)

        safe_domain = sanitize_domain_for_path(domain)
        key_dir = Path(cert_store_path) / safe_domain
        key_path = key_dir / "privkey.pem"
        atomic_write_text(key_path, key_pem)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        logger.info("Private key written to %s", key_path)

        csr_der = create_csr(domain_key, domain)

        order = state.get("current_order") or {}
        updated_order = {**order, "csr_der_hex": csr_der.hex()}

        return {"current_order": updated_order}


def csr_generator(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `CsrGeneratorNode`."""
    return CsrGeneratorNode().run(state)
