"""
Node registry for centralized node management.

The registry maps node names to their callable classes or functions.
The factory function instantiates classes and returns functions as-is.
"""
from __future__ import annotations

from agent.nodes.account import AcmeAccountSetupNode
from agent.nodes.challenge import ChallengeSetupNode, ChallengeVerifierNode
from agent.nodes.csr import CsrGeneratorNode
from agent.nodes.error_handler import ErrorHandlerNode
from agent.nodes.finalizer import CertDownloaderNode, OrderFinalizerNode
from agent.nodes.order import OrderInitializerNode
from agent.nodes.planner import RenewalPlannerNode
from agent.nodes.reporter import RevocationReporterNode, SummaryReporterNode
from agent.nodes.retry_scheduler import RetrySchedulerNode
from agent.nodes.revocation_router import (
    pick_next_revocation_domain,
    revocation_loop_router,
)
from agent.nodes.router import pick_next_domain
from agent.nodes.revoker import CertRevokerNode
from agent.nodes.scanner import CertificateScannerNode
from agent.nodes.storage import StorageManagerNode


# Registry maps node name → callable class or function
NODE_REGISTRY = {
    # Renewal graph nodes
    "certificate_scanner": CertificateScannerNode,
    "renewal_planner": RenewalPlannerNode,
    "acme_account_setup": AcmeAccountSetupNode,
    "pick_next_domain": pick_next_domain,
    "order_initializer": OrderInitializerNode,
    "challenge_setup": ChallengeSetupNode,
    "challenge_verifier": ChallengeVerifierNode,
    "csr_generator": CsrGeneratorNode,
    "order_finalizer": OrderFinalizerNode,
    "cert_downloader": CertDownloaderNode,
    "storage_manager": StorageManagerNode,
    "error_handler": ErrorHandlerNode,
    "retry_scheduler": RetrySchedulerNode,
    "summary_reporter": SummaryReporterNode,
    # Revocation graph nodes
    "revocation_account_setup": AcmeAccountSetupNode,
    "pick_next_revocation_domain": pick_next_revocation_domain,
    "cert_revoker": CertRevokerNode,
    "revocation_reporter": RevocationReporterNode,
}


def get_node(name: str):
    """
    Factory: instantiate node callable by name.

    Classes are instantiated; functions are returned as-is.

    Args:
        name: Node name from NODE_REGISTRY

    Returns:
        Callable node instance or function

    Raises:
        KeyError: If node name not in registry
    """
    node_cls_or_fn = NODE_REGISTRY[name]
    # Classes need instantiation, functions don't
    return node_cls_or_fn() if isinstance(node_cls_or_fn, type) else node_cls_or_fn
