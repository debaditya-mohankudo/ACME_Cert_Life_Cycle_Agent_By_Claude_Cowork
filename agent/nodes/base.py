"""Tiny structural contract for callable graph nodes."""
from __future__ import annotations

from typing import Protocol

from agent.state import AgentState


class NodeCallable(Protocol):
    """Structural contract for node instances accepted by graph registration."""

    def __call__(self, state: AgentState) -> dict:
        """Execute node logic and return partial state updates."""
        ...
