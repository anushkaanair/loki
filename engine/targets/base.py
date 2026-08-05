"""Target adapter interface + the authorization gate.

Every target the engine can attack implements ``TargetAdapter.query``. The
authorization gate is real, enforced code : any target that is not a
built-in self-built sandbox must be explicitly attested as authorized, or the
engine refuses to run it.
"""
from __future__ import annotations

from typing import Any

from ..core.types import Message, Response

# Self-built sandbox targets are always safe to attack — they have no
# real-world effect and exist for exactly this purpose.
SELF_BUILT_KINDS = {"chat", "agent", "rag", "echo"}


class AuthorizationError(RuntimeError):
    pass


class TargetAdapter:
    """Pluggable target. ``kind`` drives the authorization gate."""

    kind: str = "base"

    def __init__(self, name: str, tier: str | None = None):
        self.name = name
        self.tier = tier

    async def query(self, messages: list[Message], **kwargs: Any) -> Response:
        raise NotImplementedError

    def reset(self) -> None:
        """Re-initialize per-attempt state (tripwire logs, retriever, etc.).

        The evidence engine re-inits a *fresh* target between reproduction
        trials; this is that hook.
        """

    def config(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "tier": self.tier}

    def model_version(self) -> str:
        return "n/a"


def authorize(kind: str, authorized: bool, name: str) -> None:
    """Enforce the authorization gate. Raises unless allowed."""
    if kind in SELF_BUILT_KINDS:
        return
    if kind == "gandalf":
        # Gandalf is a public, intentionally-vulnerable CTF explicitly built to
        # be attacked; permitted as a regression gate.
        return
    if not authorized:
        raise AuthorizationError(
            f"Target '{name}' (kind={kind}) is not a self-built sandbox. "
            f"Re-run with --i-am-authorized-to-test-this to attest you are "
            f"authorized to test it, or set authorized: true in the campaign config."
        )
