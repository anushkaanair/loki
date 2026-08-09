"""Target factory. Applies the authorization gate before building anything."""
from __future__ import annotations

from ..core.config import TargetConfig
from .agent import AgentTarget
from .backends import make_backend
from .base import authorize
from .chat import ChatTarget
from .gandalf import LiveGandalf, LocalGandalf
from .rag import RagTarget


def build_target(cfg: TargetConfig, *, cli_authorized: bool = False, external_scorer=None):
    """Instantiate a target from config, enforcing the authorization gate."""
    authorize(cfg.kind, cfg.authorized or cli_authorized, cfg.name)

    backend = make_backend(cfg.backend, cfg.model, **cfg.extra) if cfg.kind in (
        "chat", "agent", "rag") else None

    # Generation length is a campaign knob: real local models generate
    # token-by-token, so unbounded DoS-style prompts would otherwise dominate
    # runtime. Defaults match the historical values so sim results are unchanged.
    mt = cfg.extra.get("max_tokens")

    if cfg.kind == "chat":
        return ChatTarget(cfg.name, tier=cfg.tier or "tier-0", backend=backend,
                          external_scorer=external_scorer,
                          max_tokens=int(mt) if mt else 400)
    if cfg.kind == "agent":
        # max_steps bounds the tool loop. Each step is a full generation with a
        # context that grows, so it dominates cost against a real model; 2 still
        # covers the fetch->act indirect-injection chain.
        steps = cfg.extra.get("max_steps")
        return AgentTarget(cfg.name, backend=backend,
                           max_steps=int(steps) if steps else 4,
                           max_tokens=int(mt) if mt else 300)
    if cfg.kind == "rag":
        return RagTarget(cfg.name, backend=backend,
                         access_control=bool(cfg.extra.get("access_control", False)),
                         max_tokens=int(mt) if mt else 300)
    if cfg.kind == "gandalf":
        level = int(cfg.extra.get("level", 1))
        if cfg.extra.get("live"):
            return LiveGandalf(level, cfg.name)
        return LocalGandalf(level, cfg.name)
    if cfg.kind == "openai":
        # Generic OpenAI-compatible adapter, wrapped as a chat target so the
        # full attack surface applies. Requires authorization (gate above).
        return ChatTarget(cfg.name, tier=cfg.tier or "tier-0",
                          backend=make_backend("openai", cfg.model, **cfg.extra))
    raise ValueError(f"unknown target kind: {cfg.kind}")


def default_self_built_targets() -> list[TargetConfig]:
    """The built-in benchmark suite: 3 chat tiers + agent + RAG."""
    return [
        TargetConfig(name="chat-tier0", kind="chat", tier="tier-0"),
        TargetConfig(name="chat-tier1", kind="chat", tier="tier-1"),
        TargetConfig(name="chat-tier2", kind="chat", tier="tier-2"),
        TargetConfig(name="agent-target", kind="agent"),
        TargetConfig(name="rag-target", kind="rag"),
    ]
