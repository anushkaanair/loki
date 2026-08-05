"""Build a name→fresh-target factory from a list of target configs.

Centralized so the orchestrator, the evidence engine (reproduction), and
`loki replay` all reconstruct identical targets. Optionally wires the trained
classifier into tier-2's input filter, so a real model helps defend.
"""
from __future__ import annotations

from ..targets.registry import build_target
from .config import TargetConfig


def make_factory(target_configs: list[TargetConfig], *, cli_authorized: bool = False,
                 use_trained_scorer: bool = True):
    by_name = {tc.name: tc for tc in target_configs}
    external_scorer = None
    if use_trained_scorer:
        try:
            from ..judge.classifier import InjectionClassifier
            clf = InjectionClassifier()
            if clf.is_trained:
                external_scorer = clf.score
        except Exception:
            external_scorer = None

    def factory(name: str):
        cfg = by_name.get(name)
        if cfg is None:
            raise KeyError(f"unknown target '{name}' in this campaign")
        return build_target(cfg, cli_authorized=cli_authorized,
                            external_scorer=external_scorer)

    return factory
