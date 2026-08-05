"""Refusal-pattern analysis and routing .

A first-class reasoning step, not a retry counter. Given the history of failed
responses for a lineage, classify *how* it is failing and recommend the next
mutation direction.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.types import Response


@dataclass
class RefusalAnalysis:
    mode: str          # keyword_filter | alignment | dos_signal | partial | unknown
    hint: str          # mutation hint for the mutator
    escalate_dos: bool = False
    exploit_partial: bool = False


def analyze(responses: list[Response], partials: list[bool] | None = None) -> RefusalAnalysis:
    if not responses:
        return RefusalAnalysis("unknown", "add_encoding")

    # Partial compliance is the strongest signal available — intensify.
    if partials and any(partials):
        return RefusalAnalysis("partial", "intensify", exploit_partial=True)

    # Truncated / empty / timeout ⟹ possible DoS.
    if any(r.timed_out or r.truncated or (r.empty and not r.text) for r in responses):
        return RefusalAnalysis("dos_signal", "intensify", escalate_dos=True)

    texts = [r.text.strip() for r in responses if r.text.strip()]
    blocked = [r for r in responses if r.meta.get("blocked_by")]
    if blocked and len(blocked) >= max(1, len(responses) // 2):
        # An input filter is dropping us before the model — obfuscate to bypass.
        return RefusalAnalysis("keyword_filter", "add_encoding")

    if not texts:
        return RefusalAnalysis("unknown", "add_encoding")

    unique = set(texts)
    if len(unique) == 1 and len(texts) >= 2:
        # Identical refusal text ⟹ keyword/pattern filter ⟹ switch to encoding.
        return RefusalAnalysis("keyword_filter", "add_encoding")
    if len(unique) >= max(2, len(texts) // 2):
        # Semantically varied refusals ⟹ model-level alignment ⟹ reframe.
        return RefusalAnalysis("alignment", "switch_persona")
    return RefusalAnalysis("unknown", "add_encoding")
