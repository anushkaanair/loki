"""Shared attempt execution: render → plant → query → judge → score.

Used by the orchestrator (genetic search) *and* the evidence engine
(reproduction + replay), so a finding is verified through exactly the same code
path that discovered it. The ``seed_salt`` fully determines the simulated
target's behavior, which is what makes replay deterministic.
"""
from __future__ import annotations

import hashlib
import uuid

from ..attacker.genome import Genome
from ..attacker.techniques import render
from ..judge.judge import Judge
from .types import Attempt, Message, Role


def make_seed_salt(campaign_seed: int, genome: Genome, tag: str) -> str:
    sig = f"{campaign_seed}|{genome.family}|{genome.goal}|{genome.encoding}|" \
          f"{genome.prefix}|{genome.suffix}|{genome.phrasing}|{tag}"
    return hashlib.sha256(sig.encode()).hexdigest()[:16]


async def execute(target, genome: Genome, judge: Judge, *, campaign_id: str,
                  campaign_seed: int, generation: int, tag: str,
                  parents: list[str] | None = None,
                  seed_salt: str | None = None) -> Attempt:
    """Run one attempt. If ``seed_salt`` is given (replay), it is used verbatim."""
    messages, plant = render(genome)
    salt = seed_salt or make_seed_salt(campaign_seed, genome, tag)

    # Fresh target state, then plant any indirect-injection content.
    target.reset()
    if plant is not None:
        if plant.channel == "url" and hasattr(target, "plant_url"):
            target.plant_url(plant.url, plant.content)
        elif plant.channel == "doc" and hasattr(target, "plant_document"):
            target.plant_document(plant.content, owner=plant.owner)

    response = await target.query(messages, seed_salt=salt, family=genome.family)

    attempt = Attempt(
        id=str(uuid.uuid4())[:12],
        campaign_id=campaign_id,
        generation=generation,
        target=target.name,
        technique_family=genome.family,
        owasp_category=genome.owasp,
        prompt_messages=messages,
        response=response,
        parent_ids=parents or [],
        seed=campaign_seed,
        genome={**genome.to_dict(), "seed_salt": salt},
    )
    attempt.verdict = await judge.judge(attempt, target.kind)
    return attempt
