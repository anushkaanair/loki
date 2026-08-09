"""Campaign orchestrator .

Config → scheduling → budget. For each target it runs an adaptive genetic
search across the goals in scope, streams every attempt to the store and to the
live event bus, then hands all successes to the evidence engine for
verification. Fully seeded and reproducible.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Callable

from ..attacker.genetic import GeneticSearch, GenerationStat
from ..attacker.genome import Genome
from ..attacker.techniques import ALL_FAMILIES
from ..evidence.engine import EvidenceEngine
from ..judge.judge import Judge
from .budget import BudgetTracker
from .config import CampaignConfig, RunManifest
from .executor import execute
from .rng import SeededRNG
from .store import Store
from .types import Attempt, Finding, OWASP, Severity, Verdict

# Which goals apply to each target kind.
GOALS_BY_KIND = {
    "chat": ["leak_secret", "leak_system_prompt", "markup_exfil", "injection_marker", "dos"],
    "agent": ["call_delete", "call_email", "leak_secret", "injection_marker"],
    "rag": ["rag_bleed", "leak_secret", "injection_marker"],
    "gandalf": ["leak_secret"],
    "openai": ["leak_secret", "leak_system_prompt", "injection_marker"],
}

# A diverse starter family set per goal (genetic search expands from here).
STARTER_FAMILIES = {
    "call_delete": ["indirect_tool", "direct_override", "authority_reframing"],
    "call_email": ["indirect_tool", "direct_override", "roleplay"],
    "rag_bleed": ["indirect_rag", "direct_override", "authority_reframing"],
    "dos": ["dos_expansion"],
}
_DEFAULT_STARTERS = ["direct_override", "authority_reframing", "roleplay",
                     "encoding_obfuscation", "proper_noun", "context_flooding"]


def matrix_goal(family: str, kind: str) -> str:
    """The natural goal to exercise a (family, target) cell in the systematic
    effectiveness sweep."""
    if family == "dos_expansion":
        return "dos"
    if family == "indirect_tool":
        return "call_delete" if kind == "agent" else "leak_secret"
    if family == "indirect_rag":
        # The poison-doc hijack is proven cleanly via the injection marker; it
        # does not depend on the private canary doc also being retrieved.
        return "injection_marker" if kind == "rag" else "leak_secret"
    if kind == "agent":
        return "call_delete"
    if kind == "rag":
        return "rag_bleed"
    return "leak_secret"


class Orchestrator:
    def __init__(self, cfg: CampaignConfig, store: Store, target_factory,
                 judge: Judge | None = None,
                 on_attempt: Callable[[Attempt], None] | None = None,
                 on_generation: Callable[[str, GenerationStat], None] | None = None,
                 on_progress: Callable[[str, int, int, str], None] | None = None):
        self.cfg = cfg
        self.store = store
        self.target_factory = target_factory  # name -> fresh target
        self.judge = judge or Judge()
        self.on_attempt = on_attempt
        self.on_generation = on_generation
        self.on_progress = on_progress
        self.campaign_id = f"{cfg.name}-{uuid.uuid4().hex[:6]}"
        self.rng = SeededRNG(cfg.seed)
        self.budget = BudgetTracker(cfg.budget.max_calls, cfg.budget.max_wall_clock_s,
                                    cfg.budget.max_spend_usd)
        self._corpus_raw: list[str] = []
        self.corpus_source = "none"
        if cfg.seed_from_corpus:
            try:
                from ..attacker.corpus import load_raw_payloads
                self._corpus_raw, self.corpus_source = load_raw_payloads(n=12, seed=cfg.seed)
            except Exception:
                self._corpus_raw = []

    def _seed_genomes(self, kind: str) -> list[Genome]:
        goals = [g for g in GOALS_BY_KIND.get(kind, ["leak_secret"])
                 if not self.cfg.owasp_scope or
                 Genome(family="direct_override", goal=g).owasp.value in self.cfg.owasp_scope]
        genomes: list[Genome] = []
        allowed = set(self.cfg.techniques) if self.cfg.techniques else None
        for goal in goals:
            fams = STARTER_FAMILIES.get(goal, _DEFAULT_STARTERS)
            for fam in fams:
                if allowed and fam not in allowed:
                    continue
                genomes.append(Genome(family=fam, goal=goal))
        # Seed from real-world jailbreak corpora (P3): mutate from real attacks.
        if self._corpus_raw:
            primary = goals[0] if goals else "leak_secret"
            for raw in self._corpus_raw:
                genomes.append(Genome(family="jailbreak_corpus", goal=primary,
                                      extra={"raw": raw}))
        return genomes or [Genome(family="direct_override", goal="leak_secret")]

    async def run(self) -> list[Finding]:
        manifest = RunManifest(
            campaign=self.cfg.name, seed=self.cfg.seed,
            config_hash=self.cfg.model_dump().__str__()[:0] or "",
            budget=self.budget.as_dict(),
        )
        for tc in self.cfg.targets:
            tgt = self.target_factory(tc.name)
            manifest.target_hashes[tc.name] = tc.hash()
            manifest.model_versions[tc.name] = tgt.model_version()
        manifest_d = manifest.model_dump()
        manifest_d["campaign_config"] = self.cfg.model_dump()  # for replay/report
        self.store.start_campaign(self.campaign_id, self.cfg.name, self.cfg.seed, manifest_d)

        all_successes: list[Attempt] = []
        # ---- Phase 1: systematic effectiveness sweep (every target × family) ----
        all_successes += await self._matrix_sweep()

        # ---- Phase 2: adaptive genetic search (discovery) ----
        for tc in self.cfg.targets:
            target = self.target_factory(tc.name)
            seeds = self._seed_genomes(target.kind)

            async def evaluate(genome: Genome, gen: int, parents: list[str],
                               _t=target) -> Attempt:
                if self.budget.exhausted:
                    return self._skipped(genome, gen, _t)
                self.budget.consume(1)
                att = await execute(_t, genome, self.judge,
                                    campaign_id=self.campaign_id,
                                    campaign_seed=self.cfg.seed, generation=gen,
                                    tag=f"{_t.name}:{gen}:{uuid.uuid4().hex[:4]}",
                                    parents=parents)
                att.genome["phase"] = "adaptive"
                self.store.record_attempt(att)
                if att.verdict and att.verdict.success:
                    all_successes.append(att)
                if self.on_attempt:
                    self.on_attempt(att)
                return att

            search = GeneticSearch(
                evaluate, self.rng.stream(f"ga:{tc.name}"),
                population_size=self.cfg.population_size,
                generations=self.cfg.generations, concurrency=self.cfg.concurrency,
                on_generation=(lambda s, n=tc.name: self.on_generation(n, s))
                              if self.on_generation else None,
            )
            await search.run(seeds)
            self.store.commit()

        # ---- evidence pipeline over all successes ----
        evidence = EvidenceEngine(self.judge, self.target_factory, self.cfg.seed,
                                  self.campaign_id, trials=self.cfg.reproduction_trials)
        findings = await evidence.build_findings(all_successes, on_progress=self.on_progress)
        for f in findings:
            self.store.record_finding(f, self.campaign_id)
        self._record_judge_labels(all_successes)
        self.store.finish_campaign(self.campaign_id)
        return findings

    async def _matrix_sweep(self) -> list[Attempt]:
        """Systematic ASR measurement over every (target × technique family).

        Fixed ``matrix_trials`` per cell with distinct seeds, so the
        technique-vs-defense effectiveness matrix and the headline tier-vs-ASR
        table rest on a balanced sample rather than the genetic search's
        (deliberately skewed) exploration.
        """
        successes: list[Attempt] = []
        allowed = set(self.cfg.techniques) if self.cfg.techniques else None
        families = [f for f in ALL_FAMILIES if not allowed or f in allowed]
        sem = asyncio.Semaphore(self.cfg.concurrency)
        # Progress accounting. Against a real local model a probe costs seconds,
        # so a sweep runs for tens of minutes; commit and report per cell rather
        # than only at the end, or the run is unobservable while it works.
        total_cells = len(self.cfg.targets) * len(families)
        done_cells = {"n": 0}

        async def cell(tc, family):
            target = self.target_factory(tc.name)
            goal = matrix_goal(family, target.kind)
            if self.cfg.owasp_scope:
                if Genome(family=family, goal=goal).owasp.value not in self.cfg.owasp_scope:
                    return []
            out = []
            for t in range(self.cfg.matrix_trials):
                if self.budget.exhausted:
                    break
                async with sem:
                    self.budget.consume(1)
                    g = Genome(family=family, goal=goal)
                    att = await execute(self.target_factory(tc.name), g, self.judge,
                                        campaign_id=self.campaign_id,
                                        campaign_seed=self.cfg.seed, generation=-2,
                                        tag=f"matrix:{tc.name}:{family}:{t}")
                att.genome["phase"] = "matrix"
                self.store.record_attempt(att)
                if att.verdict and att.verdict.success:
                    out.append(att)
                if self.on_attempt:
                    self.on_attempt(att)
            # Durably persist each cell so progress is inspectable mid-run.
            self.store.commit()
            done_cells["n"] += 1
            if self.on_progress:
                self.on_progress("matrix", done_cells["n"], total_cells,
                                 f"{tc.name}/{family}")
            return out

        tasks = [cell(tc, fam) for tc in self.cfg.targets for fam in families]
        for res in await asyncio.gather(*tasks):
            successes += res
        self.store.commit()
        return successes

    def _record_judge_labels(self, successes: list[Attempt]) -> None:
        # Persist per-attempt signals for the agreement metric (report computes κ).
        for a in self.store.attempts(self.campaign_id):
            if not a.verdict:
                continue
            s = a.verdict.judge_signals
            self.store.record_judge_label(
                self.campaign_id, a.id,
                canary=(1 if s.canary else 0) if s.canary is not None else None,
                classifier=s.classifier,
                llm_judge=s.llm_judge,
                blob={"success": a.verdict.success, "partial": a.verdict.partial,
                      "target": a.target, "tripwire": bool(s.tripwire)},
            )

    def _skipped(self, genome: Genome, gen: int, target) -> Attempt:
        return Attempt(
            id=uuid.uuid4().hex[:12], campaign_id=self.campaign_id, generation=gen,
            target=target.name, technique_family=genome.family, owasp_category=genome.owasp,
            prompt_messages=[], seed=self.cfg.seed, genome=genome.to_dict(),
            verdict=Verdict(success=False, confidence=0.0, owasp_category=genome.owasp,
                            severity=Severity.LOW, technique_family=genome.family,
                            rationale="skipped: budget exhausted"),
        )
