"""The adaptive genetic search .

generate → execute → classify → mutate, with elitism, tournament selection,
crossover, explicit diversity pressure, and refusal-pattern routing. Records a
fitness-over-generations curve so the "adaptive" claim is visible in the
dashboard.

The loop is target- and judge-agnostic: it is handed an async ``evaluate``
callback that renders a genome, queries the target, judges the result, and
returns a scored ``Attempt``.
"""
from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..core.types import Attempt
from .fitness import apply_diversity
from .genome import Genome
from .mutations import crossover, mutate
from .refusal import analyze

EvaluateFn = Callable[[Genome, int, list[str]], Awaitable[Attempt]]


@dataclass
class GenerationStat:
    generation: int
    best_fitness: float
    mean_fitness: float
    n_success: int
    n_partial: int
    refusal_modes: dict[str, str] = field(default_factory=dict)


class GeneticSearch:
    def __init__(self, evaluate: EvaluateFn, rng: random.Random, *,
                 population_size: int = 24, generations: int = 6,
                 elitism: int = 4, concurrency: int = 8,
                 on_attempt: Callable[[Attempt], None] | None = None,
                 on_generation: Callable[[GenerationStat], None] | None = None):
        self.evaluate = evaluate
        self.rng = rng
        self.population_size = population_size
        self.generations = generations
        self.elitism = elitism
        self.sem = asyncio.Semaphore(concurrency)
        self.on_attempt = on_attempt
        self.on_generation = on_generation
        self.history: list[GenerationStat] = []
        self.all_attempts: list[Attempt] = []

    async def _eval_one(self, g: Genome, gen: int, parents: list[str]) -> tuple[Genome, Attempt]:
        async with self.sem:
            attempt = await self.evaluate(g, gen, parents)
        if self.on_attempt:
            self.on_attempt(attempt)
        self.all_attempts.append(attempt)
        return g, attempt

    async def run(self, seed_genomes: list[Genome]) -> list[Attempt]:
        # Fill the population from the seeds, cycling if needed. Never truncate
        # below the seed count — every seeded (family, goal) must be evaluated.
        pop_size = max(self.population_size, len(seed_genomes))
        population: list[Genome] = list(seed_genomes)
        while len(population) < pop_size:
            population.append(self.rng.choice(seed_genomes).clone())
        population = population[:pop_size]
        self.population_size = pop_size
        parents_map: dict[int, list[str]] = defaultdict(list)

        for gen in range(self.generations):
            results = await asyncio.gather(*[
                self._eval_one(g, gen, parents_map.get(id(g), [])) for g in population
            ])
            genomes = [g for g, _ in results]
            attempts = [a for _, a in results]
            apply_diversity(attempts, genomes)

            fits = [a.fitness for a in attempts]
            n_succ = sum(1 for a in attempts if a.verdict and a.verdict.success)
            n_part = sum(1 for a in attempts if a.verdict and a.verdict.partial)

            # Refusal routing: one analysis per goal from that goal's failures.
            hints: dict[str, str] = {}
            modes: dict[str, str] = {}
            by_goal: dict[str, list[Attempt]] = defaultdict(list)
            for g, a in zip(genomes, attempts):
                if not (a.verdict and a.verdict.success):
                    by_goal[g.goal].append(a)
            for goal, ats in by_goal.items():
                ra = analyze([a.response for a in ats if a.response],
                             [bool(a.verdict and a.verdict.partial) for a in ats])
                hints[goal] = ra.hint
                modes[goal] = ra.mode

            stat = GenerationStat(gen, max(fits, default=0.0),
                                  sum(fits) / len(fits) if fits else 0.0,
                                  n_succ, n_part, modes)
            self.history.append(stat)
            if self.on_generation:
                self.on_generation(stat)

            if gen == self.generations - 1:
                break

            # ---- selection + reproduction ----
            ranked = sorted(zip(genomes, attempts), key=lambda x: x[1].fitness, reverse=True)
            elites = [g for g, _ in ranked[:self.elitism]]
            next_pop: list[Genome] = [e.clone() for e in elites]
            new_parents: dict[int, list[str]] = {}

            while len(next_pop) < self.population_size:
                if self.rng.random() < 0.35 and len(ranked) >= 2:
                    pa = self._tournament(ranked)
                    pb = self._tournament(ranked)
                    child = crossover(pa[0], pb[0], self.rng)
                    parents = [pa[1].id, pb[1].id]
                else:
                    parent = self._tournament(ranked)
                    child = mutate(parent[0], self.rng, hints.get(parent[0].goal))
                    parents = [parent[1].id]
                new_parents[id(child)] = parents
                next_pop.append(child)

            population = next_pop
            parents_map = defaultdict(list, new_parents)

        return self.all_attempts

    def _tournament(self, ranked, k: int = 3):
        contenders = self.rng.sample(ranked, min(k, len(ranked)))
        return max(contenders, key=lambda x: x[1].fitness)
