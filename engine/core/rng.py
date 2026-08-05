"""Centralized, seeded randomness.

Every campaign draws from a single seeded generator so that
`same seed + same target config ⟹ same attack sequence`, which is what makes a
finding's replay trustworthy months later. Components ask the campaign for a
named sub-stream rather than importing
the global `random` module, which keeps parallel components independent yet
reproducible.
"""
from __future__ import annotations

import hashlib
import random


class SeededRNG:
    """A named-substream RNG. Deterministic given the root seed."""

    def __init__(self, seed: int):
        self.seed = seed
        self._root = random.Random(seed)
        self._streams: dict[str, random.Random] = {}

    def stream(self, name: str) -> random.Random:
        """A stable, independent sub-generator identified by ``name``."""
        if name not in self._streams:
            h = hashlib.sha256(f"{self.seed}:{name}".encode()).hexdigest()
            self._streams[name] = random.Random(int(h[:16], 16))
        return self._streams[name]

    def choice(self, name: str, seq):
        return self.stream(name).choice(list(seq))

    def random(self, name: str) -> float:
        return self.stream(name).random()
