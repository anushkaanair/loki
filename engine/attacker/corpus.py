"""Seed the genetic population from real-world jailbreak corpora.

Mutating from real, in-the-wild jailbreak prompts gives the search a far stronger
starting population than hand-written templates alone. Uses public, already-
released research datasets only (same sourcing discipline as the classifier): no
data is scraped from any live system.

Sources tried in order (first that loads wins); the one used is recorded so the
report can state it:
  1. TrustAIRLab/in-the-wild-jailbreak-prompts  (the "Do Anything Now" corpus)
  2. rubend18/ChatGPT-Jailbreak-Prompts
  3. jayavibhav/prompt-injection                (fallback, already cached)
"""
from __future__ import annotations

import random

from .genome import Genome

_SOURCES = [
    ("TrustAIRLab/in-the-wild-jailbreak-prompts", "jailbreak_2023_12_25", ("prompt",)),
    ("rubend18/ChatGPT-Jailbreak-Prompts", None, ("Prompt", "prompt")),
    ("jayavibhav/prompt-injection", None, ("text", "prompt")),
]


def load_raw_payloads(n: int = 12, seed: int = 42) -> tuple[list[str], str]:
    """Return raw jailbreak prompt strings + the dataset name actually used."""
    from datasets import load_dataset

    rng = random.Random(seed)
    for name, config, text_cols in _SOURCES:
        try:
            ds = load_dataset(name, config, split="train") if config else \
                load_dataset(name, split="train")
        except Exception:
            continue
        cols = set(ds.column_names)
        col = next((c for c in text_cols if c in cols), None)
        if not col:
            continue
        texts = []
        for r in ds:
            t = r.get(col)
            if not t:
                continue
            if name.endswith("prompt-injection") and r.get("label") not in (1, "1", True):
                continue
            t = str(t).strip()
            if 20 <= len(t) <= 800:
                texts.append(t)
            if len(texts) >= 2000:
                break
        if texts:
            return rng.sample(texts, min(n, len(texts))), name
    return [], "none"


def load_jailbreak_seeds(goal: str = "leak_secret", n: int = 12,
                         seed: int = 42) -> tuple[list[Genome], str]:
    """Return raw-payload seed genomes + the dataset name actually used."""
    from datasets import load_dataset

    rng = random.Random(seed)
    for name, config, text_cols in _SOURCES:
        try:
            ds = load_dataset(name, config, split="train") if config else \
                load_dataset(name, split="train")
        except Exception:
            continue
        cols = set(ds.column_names)
        col = next((c for c in text_cols if c in cols), None)
        if not col:
            continue
        texts = []
        for r in ds:
            t = r.get(col)
            if not t:
                continue
            # For the injection dataset, keep only positive (injection) rows.
            if name.endswith("prompt-injection") and r.get("label") not in (1, "1", True):
                continue
            t = str(t).strip()
            if 20 <= len(t) <= 800:   # usable, not truncated giants
                texts.append(t)
            if len(texts) >= 2000:
                break
        if not texts:
            continue
        picks = rng.sample(texts, min(n, len(texts)))
        seeds = [Genome(family="jailbreak_corpus", goal=goal, extra={"raw": p}) for p in picks]
        return seeds, name
    return [], "none"
