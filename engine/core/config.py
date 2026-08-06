"""Campaign / budget / target configuration and the run manifest."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yaml  # type: ignore
from pydantic import BaseModel, Field

from .types import config_hash

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts"
DATA = ROOT / "data"


class Budget(BaseModel):
    """Every campaign runs under an explicit budget ."""

    max_calls: int = 2000
    max_wall_clock_s: float = 3600.0
    max_spend_usd: float = 0.0  # local models cost $0; kept for the manifest


class TargetConfig(BaseModel):
    name: str
    kind: str  # chat | agent | rag | gandalf | openai | echo
    tier: str | None = None  # for chat: tier-0 / tier-1 / tier-2
    backend: str = "deterministic"  # deterministic | hf | openai
    model: str | None = None
    authorized: bool = False  # required for non-self-built targets
    extra: dict[str, Any] = Field(default_factory=dict)

    def hash(self) -> str:
        return config_hash(self.model_dump())


class CampaignConfig(BaseModel):
    name: str = "default"
    seed: int = 42
    generations: int = 6
    population_size: int = 24
    concurrency: int = 8
    budget: Budget = Field(default_factory=Budget)
    targets: list[TargetConfig] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)  # empty = all
    owasp_scope: list[str] = Field(default_factory=list)  # empty = all
    reproduction_trials: int = 10
    matrix_trials: int = 10  # fixed trials per (target, family) in the systematic sweep
    seed_from_corpus: bool = False  # seed the population from real-world jailbreak corpora

    @classmethod
    def load(cls, path: str | Path) -> "CampaignConfig":
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)


class RunManifest(BaseModel):
    """Recorded at the start of every campaign for reproducibility ."""

    campaign: str
    seed: int
    started_at: float = Field(default_factory=time.time)
    config_hash: str = ""
    target_hashes: dict[str, str] = Field(default_factory=dict)
    model_versions: dict[str, str] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
