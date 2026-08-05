"""Explicit campaign budget tracking .

An attack success rate is meaningless without knowing how many attempts bought
it, so every probe is counted and the report states the budget that produced the
results.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class BudgetTracker:
    max_calls: int
    max_wall_clock_s: float
    max_spend_usd: float = 0.0
    calls: int = 0
    spend_usd: float = 0.0
    started_at: float = field(default_factory=time.time)

    def consume(self, calls: int = 1, spend: float = 0.0) -> None:
        self.calls += calls
        self.spend_usd += spend

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    @property
    def exhausted(self) -> bool:
        return (self.calls >= self.max_calls
                or self.elapsed_s >= self.max_wall_clock_s
                or (self.max_spend_usd > 0 and self.spend_usd >= self.max_spend_usd))

    def as_dict(self) -> dict:
        return {"max_calls": self.max_calls, "calls_used": self.calls,
                "max_wall_clock_s": self.max_wall_clock_s,
                "wall_clock_used_s": round(self.elapsed_s, 2),
                "max_spend_usd": self.max_spend_usd, "spend_usd": self.spend_usd}
