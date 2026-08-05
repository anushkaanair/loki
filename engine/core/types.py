"""Core data model shared across every Loki component.

These types are the contract between the attacker, the targets, the judge, and
the evidence engine. Keep them small, serializable, and free of behavior.
"""
from __future__ import annotations

import enum
import hashlib
import json
import time
from typing import Any

from pydantic import BaseModel, Field


class OWASP(str, enum.Enum):
    """The five OWASP-LLM categories Loki tests ."""

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Insecure Output Handling
    LLM04 = "LLM04"  # Model Denial of Service
    LLM06 = "LLM06"  # Sensitive Information Disclosure
    LLM08 = "LLM08"  # Excessive Agency

    @property
    def title(self) -> str:
        return {
            "LLM01": "Prompt Injection",
            "LLM02": "Insecure Output Handling",
            "LLM04": "Model Denial of Service",
            "LLM06": "Sensitive Information Disclosure",
            "LLM08": "Excessive Agency",
        }[self.value]


class Severity(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}[self.value]


class Role(str, enum.Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Message(BaseModel):
    role: Role
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"role": self.role.value, "content": self.content}


class ToolCall(BaseModel):
    """A tool invocation emitted by an agent target. Logged verbatim."""

    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None


class Response(BaseModel):
    """What a target returns for one query.

    `truncated`, `empty`, and `timed_out` are first-class so the refusal
    analyzer and the LLM04 (DoS) probes can reason about failure *modes*, not
    just presence/absence of text.
    """

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    latency_s: float = 0.0
    truncated: bool = False
    empty: bool = False
    timed_out: bool = False
    error: str | None = None
    # Free-form target-side signal (e.g. canary triggers, retrieved doc ids).
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_error_like(self) -> bool:
        return self.timed_out or self.error is not None or (self.empty and not self.text)


class JudgeSignals(BaseModel):
    """Raw output of each independent judge signal for one attempt."""

    canary: bool | None = None            # deterministic oracle: exact-match ground truth
    tripwire: str | None = None           # deterministic oracle: tool tripwire detail
    classifier: float | None = None       # trained model P(injection-success)
    llm_judge: str | None = None          # "success" / "failure" / "partial"
    llm_judge_rationale: str | None = None
    heuristic: float | None = None        # cheap lexical fallback score


class Verdict(BaseModel):
    """The judge's decision for a single attempt."""

    success: bool
    confidence: float
    owasp_category: OWASP
    severity: Severity
    technique_family: str
    judge_signals: JudgeSignals = Field(default_factory=JudgeSignals)
    rationale: str = ""
    partial: bool = False  # partial compliance — strongest mutation signal


class Attempt(BaseModel):
    """One generate→execute→classify unit. The atom of a campaign."""

    id: str
    campaign_id: str
    generation: int
    target: str
    technique_family: str
    owasp_category: OWASP
    prompt_messages: list[Message]
    response: Response | None = None
    verdict: Verdict | None = None
    fitness: float = 0.0
    parent_ids: list[str] = Field(default_factory=list)
    seed: int = 0
    created_at: float = Field(default_factory=time.time)
    # The genome that produced this attempt (technique + mutation stack).
    genome: dict[str, Any] = Field(default_factory=dict)

    @property
    def payload(self) -> str:
        """The last user/tool-injected message — the 'successful payload'."""
        for m in reversed(self.prompt_messages):
            if m.role in (Role.USER, Role.TOOL):
                return m.content
        return self.prompt_messages[-1].content if self.prompt_messages else ""


class Reproduction(BaseModel):
    trials: int
    successes: int
    rate: float
    ci_95: tuple[float, float]
    status: str  # CONFIRMED / INTERMITTENT / FLAKE


class Finding(BaseModel):
    """A verified, provable finding — the evidence bundle the evidence pipeline produces."""

    finding_id: str
    owasp_category: OWASP
    severity: Severity
    target: dict[str, Any]
    technique_family: str
    discovered_at: str
    reproduction: Reproduction
    transcript: list[dict[str, str]]
    proof: dict[str, Any]
    judge_signals: JudgeSignals
    replay: str
    seed: int
    variant_count: int = 1
    representative_attempt_id: str = ""


def config_hash(obj: Any) -> str:
    """Stable short hash of a target/campaign config for the evidence bundle."""
    blob = json.dumps(obj, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:12]
