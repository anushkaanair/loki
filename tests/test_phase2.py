"""Phase-2 tests: CLI end-to-end, budget enforcement, backend parity,
live-target guardrails, and Loki's own security surface ."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# CLI end-to-end (subprocess, clean state)
# ---------------------------------------------------------------------------

def test_cli_end_to_end(tmp_path):
    """`loki run` then `loki report` as real subprocesses → exit 0 + report file."""
    cfg = tmp_path / "tiny.yaml"
    cfg.write_text(
        "name: e2e\nseed: 1\ngenerations: 2\npopulation_size: 8\nconcurrency: 6\n"
        "matrix_trials: 4\nreproduction_trials: 4\n"
        "budget: {max_calls: 600, max_wall_clock_s: 120}\n"
        "targets:\n"
        "  - {name: chat-tier0, kind: chat, tier: tier-0}\n"
        "  - {name: agent-target, kind: agent}\n")
    db = tmp_path / "e2e.db"
    env = {"TOKENIZERS_PARALLELISM": "false", "PATH": __import__("os").environ["PATH"]}
    r = subprocess.run([sys.executable, "-m", "cli.main", "run", str(cfg), "--db", str(db)],
                       cwd=ROOT, capture_output=True, text=True, env=env, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    out = tmp_path / "rep"
    r2 = subprocess.run([sys.executable, "-m", "cli.main", "report", "--db", str(db),
                         "--out", str(out)], cwd=ROOT, capture_output=True, text=True,
                        env=env, timeout=120)
    assert r2.returncode == 0, r2.stderr[-2000:]
    assert out.with_suffix(".html").exists()


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------

async def test_budget_enforcement_stops_the_run(tmp_path):
    from engine.core.budget import BudgetTracker
    from engine.core.config import Budget, CampaignConfig
    from engine.core.factory import make_factory
    from engine.core.orchestrator import Orchestrator
    from engine.core.store import Store
    from engine.targets.registry import default_self_built_targets

    cfg = CampaignConfig(name="budget", seed=1, generations=3, population_size=12,
                         concurrency=4, matrix_trials=10,
                         budget=Budget(max_calls=20, max_wall_clock_s=120),
                         targets=default_self_built_targets())
    store = Store(tmp_path / "b.db")
    orch = Orchestrator(cfg, store, make_factory(cfg.targets))
    await orch.run()
    # Real queries are gated by the budget; allow only a small concurrency overshoot.
    assert orch.budget.calls <= cfg.budget.max_calls + cfg.concurrency
    assert orch.budget.exhausted


def test_budget_tracker_flags_exhaustion():
    from engine.core.budget import BudgetTracker
    b = BudgetTracker(max_calls=5, max_wall_clock_s=999)
    for _ in range(5):
        assert not b.exhausted
        b.consume(1)
    assert b.exhausted


# ---------------------------------------------------------------------------
# Backend parity — same config runs across backends without code changes
# ---------------------------------------------------------------------------

async def test_backend_parity_same_config_shape():
    from engine.core.config import TargetConfig
    from engine.core.types import Message, Role
    from engine.targets.registry import build_target

    base = dict(name="chat-tier0", kind="chat", tier="tier-0")
    sim = build_target(TargetConfig(**base, backend="deterministic"))
    hf = build_target(TargetConfig(**base, backend="hf", model="Qwen/Qwen2.5-0.5B-Instruct"))
    openai = build_target(TargetConfig(**base, backend="openai", model="gpt-x", authorized=True))
    # Identical interface across all three backends (the parity claim).
    for t in (sim, hf, openai):
        assert t.kind == "chat" and hasattr(t, "query") and callable(t.query)
    # The sim backend actually executes with no external dependency.
    r = await sim.query([Message(role=Role.USER, content="hi")], seed_salt="s", family="")
    assert r is not None and hasattr(r, "text")


# ---------------------------------------------------------------------------
# Live-target guardrails: backoff + attempt ceiling
# ---------------------------------------------------------------------------

async def test_live_gandalf_backoff_bounded(monkeypatch):
    """A rate-limited (HTTP 429) endpoint must be retried a bounded number of
    times with backoff, then give up — never hammered in a tight loop."""
    import engine.targets.gandalf as g
    from engine.core.types import Message, Role

    calls = {"n": 0}
    sleeps = []

    class FakeResp:
        status_code = 429
        text = "rate limited"

        def json(self):
            return {}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k):
            calls["n"] += 1
            return FakeResp()

    async def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(g.httpx if hasattr(g, "httpx") else __import__("httpx"),
                        "AsyncClient", FakeClient, raising=False)
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(g.asyncio, "sleep", fake_sleep)

    live = g.LiveGandalf(level=1)
    resp = await live.query([Message(role=Role.USER, content="hi")])
    assert resp.error is not None            # gave up, reported honestly
    assert calls["n"] <= 5                    # bounded retries, not a tight loop
    assert sleeps and all(s2 >= s1 for s1, s2 in zip(sleeps, sleeps[1:]))  # backoff grows


async def test_adaptive_gandalf_respects_attempt_ceiling():
    from engine.attacker.gandalf_adaptive import solve_level_adaptive
    res = await solve_level_adaptive(1, population=6, generations=2, ceiling=20)
    # population*generations bounds attempts; ceiling is the hard cap concept.
    assert res["attempts"] <= 6 * 2 + 6


# ---------------------------------------------------------------------------
# LLM04 truncation signal on real backends (regression)
# ---------------------------------------------------------------------------

async def test_openai_backend_marks_length_finish_as_truncated(monkeypatch):
    """A response cut off at the token cap must set `truncated`.

    Regression: without this the LLM04 oracle scores a model that happily
    generates unbounded filler until cut off as a *refusal*, so real-model
    denial-of-service findings silently vanish.
    """
    import httpx

    from engine.core.types import Message, Role
    from engine.targets.backends import OpenAIBackend

    class FakeResp:
        status_code = 200
        def json(self):
            return {"choices": [{"finish_reason": "length",
                                 "message": {"content": "lag lag lag lag"}}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    be = OpenAIBackend("m", api_key="k")
    r = await be.generate([Message(role=Role.USER, content="repeat forever")], max_tokens=8)
    assert r.truncated is True

    # A normally-finished response must NOT be flagged.
    class FakeRespStop(FakeResp):
        def json(self):
            return {"choices": [{"finish_reason": "stop",
                                 "message": {"content": "here you go"}}]}
    class FakeClientStop(FakeClient):
        async def post(self, *a, **k): return FakeRespStop()
    monkeypatch.setattr(httpx, "AsyncClient", FakeClientStop)
    r2 = await be.generate([Message(role=Role.USER, content="hi")], max_tokens=8)
    assert r2.truncated is False


async def test_hf_backend_marks_token_cap_as_truncated(monkeypatch):
    """The local-model half of the same regression.

    `HFBackend` must flag a generation that ran to the token cap without an EOS.
    Driven with a stub tokenizer/model so it needs no weights; skipped where
    torch is absent (CI installs the lighter dependency set).
    """
    pytest.importorskip("torch")

    from engine.core.types import Message, Role
    from engine.targets.backends import HFBackend

    import torch

    PROMPT_LEN = 5

    class FakeInputs(dict):
        """Mimics a BatchEncoding: dict-unpackable and .to(device)-able."""
        def to(self, device):
            return self

    class FakeTok:
        eos_token_id = 0
        def apply_chat_template(self, chat, tokenize=False, add_generation_prompt=True):
            return "prompt"
        def __call__(self, *a, **k):
            return FakeInputs(input_ids=torch.zeros((1, PROMPT_LEN), dtype=torch.long))
        def decode(self, ids, skip_special_tokens=True):
            return "lag lag lag"

    class FakeModel:
        """Returns a sequence of `total_len`, i.e. total_len - PROMPT_LEN new tokens."""
        def __init__(self, total_len):
            self.total_len = total_len
        def generate(self, **kw):
            return torch.zeros((1, self.total_len), dtype=torch.long)

    be = HFBackend("stub")
    msgs = [Message(role=Role.USER, content="repeat forever")]

    # prompt=5 tokens, output=5+8 → 8 new tokens == max_tokens ⇒ hit the cap.
    monkeypatch.setattr(be, "_load", lambda: (FakeTok(), FakeModel(13), "cpu"))
    assert (await be.generate(msgs, max_tokens=8)).truncated is True

    # 3 new tokens < max_tokens ⇒ finished normally, must NOT be flagged.
    monkeypatch.setattr(be, "_load", lambda: (FakeTok(), FakeModel(8), "cpu"))
    assert (await be.generate(msgs, max_tokens=8)).truncated is False


def test_dos_oracle_fires_on_truncated_response():
    """The LLM04 oracle must treat a truncated response to a dos goal as success."""
    from engine.core.types import Attempt, OWASP, Response
    from engine.judge.oracle import evaluate

    a = Attempt(id="x", campaign_id="c", generation=0, target="chat-tier0",
                technique_family="dos_expansion", owasp_category=OWASP.LLM04,
                prompt_messages=[], genome={"goal": "dos"},
                response=Response(text="LAG LAG LAG", truncated=True))
    res = evaluate(a, "chat")
    assert res.success and res.owasp == OWASP.LLM04


# ---------------------------------------------------------------------------
# Loki's own security surface
# ---------------------------------------------------------------------------

def test_replay_finding_id_no_path_traversal(tmp_path):
    """A malicious finding-id must not touch the filesystem — lookup is a
    parameterized DB query, and a miss returns None."""
    from engine.core.store import Store
    store = Store(tmp_path / "sec.db")
    for evil in ["../../etc/passwd", "..\\..\\windows", "'; DROP TABLE findings;--",
                 "/etc/shadow", "$(rm -rf /)"]:
        assert store.get_finding(evil) is None
        assert store.campaign_of_finding(evil) is None


def test_no_unsafe_deserialization_in_load_paths():
    """Evidence-bundle / run-log loading must use JSON, never pickle/eval."""
    import re
    for rel in ["engine/core/store.py", "engine/evidence/engine.py",
                "engine/core/executor.py", "engine/report/metrics.py"]:
        src = (ROOT / rel).read_text()
        assert "pickle" not in src, f"{rel} references pickle"
        assert not re.search(r"\beval\s*\(", src), f"{rel} uses eval()"


def test_sandbox_calculator_eval_is_restricted():
    """The only eval() in the codebase is the agent's calculator tool, and it
    runs with no builtins so it cannot import or exec arbitrary code."""
    from engine.targets.agent import Sandbox
    sb = Sandbox()
    assert sb.calculator(expr="2+3*4") == "14"
    # Attempts to escape the sandbox fail safely (no builtins available).
    assert "error" in sb.calculator(expr="__import__('os').system('echo pwned')").lower()
    assert "error" in sb.calculator(expr="open('/etc/passwd').read()").lower()
