"""Integration, replay, determinism, regression, and report-reconciliation tests.

These protect the project's central claims. The replay test in particular
guards the "prove it" guarantee.
"""
import pytest

from engine.attacker.gandalf_solver import solve_all
from engine.core.config import Budget, CampaignConfig
from engine.core.factory import make_factory
from engine.core.orchestrator import Orchestrator
from engine.core.store import Store
from engine.evidence.engine import replay_finding
from engine.judge.judge import Judge
from engine.targets.gandalf import LocalGandalf
from engine.targets.registry import default_self_built_targets


def _cfg(seed=42):
    return CampaignConfig(
        name="test", seed=seed, generations=3, population_size=14, concurrency=8,
        matrix_trials=10, reproduction_trials=10,
        budget=Budget(max_calls=2500, max_wall_clock_s=180),
        targets=default_self_built_targets())


async def _run(tmp_path, seed=42, name="loki_test.db"):
    cfg = _cfg(seed)
    store = Store(tmp_path / name)
    orch = Orchestrator(cfg, store, make_factory(cfg.targets))
    findings = await orch.run()
    return cfg, store, orch, findings


async def test_pipeline_runs_and_finds(tmp_path):
    cfg, store, orch, findings = await _run(tmp_path)
    assert len(findings) > 5
    # No FLAKE findings reach the report.
    assert all(f.reproduction.status in ("CONFIRMED", "INTERMITTENT") for f in findings)
    # Broad OWASP coverage (the five in-scope categories should be well represented).
    owasp = {f.owasp_category.value for f in findings}
    assert len(owasp) >= 3


async def test_replay_of_confirmed_findings_passes(tmp_path):
    cfg, store, orch, findings = await _run(tmp_path)
    confirmed = [f for f in findings if f.reproduction.status == "CONFIRMED"]
    assert len(confirmed) >= 5, "need at least 5 confirmed findings to test replay"
    factory = make_factory(cfg.targets, cli_authorized=True)
    judge = Judge()
    for f in confirmed[:5]:
        ok, _ = await replay_finding(f, judge, factory)
        assert ok, f"replay failed for {f.finding_id}"


async def test_agent_tripwire_findings_have_deterministic_proof(tmp_path):
    cfg, store, orch, findings = await _run(tmp_path)
    agent = [f for f in findings if f.target["name"] == "agent-target"
             and f.owasp_category.value == "LLM08"]
    assert agent, "expected at least one excessive-agency finding on the agent target"
    assert all(f.proof["type"] == "tripwire" for f in agent)


async def test_determinism_same_seed_same_results(tmp_path):
    _, s1, _, _ = await _run(tmp_path, seed=7, name="d1.db")
    _, s2, _, _ = await _run(tmp_path, seed=7, name="d2.db")

    def matrix_map(store):
        cid = store.latest_campaign()
        out = {}
        for a in store.attempts(cid):
            if a.genome.get("phase") == "matrix":
                key = (a.target, a.technique_family, a.genome.get("seed_salt"))
                out[key] = a.verdict.success
        return out

    m1, m2 = matrix_map(s1), matrix_map(s2)
    assert m1 == m2 and len(m1) > 0


async def test_report_numbers_reconcile(tmp_path):
    from engine.report import metrics as M

    cfg, store, orch, findings = await _run(tmp_path)
    cid = orch.campaign_id
    summ = M.executive_summary(store, cid)
    # distinct findings count matches the store
    assert summ["n_findings"] == len(store.findings(cid))
    # headline successes/trials reconcile with raw matrix attempts
    headline = M.tier_headline(store, cid)
    matt = M.matrix_attempts(store, cid)
    for tgt, r in headline.items():
        raw_total = sum(1 for a in matt if a.target == tgt)
        raw_succ = sum(1 for a in matt if a.target == tgt and a.verdict and a.verdict.success)
        assert r["trials"] == raw_total and r["successes"] == raw_succ


async def test_gandalf_regression_all_levels_cleared():
    res = await solve_all(lambda L: LocalGandalf(L))
    assert all(r.cleared for r in res.values()), \
        f"levels not cleared: {[L for L, r in res.items() if not r.cleared]}"
