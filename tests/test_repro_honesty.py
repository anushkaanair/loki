"""Guards for what N-trial reproduction does and does not prove.

Greedy decoding is deterministic, so N/N reproduction on a greedy real model
measures determinism rather than robustness. These tests pin the pieces that
keep that distinction honest: a process-independent replay seed, sampled
decoding as a real option, and a funnel that counts what verification dropped.
"""
import os
import subprocess
import sys

from engine.core.config import Budget, CampaignConfig
from engine.core.factory import make_factory
from engine.core.orchestrator import Orchestrator
from engine.core.store import Store
from engine.report import metrics as M
from engine.targets.backends import HFBackend, _stable_seed, make_backend
from engine.targets.registry import default_self_built_targets


def test_replay_seed_is_stable_across_processes():
    # str hash() is salted per interpreter; the replay seed must not be.
    here = _stable_seed("salt-abc")
    code = "from engine.targets.backends import _stable_seed; print(_stable_seed('salt-abc'))"
    for hashseed in ("0", "1", "12345"):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             env={**os.environ, "PYTHONHASHSEED": hashseed}, check=True)
        assert int(out.stdout.strip()) == here
    assert _stable_seed("a") != _stable_seed("b")


def test_sampled_decoding_is_configurable_and_labelled():
    greedy = make_backend("hf", "Qwen/Qwen2.5-3B-Instruct")
    sampled = make_backend("hf", "Qwen/Qwen2.5-3B-Instruct", temperature=0.7, top_p=0.9)
    assert isinstance(greedy, HFBackend) and greedy.temperature == 0.0
    assert sampled.temperature == 0.7 and sampled.top_p == 0.9
    assert "sampled-T0.7" in sampled.version()
    assert "sampled" not in greedy.version()


async def test_funnel_is_persisted_and_consistent(tmp_path):
    cfg = CampaignConfig(
        name="funnel", seed=42, generations=2, population_size=10, concurrency=8,
        matrix_trials=6, reproduction_trials=10,
        budget=Budget(max_calls=1200, max_wall_clock_s=180),
        targets=default_self_built_targets())
    store = Store(tmp_path / "funnel.db")
    orch = Orchestrator(cfg, store, make_factory(cfg.targets))
    findings = await orch.run()
    fu = store.campaign_manifest(orch.campaign_id)["funnel"]
    assert fu["confirmed"] + fu["intermittent"] == len(findings)
    assert fu["candidates"] == fu["confirmed"] + fu["intermittent"] + fu["flake_dropped"]
    assert len(fu["flakes"]) == fu["flake_dropped"]
    assert all(f["successes"] <= 1 for f in fu["flakes"])
    # Reported figures come from the same record.
    rep = M.reproduction_funnel(store, orch.campaign_id)
    assert rep["candidates"] == fu["candidates"] and rep["flake_dropped"] == fu["flake_dropped"]
    assert not rep["greedy"]  # simulator targets are not greedy real-model decoding
