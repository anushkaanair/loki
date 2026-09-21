"""Compute every report number from the run logs — no hand-written values.

Each function reads the store and returns plain dicts the templates render. The
report-validation test asserts these reconcile exactly with the raw attempts.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ..core.config import ARTIFACTS
from ..core.stats import cohens_kappa, wilson_ci
from ..core.store import Store


def _rate(succ: int, tot: int) -> dict:
    lo, hi = wilson_ci(succ, tot)
    return {"successes": succ, "trials": tot, "rate": (succ / tot) if tot else 0.0,
            "ci_95": [round(lo, 3), round(hi, 3)]}


def matrix_attempts(store: Store, cid: str):
    return [a for a in store.attempts(cid) if a.genome.get("phase") == "matrix"]


def reproduction_funnel(store: Store, cid: str) -> dict:
    """Attempts -> candidates -> confirmed/intermittent/flake, plus how each
    target was decoded. Campaigns stored before the funnel was persisted have no
    candidate/flake counts; those fields are reported as unknown, not zero."""
    man = store.campaign_manifest(cid)
    fu = man.get("funnel")
    findings = store.findings(cid)
    out = {
        "attempts": len(store.attempts(cid)),
        "successful_attempts": sum(1 for a in store.attempts(cid) if a.verdict and a.verdict.success),
        "confirmed": sum(1 for f in findings if f.reproduction.status == "CONFIRMED"),
        "intermittent": sum(1 for f in findings if f.reproduction.status == "INTERMITTENT"),
        "candidates": fu["candidates"] if fu else None,
        "flake_dropped": fu["flake_dropped"] if fu else None,
        "decoding": man.get("decoding", {}),
    }
    if not out["decoding"]:
        # Campaigns stored before decoding was recorded: every real backend then
        # ran greedy (do_sample=False / temperature 0), and simulator targets
        # carry "deterministic-sim" in their model version.
        out["decoding"] = {
            t: ("simulated (seeded per-trial variability)" if "deterministic-sim" in mv
                else "greedy (deterministic) — inferred, campaign predates decoding record")
            for t, mv in man.get("model_versions", {}).items()}
    out["greedy"] = any(d.startswith("greedy") for d in out["decoding"].values())
    return out


def adaptive_attempts(store: Store, cid: str):
    return [a for a in store.attempts(cid) if a.genome.get("phase") == "adaptive"]


def executive_summary(store: Store, cid: str) -> dict:
    findings = store.findings(cid)
    by_sev: dict[str, int] = defaultdict(int)
    by_owasp: dict[str, int] = defaultdict(int)
    confirmed = [f for f in findings if f.reproduction.status == "CONFIRMED"]
    for f in findings:
        by_sev[f.severity.value] += 1
        by_owasp[f.owasp_category.value] += 1
    total_variants = sum(f.variant_count for f in findings)
    succ = sum(1 for a in store.attempts(cid) if a.verdict and a.verdict.success)
    return {
        "n_findings": len(findings),
        "n_confirmed": len(confirmed),
        "by_severity": dict(by_sev),
        "by_owasp": dict(by_owasp),
        "total_successful_attempts": succ,
        "total_variants": total_variants,
        "distinct_sentence": f"{len(findings)} distinct findings across "
                             f"{succ} successful attempts",
    }


def tier_headline(store: Store, cid: str) -> dict:
    """Guardrail tier vs attack success rate (matrix phase)."""
    att = matrix_attempts(store, cid)
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for a in att:
        agg[a.target][1] += 1
        if a.verdict and a.verdict.success:
            agg[a.target][0] += 1
    return {t: _rate(s, n) for t, (s, n) in sorted(agg.items())}


def effectiveness_matrix(store: Store, cid: str) -> dict:
    """Technique family × target ASR (matrix phase)."""
    att = matrix_attempts(store, cid)
    cells: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    families, targets = set(), set()
    for a in att:
        fam, tgt = a.technique_family, a.target
        families.add(fam); targets.add(tgt)
        cells[fam][tgt][1] += 1
        if a.verdict and a.verdict.success:
            cells[fam][tgt][0] += 1
    out = {}
    for fam in families:
        out[fam] = {tgt: _rate(*cells[fam][tgt]) if cells[fam][tgt][1] else None
                    for tgt in targets}
    return {"families": sorted(families), "targets": sorted(targets), "cells": out}


def judge_validation(store: Store, cid: str) -> dict:
    """Classifier metrics + inter-signal agreement (Cohen's kappa) + oracle-labeled
    validation sample. See ``engine/report/hand_labeled.py`` for the genuinely
    human-labeled sample covering attempts the oracle can't judge."""
    labels = store.judge_labels(cid)
    # Agreement between trained classifier (binary @0.5) and LLM-judge on the
    # canary-labeled subset.
    clf_bin, llm_bin, canary_true = [], [], []
    for l in labels:
        if l["canary"] is None or l["classifier"] is None or l["llm_judge"] is None:
            continue
        clf_bin.append(1 if l["classifier"] >= 0.5 else 0)
        llm_bin.append(1 if l["llm_judge"] == "success" else 0)
        canary_true.append(int(l["canary"]))
    kappa = cohens_kappa(clf_bin, llm_bin) if clf_bin else float("nan")

    # Classifier held-out metrics from training.
    clf_metrics = {}
    mp = ARTIFACTS / "classifier" / "metrics.json"
    if mp.exists():
        clf_metrics = json.loads(mp.read_text())

    # Oracle-labeled validation sample (LLM-judge scored against the deterministic
    # canary/tripwire oracle) — NOT human-annotated. See hand_labeled.py for that.
    human = {}
    hp = ARTIFACTS / "human_validation.json"
    if hp.exists():
        human = json.loads(hp.read_text())

    return {
        "inter_signal_kappa": None if kappa != kappa else round(kappa, 3),
        "n_agreement_pairs": len(clf_bin),
        "classifier": clf_metrics,
        "human_validation": human,
        "signals_note": "canary/tripwire oracle is ground truth; classifier scores the "
                        "attack payload; LLM-judge scores the response — three independent views.",
    }


def fitness_curves(store: Store, cid: str) -> dict:
    """Best/mean fitness per generation per target — makes 'adaptive' visible."""
    att = adaptive_attempts(store, cid)
    by: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
    for a in att:
        by[a.target][a.generation].append(a.fitness)
    out = {}
    for tgt, gens in by.items():
        series = []
        for g in sorted(gens):
            vals = gens[g]
            series.append({"generation": g, "best": round(max(vals), 3),
                           "mean": round(sum(vals) / len(vals), 3),
                           "n_success": sum(1 for a in att
                                            if a.target == tgt and a.generation == g
                                            and a.verdict and a.verdict.success)})
        out[tgt] = series
    return out


def agent_rag_findings(store: Store, cid: str) -> list:
    fs = store.findings(cid)
    return [f for f in fs if f.target["name"] in ("agent-target", "rag-target")
            or f.technique_family in ("indirect_tool", "indirect_rag")]


def baseline_comparison() -> dict:
    p = ARTIFACTS / "baselines.json"
    return json.loads(p.read_text()) if p.exists() else {}


def own_app_findings() -> dict:
    p = ARTIFACTS / "own_app_findings.json"
    return json.loads(p.read_text()) if p.exists() else {}


def budget_summary(store: Store, cid: str) -> dict:
    return store.campaign_manifest(cid).get("budget", {})
