"""Tests for the hand-labeled judge-validation module.

These protect two claims made in the report: the hand-labeled population is
the *complete* oracle-free set (not a cherry-picked subsample), and a
degenerate all-negative gold sample reports accuracy honestly instead of a
misleading 0.000 precision/recall.
"""
import json

import pytest

from engine.core.stats import precision_recall_f1


def test_all_negative_gold_reports_accuracy_not_zero_precision():
    """Regression: P/R=0.0 on an all-negative gold sample looks like total
    disagreement. It can mean total agreement. Accuracy must be checked too."""
    gold = [0, 0, 0, 0]
    pred = [0, 0, 0, 0]  # perfect agreement, zero positives
    m = precision_recall_f1(gold, pred)
    assert m["accuracy"] == 1.0
    assert m["tn"] == 4 and m["tp"] == m["fp"] == m["fn"] == 0
    # precision/recall are conventionally 0.0 here by construction (0/0 guarded),
    # which is exactly why a report must not present them without the accuracy.
    assert m["precision"] == 0.0 and m["recall"] == 0.0


def test_completeness_check_catches_missing_and_extra_labels(tmp_path, monkeypatch):
    """Hermetic version of the completeness guarantee — does not depend on the
    real campaign artifact (gitignored, absent in CI/fresh clones), so this is
    the test that actually runs everywhere and protects the claim.

    Builds a tiny synthetic store with a known oracle-free population and
    asserts build() correctly flags both an incomplete (missing) label set and
    a cherry-picked (extra) one — the two ways a hand-labeled sample could
    quietly misrepresent itself as "complete" when it isn't.
    """
    from engine.report import hand_labeled as hl

    db = tmp_path / "synthetic.db"
    from engine.core.store import Store
    store = Store(db)
    store.start_campaign("c1", "synthetic", 1, {})
    # Three attempts: one with a canary, one with a tripwire, one with neither
    # (the only one that belongs in the oracle-free population).
    store.record_judge_label("c1", "has-canary", canary=1, classifier=0.9,
                             llm_judge="success", blob={"tripwire": False})
    store.record_judge_label("c1", "has-tripwire", canary=None, classifier=0.9,
                             llm_judge="success", blob={"tripwire": True})
    store.record_judge_label("c1", "oracle-free", canary=None, classifier=0.5,
                             llm_judge="failure", blob={"tripwire": False})
    store.finish_campaign("c1")

    # Correct: labels exactly match the true oracle-free population.
    monkeypatch.setattr(hl, "_CAMPAIGNS", {
        str(db): {"oracle-free": hl.HandLabel("oracle-free", 0, "test")}
    })
    out = hl.build(str(db))
    assert out["population_complete"] is True

    # Incomplete: missing the one oracle-free attempt.
    monkeypatch.setattr(hl, "_CAMPAIGNS", {str(db): {}})
    out = hl.build(str(db))
    assert out["population_complete"] is False
    assert "oracle-free" in out["population_check"]["missing_from_labels"]

    # Cherry-picked: includes an attempt that DID have oracle signal.
    monkeypatch.setattr(hl, "_CAMPAIGNS", {
        str(db): {
            "oracle-free": hl.HandLabel("oracle-free", 0, "test"),
            "has-canary": hl.HandLabel("has-canary", 1, "wrongly included"),
        }
    })
    out = hl.build(str(db))
    assert out["population_complete"] is False
    assert "has-canary" in out["population_check"]["extra_in_labels"]


def test_hand_labeled_population_is_complete_not_a_subsample(tmp_path):
    """The build() function must refuse to silently under- or over-cover the
    true oracle-free population — a hand-labeled set is only meaningful if it's
    the whole population (or explicitly flagged as incomplete)."""
    from engine.report import hand_labeled as hl

    db = "artifacts/loki_real_3b.db"
    import os
    if not os.path.exists(db):
        pytest.skip("no real-3b campaign artifact in this checkout")

    out = hl.build(db)
    assert out["population_complete"] is True, out["population_check"]
    assert out["n"] == out["population_check"]["expected"]
    assert not out["population_check"]["missing_from_labels"]
    assert not out["population_check"]["extra_in_labels"]


def test_exhaustive_divergence_matches_full_population(tmp_path):
    """The exhaustive divergence count must come from every stored attempt,
    not a sample — assert the reported total is derivable from the raw store."""
    import os
    from engine.core.store import Store
    from engine.report import hand_labeled as hl

    db = "artifacts/loki_real_3b.db"
    if not os.path.exists(db):
        pytest.skip("no real-3b campaign artifact in this checkout")

    out = hl.exhaustive_divergence(db)
    store = Store(db)
    cid = store.latest_campaign()
    rows = store.judge_labels(cid)

    def oracle_success(r):
        if r["canary"] is not None:
            return bool(r["canary"])
        return bool(json.loads(r["blob"]).get("tripwire"))

    raw_total = sum(1 for r in rows if oracle_success(r))
    raw_div = sum(1 for r in rows if oracle_success(r) and r["llm_judge"] != "success")
    assert out["total_oracle_confirmed_successes"] == raw_total
    assert out["divergence_count"] == raw_div
