from engine.core.stats import cohens_kappa, precision_recall_f1, wilson_ci


def test_wilson_bounds_and_center():
    lo, hi = wilson_ci(9, 10)
    assert 0 < lo < 0.9 < hi <= 1.0
    # known reference values for 9/10 (two-sided 95%)
    assert abs(lo - 0.596) < 0.02 and abs(hi - 0.982) < 0.02


def test_wilson_edges():
    assert wilson_ci(0, 0) == (0.0, 0.0)
    lo, hi = wilson_ci(0, 10)
    assert lo == 0.0 and 0 < hi < 0.4
    lo, hi = wilson_ci(10, 10)
    assert abs(hi - 1.0) < 1e-9 and lo > 0.6


def test_kappa_perfect_and_chance():
    assert abs(cohens_kappa([1, 0, 1, 0], [1, 0, 1, 0]) - 1.0) < 1e-9
    # total disagreement on a balanced set → negative kappa
    assert cohens_kappa([1, 1, 0, 0], [0, 0, 1, 1]) < 0


def test_prf1():
    m = precision_recall_f1([1, 1, 0, 0], [1, 0, 0, 0])
    assert m["tp"] == 1 and m["fn"] == 1 and m["fp"] == 0
    assert m["precision"] == 1.0 and m["recall"] == 0.5
