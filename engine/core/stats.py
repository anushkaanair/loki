"""Statistics used across the evidence and judge components.

Kept dependency-light (numpy/scipy only) and unit-tested — these functions
produce numbers that appear verbatim in the report, so correctness matters.
"""
from __future__ import annotations

import math

import numpy as np


def wilson_ci(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% confidence interval for a binomial proportion.

    Preferred over the normal approximation because it stays inside [0, 1] and
    behaves well for small n and extreme rates — exactly the regime of a
    10-trial reproduction check. ``z`` defaults to the 97.5th percentile of the
    standard normal (two-sided 95%).
    """
    if trials <= 0:
        return (0.0, 0.0)
    p = successes / trials
    n = trials
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - margin), min(1.0, center + margin))


def cohens_kappa(a: list[int], b: list[int]) -> float:
    """Cohen's kappa for two raters with binary labels.

    Used for inter-signal agreement between the trained classifier and the
    LLM-judge on the canary-labeled subset .
    """
    a = np.asarray(a)
    b = np.asarray(b)
    if len(a) == 0 or len(a) != len(b):
        return float("nan")
    po = float(np.mean(a == b))
    # Expected agreement under independence.
    pa1 = np.mean(a)
    pb1 = np.mean(b)
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    if pe >= 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def precision_recall_f1(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    """Binary precision / recall / F1 with the positive class = 1."""
    yt = np.asarray(y_true)
    yp = np.asarray(y_pred)
    tp = int(np.sum((yt == 1) & (yp == 1)))
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    tn = int(np.sum((yt == 0) & (yp == 0)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    acc = (tp + tn) / len(yt) if len(yt) else 0.0
    return {
        "precision": precision, "recall": recall, "f1": f1, "accuracy": acc,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }
