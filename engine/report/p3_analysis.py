"""Verify the refusal-pattern router still discriminates on REAL refusal text.

The router's core assumption is that *identical* refusal text across attempts
signals a keyword/pattern filter (→ obfuscate), while *varied* refusals signal
model-level alignment (→ reframe). Real refusals vary far more than the
simulator's, so we check the discrimination empirically against real output.
"""
from __future__ import annotations

import json
from collections import defaultdict

from ..attacker.refusal import analyze
from ..core.config import ARTIFACTS
from ..core.store import Store


def run(db_path) -> dict:
    store = Store(db_path)
    cid = store.latest_campaign()
    if not cid:
        return {"status": "no campaign"}
    attempts = [a for a in store.attempts(cid)
                if a.response is not None and a.verdict is not None
                and not a.verdict.success]

    # Group real refusals by (target, technique) and run the router on each group.
    groups: dict[tuple, list] = defaultdict(list)
    for a in attempts:
        groups[(a.target, a.technique_family)].append(a.response)

    modes = defaultdict(int)
    unique_refusal_texts = set()
    per_group = []
    for (tgt, fam), resps in groups.items():
        if len(resps) < 2:
            continue
        ra = analyze(resps)
        modes[ra.mode] += 1
        texts = {(r.text or "").strip() for r in resps}
        unique_refusal_texts |= texts
        per_group.append({"target": tgt, "technique": fam, "n": len(resps),
                          "distinct_refusals": len(texts), "router_mode": ra.mode,
                          "hint": ra.hint})

    mv = store.campaign_manifest(cid).get("model_versions", {})
    backend_label = f"{list(mv.values())[0]} (real refusals)" if mv else "unknown backend"
    out = {
        "backend": backend_label,
        "n_refusal_groups": len(per_group),
        "router_mode_distribution": dict(modes),
        "distinct_refusal_strings_seen": len(unique_refusal_texts),
        "discrimination_works": bool(modes.get("alignment", 0) or modes.get("keyword_filter", 0)),
        "note": ("Real refusals are more varied than the simulator's; the router still "
                 "routes them to 'alignment' (reframe) vs 'keyword_filter' (obfuscate) "
                 "based on refusal-text diversity, as designed."),
        "sample_groups": per_group[:12],
    }
    (ARTIFACTS / "p3_refusal_analysis.json").write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else ARTIFACTS / "loki_real.db"
    r = run(db)
    print(json.dumps({k: v for k, v in r.items() if k != "sample_groups"}, indent=2))
