# Contributing to Loki

## Setup

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e '.[ml,dev]'
.venv/bin/python -m pytest -q
```

PDF report generation needs native libs (`brew install pango gdk-pixbuf libffi` on
macOS). Without them the HTML report still builds and the PDF step is skipped with a
note — it is not a hard failure.

## The one rule that matters

**Every number in a report must be derived from the run logs by code.** No
hand-written figures, ever. `engine/report/metrics.py` reads the SQLite store and
`tests/test_pipeline.py::test_report_numbers_reconcile` asserts the headline table
reconciles with the raw attempts. If you add a statistic, add the reconciliation test
with it.

Corollaries that reviewers will hold you to:

- **Never merge simulator results with real-model results.** They live in separate
  databases and separate report sections, and every table states its backend.
- **A finding that cannot be replayed does not go in the report.** If you touch the
  evidence pipeline, `test_replay_of_confirmed_findings_passes` must still pass.
- **Report what you measured, not what you hoped.** A lower attack-success rate
  against a better-defended target is a *result*, not a bug to tune away.

## Where things live

| Area | Path | Notes |
| ---- | ---- | ----- |
| Attack techniques | `engine/attacker/techniques.py` | add a family + its OWASP tag |
| Mutation operators | `engine/attacker/mutations.py` | must draw from the seeded RNG |
| Targets | `engine/targets/` | new targets implement `query()` and `reset()` |
| Judge signals | `engine/judge/` | oracle is ground truth; others are signals |
| Evidence | `engine/evidence/engine.py` | dedupe → verify → Wilson CI → bundle |
| Reports | `engine/report/` | `metrics.py` computes, templates render |

## Adding a technique family

1. Add the family to `FAMILY_OWASP` and a `render()` branch in `techniques.py`.
2. If it injects through a *trusted* channel (tool output, retrieved document),
   return a `Plant` — that is what makes it an indirect-injection vector.
3. Add it to a starter set in `engine/core/orchestrator.py` if it should seed the
   genetic search.
4. `tests/test_attacker.py::test_all_families_render` will pick it up automatically.

## Adding a target

Implement `kind`, `query(messages, **kwargs)`, `reset()`, `config()` and
`model_version()`. Give it a **deterministic oracle** — a canary or a tripwire — or
its findings will rest on the weaker judge signals alone. Wire it into
`engine/targets/registry.py`.

If the target is not a self-built sandbox, it must go through `authorize()`. See
[SECURITY.md](SECURITY.md).

## Determinism

Campaigns are seeded and reproducible: same seed + same target config ⇒ same attack
sequence (`test_determinism_same_seed_same_results`). Draw randomness from the
campaign's `SeededRNG` stream, never from the global `random` module.
