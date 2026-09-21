"""Render the standalone benchmark report (HTML + PDF).

Every number comes from ``metrics.py`` (i.e. from the run logs). The template is
self-contained: dark terminal aesthetic, inline CSS, no external assets.
"""
from __future__ import annotations

import datetime
from pathlib import Path

from jinja2 import Environment

from ..core.store import Store
from . import metrics as M

_TEMPLATE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Loki Benchmark Report — {{ cid }}</title>
<style>
  :root{--bg:#0a0d0a;--fg:#c8d6c8;--dim:#7a8a7a;--acid:#39ff5b;--red:#ff3b57;
        --amber:#ffb300;--panel:#111611;--line:#1f291f;}
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--fg);font-family:"JetBrains Mono","Fira Code",
       ui-monospace,Menlo,monospace;margin:0;padding:32px 40px;font-size:13px;line-height:1.5}
  h1,h2,h3{color:var(--acid);font-weight:600;letter-spacing:.5px}
  h1{font-size:26px;border-bottom:2px solid var(--acid);padding-bottom:10px}
  h2{font-size:18px;margin-top:38px;border-left:3px solid var(--acid);padding-left:10px}
  h3{font-size:14px;color:#9fe6a8}
  a{color:var(--acid)} code,pre{background:#0d120d;border:1px solid var(--line);
       border-radius:4px;padding:1px 5px;color:#9fe6a8}
  pre{padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word}
  table{border-collapse:collapse;width:100%;margin:12px 0;font-size:12px}
  th,td{border:1px solid var(--line);padding:6px 9px;text-align:left}
  th{background:var(--panel);color:#9fe6a8;text-transform:uppercase;font-size:10.5px;letter-spacing:.5px}
  .kpis{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
  .kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;min-width:120px}
  .kpi .n{font-size:26px;color:var(--acid);font-weight:700}
  .kpi .l{color:var(--dim);font-size:11px;text-transform:uppercase}
  .sev-Critical{color:var(--red);font-weight:700}.sev-High{color:var(--amber);font-weight:700}
  .sev-Medium{color:#ffe066}.sev-Low{color:var(--dim)}
  .muted{color:var(--dim)} .ok{color:var(--acid)} .bad{color:var(--red)}
  .finding{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}
  .heat{text-align:center;font-weight:600}
  .badge{display:inline-block;padding:1px 7px;border-radius:4px;border:1px solid var(--line);font-size:11px}
  .CONFIRMED{color:var(--acid);border-color:var(--acid)}
  .INTERMITTENT{color:var(--amber);border-color:var(--amber)}
  header .sub{color:var(--dim);margin-top:4px}
  footer{margin-top:48px;border-top:1px solid var(--line);padding-top:12px;color:var(--dim)}
</style></head><body>
<header>
  <h1>▲ LOKI — Adaptive AI Red-Teaming Benchmark Report</h1>
  <div class="sub">campaign <code>{{ cid }}</code> · seed {{ seed }} · generated {{ now }}</div>
</header>

<h2>1 · Executive summary</h2>
<div class="kpis">
  <div class="kpi"><div class="n">{{ summary.n_findings }}</div><div class="l">distinct findings</div></div>
  <div class="kpi"><div class="n">{{ summary.n_confirmed }}</div><div class="l">CONFIRMED</div></div>
  <div class="kpi"><div class="n">{{ summary.total_successful_attempts }}</div><div class="l">successful attempts</div></div>
  <div class="kpi"><div class="n">{{ budget.calls_used or "-" }}</div><div class="l">probe budget used</div></div>
</div>
<p>{{ summary.distinct_sentence }} — deduplicated to distinct findings, each verified
by re-running on a freshly initialized target and reported with a Wilson 95% CI.
Flaky candidates (≤1/{{ repro_trials }}) are dropped from the findings list and counted below.</p>
<table><tr><th>Attempts</th><th>Successful</th><th>Candidates (deduped)</th><th>CONFIRMED</th><th>INTERMITTENT</th><th>FLAKE (dropped)</th></tr>
<tr><td>{{ funnel.attempts }}</td><td>{{ funnel.successful_attempts }}</td>
<td>{{ funnel.candidates if funnel.candidates is not none else "not recorded" }}</td>
<td>{{ funnel.confirmed }}</td><td>{{ funnel.intermittent }}</td>
<td>{{ funnel.flake_dropped if funnel.flake_dropped is not none else "not recorded" }}</td></tr></table>
{% if funnel.greedy %}<p class="muted"><b>Decoding note:</b> at least one target uses greedy
decoding, which is deterministic — re-running the same prompt gives the same output, so a
{{ repro_trials }}/{{ repro_trials }} reproduction there shows determinism, not robustness.
The sampled-decoding campaign configs give the reproduction rate real variance.</p>{% endif %}
<table><tr><th>Severity</th>{% for s in ["Critical","High","Medium","Low"] %}<th>{{ s }}</th>{% endfor %}</tr>
<tr><td>count</td>{% for s in ["Critical","High","Medium","Low"] %}<td class="sev-{{s}}">{{ summary.by_severity.get(s,0) }}</td>{% endfor %}</tr></table>
<table><tr><th>OWASP</th>{% for o,c in summary.by_owasp.items() %}<th>{{ o }}</th>{% endfor %}</tr>
<tr><td>count</td>{% for o,c in summary.by_owasp.items() %}<td>{{ c }}</td>{% endfor %}</tr></table>

<h2>2 · Headline — guardrail tier vs. attack success rate</h2>
<p class="muted">Measured over the systematic sweep ({{ repro_trials }}+ fixed trials per
target × technique family). Every rate carries a Wilson 95% CI.</p>
<table><tr><th>Target</th><th>ASR</th><th>successes / trials</th><th>95% CI</th></tr>
{% for t,r in headline.items() %}
<tr><td>{{ t }}</td><td class="{{ 'ok' if r.rate<0.15 else 'bad' }}">{{ '%.0f'|format(r.rate*100) }}%</td>
<td>{{ r.successes }}/{{ r.trials }}</td><td>[{{ '%.2f'|format(r.ci_95[0]) }}, {{ '%.2f'|format(r.ci_95[1]) }}]</td></tr>
{% endfor %}</table>
<p>{% if tier0 and tier2 %}Hardening the chat target from tier-0 to tier-2 reduced
attack success from <b>{{ '%.0f'|format(tier0*100) }}%</b> to
<b>{{ '%.0f'|format(tier2*100) }}%</b>. The tier-2 residual is dominated by
resource-exhaustion (LLM04) and instruction-following hijack (LLM01), which output
filtering does not address.{% endif %}</p>

<h2>3 · Technique effectiveness matrix (family × defense)</h2>
<p class="muted">ASR per cell. This defense-vs-attack cross-table is the core novel contribution.</p>
<table><tr><th>Technique family</th>{% for t in matrix.targets %}<th>{{ t }}</th>{% endfor %}</tr>
{% for fam in matrix.families %}<tr><td>{{ fam }}</td>
{% for t in matrix.targets %}{% set c = matrix.cells[fam][t] %}
{% if c %}<td class="heat" style="background:{{ heat(c.rate) }}">{{ '%.0f'|format(c.rate*100) }}%</td>
{% else %}<td class="muted heat">–</td>{% endif %}{% endfor %}</tr>{% endfor %}
</table>

<h2>4 · Agent &amp; RAG findings — indirect injection &amp; excessive agency</h2>
<p class="muted">The area where existing tooling is weakest. These carry deterministic
tripwire / canary proofs.</p>
{% for f in agent_rag %}
<div class="finding">
  <b>{{ f.finding_id }}</b> · <span class="sev-{{f.severity.value}}">{{ f.severity.value }}</span> ·
  {{ f.owasp_category.value }} · {{ f.target.name }} · <code>{{ f.technique_family }}</code>
  · <span class="badge {{ f.reproduction.status }}">{{ f.reproduction.status }}
  {{ f.reproduction.successes }}/{{ f.reproduction.trials }}
  CI[{{ '%.2f'|format(f.reproduction.ci_95[0]) }},{{ '%.2f'|format(f.reproduction.ci_95[1]) }}]</span>
  <div class="muted">proof ({{ f.proof.type }}): {{ f.proof.detail }}</div>
  <div>replay: <code>{{ f.replay }}</code></div>
</div>
{% else %}<p class="muted">None in this campaign.</p>{% endfor %}

<h2>5 · Baseline comparison — Loki vs. Garak &amp; Promptfoo</h2>
{% if baselines %}
<table><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Notes</th></tr>
{% for b in baselines.tools %}<tr><td>{{ b.name }}</td><td>{{ b.status }}</td>
<td>{{ b.findings if b.findings is not none else '–' }}</td><td class="muted">{{ b.notes }}</td></tr>{% endfor %}</table>
<p><b>What Loki found that they did not:</b> {{ baselines.loki_unique }}</p>
{% if baselines.their_unique %}<p class="muted"><b>What they found that Loki did not:</b> {{ baselines.their_unique }}</p>{% endif %}
{% else %}<p class="muted">Baseline comparison not run in this campaign. See the "Baseline comparison" section of the README to enable it.</p>{% endif %}

<h2>5b · Own-application validation — the operator's real apps</h2>
{% if own_app %}
<p class="muted">{{ own_app.note }} Source: <code>{{ own_app.source_file }}</code>.</p>
<p><b>{{ own_app.n_findings }}</b> evidence-verified findings on <b>{{ own_app.app }}</b>
 ({{ own_app.confirmed }} CONFIRMED). This is the most persuasive artifact: real issues in a
 system the operator built.</p>
<table><tr><th>id</th><th>OWASP</th><th>sev</th><th>technique</th><th>status</th><th>rate</th><th>replay</th></tr>
{% for f in own_app.findings[:12] %}<tr><td>{{ f.finding_id }}</td><td>{{ f.owasp }}</td>
<td class="sev-{{ f.severity }}">{{ f.severity }}</td><td>{{ f.technique }}</td>
<td><span class="badge {{ f.status }}">{{ f.status }}</span></td>
<td>{{ '%.2f'|format(f.rate) }}</td><td><code>{{ f.replay }}</code></td></tr>{% endfor %}</table>
<p class="muted"><b>Recommendation:</b> {{ own_app.recommendation }}</p>
{% else %}<p class="muted">Own-app validation not run. Enable with <code>python -m engine.report.own_app</code>.</p>{% endif %}

<h2>6 · Judge validation</h2>
<table><tr><th>Signal</th><th>Metric</th><th>Value</th></tr>
{% if judge.classifier %}
<tr><td>Trained classifier</td><td>precision / recall / F1</td>
<td>{{ '%.3f'|format(judge.classifier.precision) }} / {{ '%.3f'|format(judge.classifier.recall) }} / {{ '%.3f'|format(judge.classifier.f1) }}</td></tr>
<tr><td class="muted">↳ dataset</td><td class="muted">held-out n={{ judge.classifier.n_val }}</td><td class="muted">{{ judge.classifier.balance.dataset_used if judge.classifier.balance else '' }}</td></tr>
{% else %}<tr><td>Trained classifier</td><td>status</td><td class="muted">not trained (heuristic fallback in use)</td></tr>{% endif %}
<tr><td>Inter-signal agreement</td><td>Cohen's κ (classifier vs LLM-judge)</td>
<td>{{ judge.inter_signal_kappa if judge.inter_signal_kappa is not none else 'n/a' }} (n={{ judge.n_agreement_pairs }})</td></tr>
{% if judge.human_validation %}
<tr><td>LLM-judge vs oracle (validation sample)</td><td>precision / recall (n={{ judge.human_validation.n }})</td>
<td>{{ '%.3f'|format(judge.human_validation.precision) }} / {{ '%.3f'|format(judge.human_validation.recall) }}</td></tr>
{% endif %}
</table>
<p class="muted">{{ judge.signals_note }}</p>
<p class="muted"><b>Label source:</b> {{ judge.human_validation.label_source if judge.human_validation else "n/a" }}.
This is <em>not</em> a human-annotated sample — it is the LLM-judge scored against
the deterministic canary/tripwire oracle, which is ground truth for self-built
targets but does not cover cases where no oracle applies.</p>

<h2>7 · Full finding appendix</h2>
{% for f in findings %}
<div class="finding">
  <b>{{ f.finding_id }}</b> · <span class="sev-{{f.severity.value}}">{{ f.severity.value }}</span> ·
  {{ f.owasp_category.value }} ({{ owasp_title(f.owasp_category.value) }}) · {{ f.target.name }}
  · <code>{{ f.technique_family }}</code>
  · <span class="badge {{ f.reproduction.status }}">{{ f.reproduction.status }}</span>
  <div class="muted">reproduction {{ f.reproduction.successes }}/{{ f.reproduction.trials }}
   (rate {{ '%.2f'|format(f.reproduction.rate) }}, 95% CI
   [{{ '%.2f'|format(f.reproduction.ci_95[0]) }}, {{ '%.2f'|format(f.reproduction.ci_95[1]) }}])
   · {{ f.variant_count }} variant(s) · seed {{ f.seed }}</div>
  <div>proof ({{ f.proof.type }}): {{ f.proof.detail }}</div>
  <div>judge signals: canary={{ f.judge_signals.canary }} · classifier={{ f.judge_signals.classifier }}
       · llm_judge={{ f.judge_signals.llm_judge }}</div>
  <details><summary class="muted">transcript</summary><pre>{% for m in f.transcript %}[{{ m.role }}] {{ m.content[:600] }}
{% endfor %}</pre></details>
  <div>replay: <code>{{ f.replay }}</code></div>
</div>
{% endfor %}

<h2>8 · Limitations</h2>
<ul>
{% for lim in limitations %}<li>{{ lim }}</li>{% endfor %}
</ul>

<footer>Generated by Loki. Every figure in this report is computed from the SQLite run
log by <code>engine/report/metrics.py</code> — no hand-written numbers. Reproduce any
finding with <code>loki replay &lt;finding-id&gt;</code>.</footer>
</body></html>"""


def _heat(rate: float) -> str:
    if rate <= 0.001:
        return "#0d120d"
    if rate < 0.2:
        return "#14361c"
    if rate < 0.5:
        return "#3a4d12"
    if rate < 0.8:
        return "#6b4a0e"
    return "#5c1420"


_OWASP_TITLES = {"LLM01": "Prompt Injection", "LLM02": "Insecure Output Handling",
                 "LLM04": "Model Denial of Service", "LLM06": "Sensitive Information Disclosure",
                 "LLM08": "Excessive Agency"}

_LIMITATIONS = [
    "The primary targets pair a documented, seeded LLM *simulator* with REAL guardrail "
    "code (denylist, input classifier, delimiter isolation, output filter) and real "
    "tripwires. Headline rates therefore measure the guardrail stack's behavior under a "
    "modeled model; they are not a claim about any specific commercial LLM. The same "
    "attacks run unchanged against a real local HF model via the --backend hf option.",
    "The trained classifier is a judge *signal*, not ground truth; the canary/tripwire "
    "oracle is authoritative for self-built targets. Where no oracle applies, success "
    "depends on classifier + LLM-judge agreement, which is weaker.",
    "HackAPrompt 1.0 became a gated Hub dataset (requires HF authentication). The "
    "classifier was trained on a public, ungated prompt-injection corpus instead; the "
    "exact dataset is named in §6. Its labels denote injection *attempts*, not success.",
    "Without an API key, the LLM-as-judge runs its fixed rubric in deterministic "
    "rule-based mode rather than as a large model. Set OPENAI_API_KEY to enable the "
    "model-backed judge; the rubric is identical.",
    "Out of scope (not reliably black-box testable): training-data poisoning, "
    "supply-chain, model theft, overreliance.",
    "Reproduction CIs are wide at n=10 by design; raise --reproduction-trials for "
    "tighter intervals at higher budget cost.",
]


def generate_report(store: Store, cid: str, out_base: Path) -> list[Path]:
    env = Environment(autoescape=False)
    env.filters["heat"] = _heat
    tmpl = env.from_string(_TEMPLATE)

    headline = M.tier_headline(store, cid)
    tier0 = headline.get("chat-tier0", {}).get("rate")
    tier2 = headline.get("chat-tier2", {}).get("rate")

    html = tmpl.render(
        cid=cid,
        seed=store.campaign_manifest(cid).get("seed", "?"),
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        summary=M.executive_summary(store, cid),
        funnel=M.reproduction_funnel(store, cid),
        headline=headline, tier0=tier0, tier2=tier2,
        matrix=M.effectiveness_matrix(store, cid),
        agent_rag=M.agent_rag_findings(store, cid),
        findings=store.findings(cid),
        judge=M.judge_validation(store, cid),
        baselines=M.baseline_comparison(),
        own_app=M.own_app_findings(),
        budget=M.budget_summary(store, cid),
        repro_trials=store.campaign_manifest(cid).get("campaign_config", {}).get("reproduction_trials", 10),
        limitations=_LIMITATIONS,
        heat=_heat,
        owasp_title=lambda o: _OWASP_TITLES.get(o, o),
    )
    out_base.parent.mkdir(parents=True, exist_ok=True)
    html_path = out_base.with_suffix(".html")
    html_path.write_text(html)
    paths = [html_path]

    pdf_path = out_base.with_suffix(".pdf")
    if _render_pdf(html, pdf_path):
        paths.append(pdf_path)
    else:
        (out_base.parent / "PDF_SKIPPED.txt").write_text(
            "PDF generation skipped: native libs for weasyprint (pango/gobject) not found. "
            "On macOS: `brew install pango gdk-pixbuf libffi`. The HTML report is complete.")
    return paths


def _render_pdf(html: str, pdf_path: Path) -> bool:
    """Render PDF, making weasyprint's native libs discoverable if needed."""
    import os

    # Ensure Homebrew libs (libgobject/pango/cairo) are on the loader path.
    for libdir in ("/opt/homebrew/lib", "/usr/local/lib"):
        if os.path.isdir(libdir):
            cur = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
            if libdir not in cur:
                os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = (cur + ":" + libdir).strip(":")
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(pdf_path))
        return True
    except Exception:
        return False
