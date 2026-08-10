"""The ``loki`` CLI: run / replay / report / targets.

    loki run <campaign.yaml>       run an adaptive red-team campaign
    loki run --quick               run the built-in self-built benchmark suite
    loki replay <finding-id>       deterministically re-execute a finding → PASS/FAIL
    loki report [--campaign <id>]  generate the HTML/PDF benchmark report
    loki targets list              list built-in self-built targets
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from engine.core.config import CampaignConfig, Budget
from engine.core.factory import make_factory
from engine.core.orchestrator import Orchestrator
from engine.core.store import Store

app = typer.Typer(add_completion=False, help="Loki — adaptive AI red-teaming engine")
console = Console()


def _default_campaign() -> CampaignConfig:
    from engine.targets.registry import default_self_built_targets
    return CampaignConfig(
        name="benchmark", seed=42, generations=6, population_size=24, concurrency=10,
        matrix_trials=16, reproduction_trials=12,
        budget=Budget(max_calls=9000, max_wall_clock_s=900),
        targets=default_self_built_targets(),
    )


@app.command()
def run(
    campaign: str = typer.Argument(None, help="Path to a campaign YAML (omit with --quick)"),
    quick: bool = typer.Option(False, "--quick", help="Run the built-in self-built suite"),
    i_am_authorized_to_test_this: bool = typer.Option(
        False, "--i-am-authorized-to-test-this",
        help="Attest authorization for any non-self-built target"),
    db: str = typer.Option("artifacts/loki.db", help="SQLite path"),
):
    """Run a red-team campaign end-to-end (matrix sweep + adaptive search + evidence)."""
    if quick or not campaign:
        cfg = _default_campaign()
    else:
        cfg = CampaignConfig.load(campaign)
    store = Store(db)
    factory = make_factory(cfg.targets, cli_authorized=i_am_authorized_to_test_this)

    n = {"a": 0}

    def on_attempt(att):
        n["a"] += 1
        if att.verdict and att.verdict.success and n["a"] % 1 == 0:
            v = att.verdict
            console.print(f"[green]✔[/green] {att.target} · {att.technique_family} · "
                          f"{v.owasp_category.value} · {v.severity.value}")

    def on_progress(phase: str, i: int, total: int, label: str):
        console.print(f"[dim]{phase} {i}/{total} · {label}[/dim]")

    orch = Orchestrator(cfg, store, factory, on_attempt=on_attempt,
                        on_progress=on_progress)
    console.rule(f"[bold]Loki campaign: {cfg.name}[/bold]  seed={cfg.seed}")
    findings = asyncio.run(orch.run())
    console.rule("[bold]Findings[/bold]")
    _print_findings(findings)
    console.print(f"\n[bold]{len(findings)}[/bold] confirmed/intermittent findings · "
                  f"budget used: {orch.budget.calls} calls · campaign_id=[cyan]{orch.campaign_id}[/cyan]")
    console.print(f"Run [bold]loki report --campaign {orch.campaign_id}[/bold] to generate the report.")


@app.command()
def bench(db: str = typer.Option("artifacts/loki.db"),
         own_app: bool = typer.Option(True, help="Also validate the operator's own app replica"),
         out: str = typer.Option("artifacts/report")):
    """One-shot full benchmark: campaign → own-app → judge validation → report."""
    from engine.report.human_validation import build as build_validation
    from engine.report.report import generate_report

    cfg = _default_campaign()
    store = Store(db)
    orch = Orchestrator(cfg, store, make_factory(cfg.targets),
                        on_attempt=lambda a: None)
    console.rule(f"[bold]Full benchmark[/bold]  seed={cfg.seed}")
    findings = asyncio.run(orch.run())
    _print_findings(findings)
    console.print(f"[bold]{len(findings)}[/bold] findings · budget {orch.budget.calls} calls")

    if own_app:
        from engine.report.own_app import run as run_own_app
        console.rule("[bold]Own-app validation (ResumeIntel replica)[/bold]")
        oa = asyncio.run(run_own_app(seed=cfg.seed))
        console.print(f"ResumeIntel replica: {oa['n_findings']} findings ({oa['confirmed']} confirmed)")

    console.rule("[bold]Judge validation[/bold]")
    hv = build_validation(store, orch.campaign_id)
    console.print(f"LLM-judge vs oracle (n={hv['n']}): precision {hv['precision']:.3f} "
                  f"recall {hv['recall']:.3f}")

    paths = generate_report(store, orch.campaign_id, Path(out))
    console.rule("[bold]Report[/bold]")
    for p in paths:
        console.print(f"[green]Wrote[/green] {p}")
    console.print(f"campaign_id=[cyan]{orch.campaign_id}[/cyan]")


@app.command()
def phase2(real_db: str = typer.Option("artifacts/loki_real_3b.db",
                                       help="Lead real-model campaign DB (Part A)"),
          real_secondary_db: str = typer.Option("artifacts/loki_real.db",
                                                help="Second real model, shown as a capacity comparison (A2b)"),
          sim_db: str = typer.Option("artifacts/loki.db"),
          own_app_backend: str = typer.Option("hf", help="backend for own-app validation"),
          model: str = typer.Option("Qwen/Qwen2.5-3B-Instruct"),
          own_app_db: str = typer.Option("artifacts/ownapp_3b.db"),
          skip_own_app: bool = typer.Option(False, help="Reuse the existing own-app artifact"),
          out: str = typer.Option("artifacts/report_phase2")):
    """Post-real-run: judge re-validation on real output → own-app (real model) → combined report."""
    from engine.report.real_judge_validation import validate
    from engine.report.own_app import run as run_own_app
    from engine.report.phase2_report import generate

    console.rule("[bold]P2 · judge re-validation on real output[/bold]")
    rj = validate(Path(real_db))
    if rj.get("status") != "no campaign":
        console.print(f"backend: {rj['backend']}")
        console.print(f"LLM-judge vs oracle (real, n={rj['n']}): "
                      f"P={rj['llm_judge_vs_oracle']['precision']:.3f} "
                      f"R={rj['llm_judge_vs_oracle']['recall']:.3f}")
        d = rj["text_says_no_action_says_yes"]
        console.print(f"text-says-no/action-says-yes: {d['count']} cases, "
                      f"{d['of_which_llm_judge_missed']} missed by LLM-judge")

    if not skip_own_app:
        console.rule(f"[bold]P4 · own-app vs real model ({model})[/bold]")
        oa = asyncio.run(run_own_app(backend=own_app_backend, model=model,
                                     db=Path(own_app_db)))
        console.print(f"ResumeIntel real prompt: {oa['n_findings']} findings "
                      f"({oa['confirmed']} confirmed)")

    console.rule("[bold]Phase-2 report (Part A / B / C)[/bold]")
    sec = Path(real_secondary_db) if Path(real_secondary_db).exists() else None
    for p in generate(Path(out), sim_db=Path(sim_db), real_db=Path(real_db),
                      real_secondary_db=sec):
        console.print(f"[green]Wrote[/green] {p}")


@app.command()
def replay(finding_id: str, db: str = typer.Option("artifacts/loki.db")):
    """Deterministically re-execute a finding's exact sequence. Prints PASS/FAIL."""
    from engine.core.config import CampaignConfig as CC
    from engine.evidence.engine import replay_finding
    from engine.judge.judge import Judge

    store = Store(db)
    finding = store.get_finding(finding_id)
    if finding is None:
        console.print(f"[red]No such finding: {finding_id}[/red]")
        raise typer.Exit(1)
    cid = store.campaign_of_finding(finding_id)
    cfg = CC.model_validate(store.campaign_manifest(cid)["campaign_config"])
    factory = make_factory(cfg.targets, cli_authorized=True)
    ok, detail = asyncio.run(replay_finding(finding, Judge(), factory))
    status = "[bold green]PASS[/bold green]" if ok else "[bold red]FAIL[/bold red]"
    console.print(f"\nReplay {finding_id}: {status}")
    console.print(f"  target={finding.target['name']}  technique={finding.technique_family}")
    console.print(f"  proof={finding.proof.get('type')}: {detail}")
    raise typer.Exit(0 if ok else 2)


@app.command()
def report(campaign: str = typer.Option(None, "--campaign", help="Campaign id (default: latest)"),
           db: str = typer.Option("artifacts/loki.db"),
           out: str = typer.Option("artifacts/report", help="Output basename")):
    """Generate the standalone HTML/PDF benchmark report from the run logs."""
    from engine.report.report import generate_report

    store = Store(db)
    cid = campaign or store.latest_campaign()
    if not cid:
        console.print("[red]No campaigns found. Run `loki run --quick` first.[/red]")
        raise typer.Exit(1)
    paths = generate_report(store, cid, Path(out))
    for p in paths:
        console.print(f"[green]Wrote[/green] {p}")


targets_app = typer.Typer(help="Inspect targets")
app.add_typer(targets_app, name="targets")


@targets_app.command("list")
def targets_list():
    """List the built-in self-built targets."""
    from engine.targets.registry import default_self_built_targets

    t = Table(title="Built-in self-built targets (always authorized)")
    t.add_column("name"); t.add_column("kind"); t.add_column("tier/notes")
    for tc in default_self_built_targets():
        t.add_row(tc.name, tc.kind, tc.tier or "-")
    console.print(t)
    console.print("\nExternal targets require --i-am-authorized-to-test-this (or authorized: true).")


def _print_findings(findings):
    t = Table()
    for c in ("id", "sev", "OWASP", "target", "technique", "repro", "CI95", "proof"):
        t.add_column(c)
    for f in findings[:40]:
        r = f.reproduction
        t.add_row(f.finding_id, f.severity.value, f.owasp_category.value, f.target["name"],
                  f.technique_family, f"{r.successes}/{r.trials} {r.status}",
                  f"[{r.ci_95[0]:.2f},{r.ci_95[1]:.2f}]", f.proof.get("type", ""))
    console.print(t)


if __name__ == "__main__":
    app()
