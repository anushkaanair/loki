"""FastAPI + WebSocket backend for the Loki dashboard.

REST endpoints expose the stored campaign results; the WebSocket streams a live
campaign as it runs (every attempt + per-generation fitness stats), which drives
the live attack feed and the genetic fitness-over-generations plot.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..core.config import ARTIFACTS, Budget, CampaignConfig
from ..core.factory import make_factory
from ..core.orchestrator import Orchestrator
from ..core.store import Store
from ..report import metrics as M
from ..targets.registry import default_self_built_targets

app = FastAPI(title="Loki Dashboard API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Which run database the dashboard reads. Override to view a real-model campaign:
#   LOKI_DB=artifacts/loki_real_3b.db python -m engine.api.server
DB = Path(os.environ.get("LOKI_DB", ARTIFACTS / "loki.db"))


def store() -> Store:
    return Store(DB)


# ---------------------------------------------------------------------------
# REST
# ---------------------------------------------------------------------------

@app.get("/api/campaigns")
def campaigns():
    s = store()
    rows = s.conn.execute(
        "SELECT id,name,seed,started_at,finished_at FROM campaigns ORDER BY started_at DESC")
    return [dict(r) for r in rows]


@app.get("/api/campaign/{cid}")
def campaign(cid: str):
    s = store()
    manifest = s.campaign_manifest(cid)
    models = sorted(set(manifest.get("model_versions", {}).values()))
    return {
        # Which model produced these numbers. The UI shows this prominently:
        # a reader must never have to guess whether a figure is simulator or real.
        "backend": ", ".join(models) if models else "unknown",
        "is_simulator": all("deterministic-sim" in m for m in models) if models else False,
        "campaign_id": cid,
        "summary": M.executive_summary(s, cid),
        "headline": M.tier_headline(s, cid),
        "matrix": M.effectiveness_matrix(s, cid),
        "judge": M.judge_validation(s, cid),
        "fitness": M.fitness_curves(s, cid),
        "budget": M.budget_summary(s, cid),
    }


@app.get("/api/campaign/{cid}/findings")
def findings(cid: str):
    return [json.loads(f.model_dump_json()) for f in store().findings(cid)]


@app.get("/api/latest")
def latest():
    cid = store().latest_campaign()
    return {"campaign_id": cid}


# ---------------------------------------------------------------------------
# Live campaign over WebSocket
# ---------------------------------------------------------------------------

class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.running = False

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for d in dead:
            self.clients.discard(d)


hub = Hub()


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    hub.clients.add(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("action") == "start" and not hub.running:
                asyncio.create_task(_run_campaign(data))
    except WebSocketDisconnect:
        hub.clients.discard(websocket)


def _clamp(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


async def _run_campaign(params: dict):
    hub.running = True
    loop = asyncio.get_event_loop()
    # Clamp every client-supplied knob server-side. This endpoint is reachable
    # by anyone with the page open, so a visitor's inputs are untrusted input,
    # not configuration — bounds keep a public demo instance from being
    # driven into CPU/memory exhaustion by a large or malicious request.
    cfg = CampaignConfig(
        name=params.get("name", "live")[:40] if isinstance(params.get("name"), str) else "live",
        seed=_clamp(params.get("seed"), 0, 2**31 - 1, 42),
        generations=_clamp(params.get("generations"), 1, 8, 5),
        population_size=_clamp(params.get("population_size"), 4, 32, 20),
        concurrency=_clamp(params.get("concurrency"), 1, 8, 8),
        matrix_trials=_clamp(params.get("matrix_trials"), 1, 16, 10),
        budget=Budget(max_calls=_clamp(params.get("max_calls"), 50, 3000, 1500),
                      max_wall_clock_s=180),
        targets=default_self_built_targets(),
    )
    s = store()

    def on_attempt(att):
        v = att.verdict
        msg = {"type": "attempt", "target": att.target, "technique": att.technique_family,
               "generation": att.generation, "phase": att.genome.get("phase", ""),
               "success": bool(v and v.success), "partial": bool(v and v.partial),
               "owasp": v.owasp_category.value if v else "", "severity": v.severity.value if v else "",
               "latency": round(att.response.latency_s * 1000) if att.response else 0}
        asyncio.run_coroutine_threadsafe(hub.broadcast(msg), loop)

    def on_generation(target, stat):
        asyncio.run_coroutine_threadsafe(hub.broadcast({
            "type": "generation", "target": target, "generation": stat.generation,
            "best": stat.best_fitness, "mean": stat.mean_fitness,
            "n_success": stat.n_success, "n_partial": stat.n_partial,
            "refusal_modes": stat.refusal_modes}), loop)

    orch = Orchestrator(cfg, s, make_factory(cfg.targets), on_attempt=on_attempt,
                        on_generation=on_generation)
    await hub.broadcast({"type": "start", "campaign": cfg.name, "seed": cfg.seed})
    try:
        findings = await orch.run()
        await hub.broadcast({"type": "done", "campaign_id": orch.campaign_id,
                             "n_findings": len(findings),
                             "findings": [json.loads(f.model_dump_json()) for f in findings]})
    finally:
        hub.running = False


# ---------------------------------------------------------------------------
# Static frontend (built) — served last so /api and /ws take precedence
# ---------------------------------------------------------------------------

_DIST = Path(__file__).resolve().parents[2] / "dashboard" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="static")


def main():
    import uvicorn
    # 0.0.0.0 + $PORT so this binds correctly behind a PaaS load balancer
    # (Render, Railway, Fly.io all inject PORT); falls back to the local
    # dev defaults when run directly.
    host = os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
    port = int(os.environ.get("PORT", 8008))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
