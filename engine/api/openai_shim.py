"""OpenAI-compatible HTTP shim over a self-built Loki target.

Exposes POST /v1/chat/completions so *any* OpenAI-compatible red-team tool
(Garak, Promptfoo, …) can attack the exact same self-built targets Loki does —
the fair-comparison substrate for a baseline comparison. It also
records whether each request leaked a canary / fired a tripwire, so an external
tool's raw ASR against these targets can be computed the same way Loki's is.

    python -m engine.api.openai_shim --target chat-tier1 --port 8011
"""
from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request

from ..core.factory import make_factory
from ..core.types import Message, Role
from ..judge.oracle import evaluate as oracle_eval
from ..targets.registry import default_self_built_targets

app = FastAPI(title="Loki OpenAI-compatible shim")
_TARGETS = {t.name: t for t in default_self_built_targets()}
_STATE = {"target": "chat-tier1", "hits": 0, "total": 0}
_factory = make_factory(default_self_built_targets())


@app.get("/v1/models")
def models():
    return {"data": [{"id": n, "object": "model"} for n in _TARGETS]}


@app.get("/stats")
def stats():
    return dict(_STATE)


@app.post("/v1/chat/completions")
async def chat(req: Request):
    body = await req.json()
    name = _STATE["target"]
    target = _factory(name)
    target.reset()
    msgs = [Message(role=Role(m.get("role", "user")), content=m.get("content", ""))
            for m in body.get("messages", []) if m.get("role") in ("user", "system", "assistant")]
    salt = uuid.uuid4().hex[:12]
    resp = await target.query(msgs, seed_salt=salt)

    # Score with the same oracle Loki uses, so external tools' ASR is comparable.
    from ..core.types import Attempt, OWASP
    att = Attempt(id=salt, campaign_id="shim", generation=0, target=name,
                  technique_family="external", owasp_category=OWASP.LLM01,
                  prompt_messages=msgs, response=resp, genome={"goal": "leak_secret"})
    verdict = oracle_eval(att, target.kind)
    _STATE["total"] += 1
    _STATE["hits"] += int(verdict.success)

    return {
        "id": f"chatcmpl-{salt}", "object": "chat.completion", "created": int(time.time()),
        "model": name,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": resp.text}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "loki_oracle": {"success": verdict.success, "proof": verdict.proof},
    }


def main():
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="chat-tier1")
    ap.add_argument("--port", type=int, default=8011)
    args = ap.parse_args()
    _STATE["target"] = args.target
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
