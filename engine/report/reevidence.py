"""Re-run the evidence phase on an existing campaign's stored successes.

Reproduction is independent of discovery, so we can re-verify already-discovered
successes at a different trial count without repeating the whole campaign. Used
to re-classify the real-model findings with N=10 (tighter Wilson CIs) after the
CONFIRMED threshold was made relative to N.
"""
from __future__ import annotations

import asyncio
import sys

from ..core.config import CampaignConfig
from ..core.factory import make_factory
from ..core.store import Store
from ..evidence.engine import EvidenceEngine
from ..judge.judge import Judge


async def rerun(db_path: str, trials: int = 10) -> int:
    store = Store(db_path)
    cid = store.latest_campaign()
    cfg = CampaignConfig.model_validate(store.campaign_manifest(cid)["campaign_config"])
    factory = make_factory(cfg.targets)
    successes = store.successful_attempts(cid)
    print(f"re-verifying {len(successes)} successful attempts at N={trials} …")

    evidence = EvidenceEngine(Judge(), factory, cfg.seed, cid, trials=trials)
    findings = await evidence.build_findings(successes)

    store.conn.execute("DELETE FROM findings WHERE campaign_id=?", (cid,))
    store.conn.commit()
    for f in findings:
        store.record_finding(f, cid)
    from collections import Counter
    print("findings:", len(findings), dict(Counter(f.reproduction.status for f in findings)))
    return len(findings)


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else "artifacts/loki_real.db"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    asyncio.run(rerun(db, n))
