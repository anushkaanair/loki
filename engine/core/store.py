"""SQLite-backed run log and findings store.

Everything the report shows is derived from these tables by code — no
hand-written numbers ever reach the report . The store is the
single source of truth for a campaign.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from .config import ARTIFACTS
from .types import Attempt, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT,
    seed INTEGER,
    manifest TEXT,
    started_at REAL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY,
    campaign_id TEXT,
    generation INTEGER,
    target TEXT,
    technique_family TEXT,
    owasp_category TEXT,
    success INTEGER,
    partial INTEGER,
    confidence REAL,
    severity TEXT,
    fitness REAL,
    latency_s REAL,
    seed INTEGER,
    created_at REAL,
    blob TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_campaign ON attempts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_attempts_target ON attempts(target);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    campaign_id TEXT,
    target TEXT,
    owasp_category TEXT,
    severity TEXT,
    technique_family TEXT,
    repro_status TEXT,
    repro_rate REAL,
    blob TEXT
);
CREATE TABLE IF NOT EXISTS judge_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT,
    attempt_id TEXT,
    canary INTEGER,
    classifier REAL,
    llm_judge TEXT,
    human_label INTEGER,
    blob TEXT
);
"""


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else ARTIFACTS / "loki.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ---- campaigns -------------------------------------------------------
    def start_campaign(self, cid: str, name: str, seed: int, manifest: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO campaigns(id,name,seed,manifest,started_at) VALUES(?,?,?,?,?)",
            (cid, name, seed, json.dumps(manifest), time.time()),
        )
        self.conn.commit()

    def finish_campaign(self, cid: str) -> None:
        self.conn.execute("UPDATE campaigns SET finished_at=? WHERE id=?", (time.time(), cid))
        self.conn.commit()

    def latest_campaign(self) -> str | None:
        row = self.conn.execute(
            "SELECT id FROM campaigns ORDER BY started_at DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    def campaign_manifest(self, cid: str) -> dict:
        row = self.conn.execute(
            "SELECT manifest FROM campaigns WHERE id=?", (cid,)).fetchone()
        return json.loads(row["manifest"]) if row and row["manifest"] else {}

    def campaign_of_finding(self, finding_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT campaign_id FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return row["campaign_id"] if row else None

    # ---- attempts --------------------------------------------------------
    def record_attempt(self, a: Attempt) -> None:
        v = a.verdict
        self.conn.execute(
            """INSERT OR REPLACE INTO attempts
               (id,campaign_id,generation,target,technique_family,owasp_category,
                success,partial,confidence,severity,fitness,latency_s,seed,created_at,blob)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                a.id, a.campaign_id, a.generation, a.target, a.technique_family,
                a.owasp_category.value,
                int(v.success) if v else 0,
                int(v.partial) if v else 0,
                v.confidence if v else 0.0,
                v.severity.value if v else "Low",
                a.fitness,
                a.response.latency_s if a.response else 0.0,
                a.seed, a.created_at,
                a.model_dump_json(),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def attempts(self, campaign_id: str | None = None) -> list[Attempt]:
        q = "SELECT blob FROM attempts"
        args: tuple = ()
        if campaign_id:
            q += " WHERE campaign_id=?"
            args = (campaign_id,)
        return [Attempt.model_validate_json(r["blob"]) for r in self.conn.execute(q, args)]

    def successful_attempts(self, campaign_id: str) -> list[Attempt]:
        rows = self.conn.execute(
            "SELECT blob FROM attempts WHERE campaign_id=? AND success=1", (campaign_id,)
        )
        return [Attempt.model_validate_json(r["blob"]) for r in rows]

    # ---- findings --------------------------------------------------------
    def record_finding(self, f: Finding, campaign_id: str) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id,campaign_id,target,owasp_category,severity,technique_family,
                repro_status,repro_rate,blob) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                f.finding_id, campaign_id, f.target.get("name", ""),
                f.owasp_category.value, f.severity.value, f.technique_family,
                f.reproduction.status, f.reproduction.rate, f.model_dump_json(),
            ),
        )
        self.conn.commit()

    def findings(self, campaign_id: str | None = None) -> list[Finding]:
        q = "SELECT blob FROM findings"
        args: tuple = ()
        if campaign_id:
            q += " WHERE campaign_id=?"
            args = (campaign_id,)
        return [Finding.model_validate_json(r["blob"]) for r in self.conn.execute(q, args)]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self.conn.execute(
            "SELECT blob FROM findings WHERE finding_id=?", (finding_id,)
        ).fetchone()
        return Finding.model_validate_json(row["blob"]) if row else None

    # ---- judge labels ----------------------------------------------------
    def record_judge_label(self, campaign_id: str, attempt_id: str, canary: int | None,
                           classifier: float | None, llm_judge: str | None,
                           human_label: int | None = None, blob: dict | None = None) -> None:
        self.conn.execute(
            """INSERT INTO judge_labels
               (campaign_id,attempt_id,canary,classifier,llm_judge,human_label,blob)
               VALUES(?,?,?,?,?,?,?)""",
            (campaign_id, attempt_id, canary, classifier, llm_judge, human_label,
             json.dumps(blob or {})),
        )
        self.conn.commit()

    def judge_labels(self, campaign_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM judge_labels WHERE campaign_id=?", (campaign_id,)
        )
        return [dict(r) for r in rows]

    def close(self) -> None:
        self.conn.close()
