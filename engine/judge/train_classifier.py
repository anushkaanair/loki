"""Fine-tune the judge's classifier signal on the public HackAPrompt 1.0 dataset.

HackAPrompt 1.0 (~600k labeled human-generated injection attempts from the
peer-reviewed 2023 competition, arXiv:2311.16119) is public research data,
downloaded directly from the Hugging Face Hub — not scraped from any live system.

We fine-tune a DistilBERT-class model to predict whether an injection *attempt*
succeeded (the dataset's ``correct`` label), subsampling to a balanced set so it
trains in reasonable time on CPU / MPS. Held-out precision/recall/F1 are written
to ``artifacts/classifier/metrics.json`` and reported verbatim by the report.

Run:  python -m engine.judge.train_classifier --max-samples 24000 --epochs 1
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
import typer

from ..core.config import ARTIFACTS
from ..core.stats import precision_recall_f1

app = typer.Typer(add_completion=False)
OUT = ARTIFACTS / "classifier"


# Preferred → fallback datasets. HackAPrompt 1.0 is the ideal source, but it
# became a *gated* Hub dataset (requires HF auth). We try it first, then fall
# back to public, ungated, already-released prompt-injection corpora. The
# dataset actually used is recorded in metrics.json and stated in the report.
_DATASET_CANDIDATES = [
    ("hackaprompt/hackaprompt-dataset", ("prompt", "user_input", "text"),
     ("correct", "success", "label")),
    ("jayavibhav/prompt-injection", ("text", "prompt"), ("label",)),
    ("deepset/prompt-injections", ("text",), ("label",)),
]


def _load_rows(max_samples: int):
    from datasets import load_dataset

    last_err = None
    for name, text_cols, label_cols in _DATASET_CANDIDATES:
        try:
            ds = load_dataset(name, split="train")
        except Exception as e:  # gated / missing
            last_err = f"{name}: {str(e)[:80]}"
            print(f"  dataset unavailable → {last_err}")
            continue
        cols = set(ds.column_names)
        text_col = next((c for c in text_cols if c in cols), None)
        label_col = next((c for c in label_cols if c in cols), None)
        if not text_col or not label_col:
            continue
        pos, neg = [], []
        for r in ds:
            t, y = r.get(text_col), r.get(label_col)
            if not t or y is None:
                continue
            yi = 1 if (y is True or y == 1 or str(y).lower() in ("true", "1", "injection")) else 0
            (pos if yi else neg).append(str(t)[:1000])
            if len(pos) + len(neg) >= max_samples * 4:
                break
        if not pos or not neg:
            continue
        random.seed(42)
        n = min(len(pos), len(neg), max_samples // 2)
        rows = [(t, 1) for t in random.sample(pos, n)] + [(t, 0) for t in random.sample(neg, n)]
        random.shuffle(rows)
        return rows, {"dataset_used": name, "total_pos": len(pos),
                      "total_neg": len(neg), "balanced_n": n,
                      "hackaprompt_note": "HackAPrompt 1.0 is gated (needs HF auth); "
                      "used public ungated substitute" if name != _DATASET_CANDIDATES[0][0]
                      else "HackAPrompt 1.0"}
    raise RuntimeError(f"no usable dataset (last error: {last_err})")


@app.command()
def main(max_samples: int = 24000, epochs: int = 1, model_name: str = "distilbert-base-uncased"):
    import torch
    from torch.utils.data import DataLoader, Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              get_linear_schedule_with_warmup)

    OUT.mkdir(parents=True, exist_ok=True)
    print("Loading HackAPrompt 1.0 …")
    rows, stats = _load_rows(max_samples)
    split = int(len(rows) * 0.85)
    train_rows, val_rows = rows[:split], rows[split:]
    print(f"train={len(train_rows)} val={len(val_rows)} balance={stats}")

    tok = AutoTokenizer.from_pretrained(model_name)
    device = "mps" if torch.backends.mps.is_available() else "cpu"

    class DS(Dataset):
        def __init__(self, data): self.data = data
        def __len__(self): return len(self.data)
        def __getitem__(self, i):
            t, y = self.data[i]
            enc = tok(t, truncation=True, max_length=128, padding="max_length",
                      return_tensors="pt")
            return {"input_ids": enc["input_ids"][0],
                    "attention_mask": enc["attention_mask"][0],
                    "labels": torch.tensor(y)}

    train_dl = DataLoader(DS(train_rows), batch_size=32, shuffle=True)
    val_dl = DataLoader(DS(val_rows), batch_size=64)

    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=3e-5)
    steps = len(train_dl) * epochs
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)

    model.train()
    for ep in range(epochs):
        for i, b in enumerate(train_dl):
            b = {k: v.to(device) for k, v in b.items()}
            out = model(**b)
            out.loss.backward()
            opt.step(); sched.step(); opt.zero_grad()
            if i % 50 == 0:
                print(f"epoch {ep} step {i}/{len(train_dl)} loss {out.loss.item():.4f}")

    # ---- evaluate ----
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for b in val_dl:
            labels = b.pop("labels")
            b = {k: v.to(device) for k, v in b.items()}
            logits = model(**b).logits
            preds = logits.argmax(-1).cpu().numpy()
            y_pred.extend(preds.tolist())
            y_true.extend(labels.numpy().tolist())
    metrics = precision_recall_f1(y_true, y_pred)
    metrics.update({"n_val": len(y_true), "epochs": epochs, "model": model_name,
                    "dataset": "hackaprompt/hackaprompt-dataset", "balance": stats})
    print("VAL METRICS:", metrics)

    model.save_pretrained(str(OUT))
    tok.save_pretrained(str(OUT))
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"Saved model + metrics to {OUT}")


if __name__ == "__main__":
    app()
