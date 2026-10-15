"""secagent-eval: predict (model/oracle/null çıktısı üret) ve score (puanla)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import prompt
from ..schema import iter_valid
from . import metrics
from .backends import build_generator


def _load(path: str, limit: int | None):
    examples = list(iter_valid(path))
    return examples[:limit] if limit else examples


def cmd_predict(a: argparse.Namespace) -> int:
    examples = _load(a.gold, a.limit)
    if a.backend == "oracle":                       # üst sınır: altın çıktıyı aynen üretir
        outputs = [prompt.render_target(e.output) for e in examples]
    else:
        gen = build_generator(a.backend, a.model, a.adapter, a.max_tokens)
        outputs = []
        for i, e in enumerate(examples, 1):
            outputs.append(gen(e.input))
            if i % 10 == 0:
                print(f"[{i}/{len(examples)}]", file=sys.stderr, flush=True)
    metrics.write_predictions(a.out, outputs, keys=[metrics.example_key(e) for e in examples])
    print(f"{len(outputs)} tahmin yazıldı -> {a.out}")
    return 0


def _fmt(v) -> str:
    return "-" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def cmd_score(a: argparse.Namespace) -> int:
    examples = _load(a.gold, a.limit)
    rows = metrics.read_prediction_rows(a.pred)[:len(examples)]
    if len(rows) != len(examples):
        print(f"HATA: {len(examples)} örnek, {len(rows)} tahmin", file=sys.stderr)
        return 2
    for i, (e, r) in enumerate(zip(examples, rows)):
        if r.get("key") is not None and r["key"] != metrics.example_key(e):
            print(f"HATA: {i}. tahmin bu altın dosyadaki örnekle uyuşmuyor (başka/yeni test kümesi?)",
                  file=sys.stderr)
            return 2
    if any(r.get("key") is None for r in rows):
        print("UYARI: tahmin dosyasında örnek kimliği yok; eşleşme yalnızca sıraya güveniyor.",
              file=sys.stderr)
    preds = [r["output"] for r in rows]
    scores = [metrics.score_example(e, p, a.line_tol) for e, p in zip(examples, preds)]
    rep = metrics.report(scores)
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    keys = ["examples", "parse_rate", "precision", "recall", "f1", "fp_rejection_rate",
            "fp_explicit_rate", "clean_false_alarm_rate", "bad_line_rate", "bad_evidence_rate", "logic_recall",
            "scanner_missed_recall"]
    pr = rep["overall"]["parse_rate"]
    if pr is not None and pr < 0.95:
        print(f"UYARI: ayrıştırma oranı {pr:.2f}; yanlış alarm/temiz oranları yalnızca ayrıştırılan "
              "örneklere aittir, model çıktısını düzeltmeden yorumlama.", file=sys.stderr)
    print("GENEL: " + "  ".join(f"{k}={_fmt(rep['overall'][k])}" for k in keys))
    print(f"{'dil':12} " + " ".join(f"{k[:9]:>9}" for k in keys[:5] + keys[5:8]))
    for lang, r in rep["by_language"].items():
        print(f"{lang:12} " + " ".join(f"{_fmt(r[k]):>9}" for k in keys[:5] + keys[5:8]))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secagent-eval")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("predict", help="tahmin dosyası üret")
    p.add_argument("--gold", required=True, help="altın JSONL (test.jsonl vb.)")
    p.add_argument("--backend", choices=["null", "oracle", "mlx", "hf"], required=True)
    p.add_argument("--model"), p.add_argument("--adapter")
    p.add_argument("--max-tokens", type=int, default=1024)
    p.add_argument("--limit", type=int)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_predict)
    s = sub.add_parser("score", help="tahminleri puanla")
    s.add_argument("--gold", required=True), s.add_argument("--pred", required=True)
    s.add_argument("--line-tol", type=int, default=metrics.DEFAULT_LINE_TOL)
    s.add_argument("--limit", type=int), s.add_argument("--out", help="JSON rapor")
    s.set_defaults(fn=cmd_score)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
