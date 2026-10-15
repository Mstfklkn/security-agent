"""
Değerlendirme metrikleri (saf fonksiyonlar; model çalıştırmaz).

Tanımlar (bir model çıktısı bir örneğe karşı puanlanır):
- Eşleşme: bulgular aynı/ilgili CWE ailesinde (mappings.cwe_related) VE |satır farkı| <= tol.
  Bire bir eşleşir (bir tahmin en çok bir altın bulguyu karşılar).
- tp/fn/spurious: gerçek (false_positive=False) altın bulgular için. spurious = hiçbir altın
  bulguya (gerçek ya da yanlış alarm) karşılık gelmeyen gerçek tahmin.
- Yanlış alarm ayıklama: altın false_positive bulgusunu model GERÇEK diye bildirirse yanlış
  (fp_wrong); false_positive=true işaretlerse AÇIKÇA doğru (fp_explicit); hiç anmazsa sessiz
  atlama (fp_omitted). fp_rejection_rate = (explicit+omitted)/toplam; fp_explicit_rate yalnızca
  açıkça ayıklananlar: hep 'bulgu yok' diyen model rejection'da %100 alır ama explicit'te %0.
  Çözümlenemeyen çıktılar bu oranlara GİRMEZ (fp_unparsed/clean_unparsed ayrı sayılır);
  parse_rate düşükse oranlar yalnızca ayrıştırılan örneklere aittir.
- Temiz örnek: altın bulgusu olmayan örnek; model gerçek bulgu bildirirse clean_flagged.
- Halüsinasyon: satır numarası kod aralığı dışında/yok (bad_line) veya `evidence` kodda
  (boşluktan bağımsız) bulunmuyor (bad_evidence).
- logic_recall: mantık hatası CWE'lerinde (mappings.LOGIC_CWES) recall.
  scanner_missed_recall: tarayıcı çıktısı BOŞ örneklerdeki recall (araçların kaçırdıkları).
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable

from .. import mappings, prompt
from ..schema import Example, ExampleInput, Finding

DEFAULT_LINE_TOL = 2


def _squash(text: str) -> str:
    return "".join(text.split())


def _match(gold: list[Finding], pred: list[Finding], tol: int) -> list[tuple[int, int]]:
    cands = []
    for gi, g in enumerate(gold):
        for pi, p in enumerate(pred):
            if (mappings.cwe_related(g.cwe, p.cwe) and isinstance(g.line, int)
                    and isinstance(p.line, int) and abs(g.line - p.line) <= tol):
                cands.append((abs(g.line - p.line), gi, pi))
    used_g, used_p, pairs = set(), set(), []
    for _d, gi, pi in sorted(cands):
        if gi not in used_g and pi not in used_p:
            used_g.add(gi), used_p.add(pi)
            pairs.append((gi, pi))
    return pairs


def score_example(ex: Example, raw_output: str | None, line_tol: int = DEFAULT_LINE_TOL) -> dict:
    out = prompt.parse_output(raw_output)
    pred = out.findings if out else []
    gold_real = [f for f in ex.output.findings if not f.false_positive]
    gold_fp = [f for f in ex.output.findings if f.false_positive]
    pred_real = [f for f in pred if not f.false_positive]

    pairs = _match(gold_real, pred_real, line_tol)
    matched_pred = {pi for _gi, pi in pairs}
    leftover = [p for i, p in enumerate(pred_real) if i not in matched_pred]
    pred_fp = [f for f in pred if f.false_positive]
    explicit_pairs = _match(gold_fp, pred_fp, line_tol)
    explicit_idx = {gi for gi, _pi in explicit_pairs}
    rest_fp = [f for i, f in enumerate(gold_fp) if i not in explicit_idx]
    fp_wrong = len(_match(rest_fp, leftover, line_tol))
    parsed = out is not None

    code = ex.input.code
    n_lines = len(code.splitlines())
    squashed_code = _squash(code)
    bad_line = sum(1 for f in pred if not isinstance(f.line, int) or not 1 <= f.line <= n_lines)
    bad_evidence = sum(1 for f in pred if not _squash(f.evidence) or _squash(f.evidence) not in squashed_code)

    logic_gold = sum(1 for f in gold_real if mappings.is_logic(f.cwe))
    logic_tp = sum(1 for gi, _pi in pairs if mappings.is_logic(gold_real[gi].cwe))
    scanner_empty = not ex.input.scanner_output.strip()
    is_clean = parsed and not ex.output.findings
    fp_explicit = len(explicit_pairs) if parsed else 0
    fp_wrong = fp_wrong if parsed else 0
    fp_omitted = len(gold_fp) - fp_explicit - fp_wrong if parsed else 0
    return {
        "parsed": out is not None, "language": ex.input.language,
        "gold_real": len(gold_real), "pred_real": len(pred_real), "pred_total": len(pred),
        "tp": len(pairs), "fn": len(gold_real) - len(pairs),
        "spurious": len(leftover) - fp_wrong if parsed else 0,
        "fp_total": len(gold_fp) if parsed else 0, "fp_unparsed": 0 if parsed else len(gold_fp),
        "fp_wrong": fp_wrong, "fp_explicit": fp_explicit, "fp_omitted": fp_omitted,
        "fp_right": fp_explicit + fp_omitted,
        "clean": bool(is_clean), "clean_unparsed": bool(not parsed and not ex.output.findings),
        "clean_flagged": bool(is_clean and pred_real),
        "bad_line": bad_line, "bad_evidence": bad_evidence,
        "logic_gold": logic_gold, "logic_tp": logic_tp,
        "miss_gold": len(gold_real) if scanner_empty else 0,
        "miss_tp": len(pairs) if scanner_empty else 0,
    }


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def aggregate(scores: Iterable[dict]) -> dict:
    s = list(scores)
    tot = lambda k: sum(x[k] for x in s)  # noqa: E731
    precision = _ratio(tot("tp"), tot("pred_real"))
    recall = _ratio(tot("tp"), tot("gold_real"))
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision and recall else (0.0 if precision is not None and recall is not None else None))
    return {
        "examples": len(s), "parse_rate": _ratio(tot("parsed"), len(s)),
        "precision": precision, "recall": recall, "f1": f1,
        "fp_rejection_rate": _ratio(tot("fp_right"), tot("fp_total")),
        "fp_explicit_rate": _ratio(tot("fp_explicit"), tot("fp_total")),
        "clean_false_alarm_rate": _ratio(tot("clean_flagged"), tot("clean")),
        "bad_line_rate": _ratio(tot("bad_line"), tot("pred_total")),
        "bad_evidence_rate": _ratio(tot("bad_evidence"), tot("pred_total")),
        "logic_recall": _ratio(tot("logic_tp"), tot("logic_gold")),
        "scanner_missed_recall": _ratio(tot("miss_tp"), tot("miss_gold")),
        "counts": {"gold_real": tot("gold_real"), "tp": tot("tp"), "fn": tot("fn"),
                   "spurious": tot("spurious"), "fp_total": tot("fp_total"),
                   "unparsed": len(s) - tot("parsed"),
                   "clean": tot("clean"), "logic_gold": tot("logic_gold"),
                   "scanner_missed_gold": tot("miss_gold")},
    }


def report(scores: list[dict]) -> dict:
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for sc in scores:
        by_lang[sc["language"]].append(sc)
    return {"overall": aggregate(scores),
            "by_language": {lang: aggregate(v) for lang, v in sorted(by_lang.items())}}


def run_predictions(examples: Iterable[Example], generate: Callable[[ExampleInput], str]) -> list[str]:
    """Her örneğin girdisi için `generate` çağrılır (model arka ucu ya da sahte üretici)."""
    return [generate(ex.input) for ex in examples]


def example_key(ex: Example) -> str:
    """Örnek kimliği (dosya+dil+kod özeti). Tahmin dosyası başka/yeni bir test kümesine ait
    olursa puanlama sessizce yanlış örneklerle eşleşmesin diye."""
    raw = f"{ex.input.file}\0{ex.input.language}\0{ex.input.code}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def write_predictions(path: str | Path, outputs: list[str], keys: list[str] | None = None) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i, text in enumerate(outputs):
            row = {"i": i, "output": text, **({"key": keys[i]} if keys else {})}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_prediction_rows(path: str | Path) -> list[dict]:
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    return sorted(rows, key=lambda r: r["i"])


def read_predictions(path: str | Path) -> list[str]:
    return [r["output"] for r in read_prediction_rows(path)]
