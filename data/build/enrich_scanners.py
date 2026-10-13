"""
Tarayıcı zenginleştirme: kayıtlara GERÇEK tarayıcı çıktısını ekler ve
düzeltilmiş koddaki kalıntı alarmlardan yanlış-alarm (false_positive) örnekleri üretir.

Neden: eğitimdeki scanner_output, çalışma anındakiyle aynı dağılımdan
gelmeli. Elle yazılmış çıktı bu dağılımı taklit edemez.

Etiket kuralları (temkinli — gürültülü etiket, etiketsiz olmaktan kötüdür):
  - Zafiyetli kayıt: bulgu CWE'si dışında bir alarm varsa kayıt BELİRSİZDİR.
  - Temiz (düzeltilmiş) kayıt: alarmın CWE'si yamanın giderdiği CWE ile aynıysa
    false_positive=True bulgu olur; farklı veya CWE'siz alarm varsa BELİRSİZDİR.
  - Belirsiz kayıt: --ambiguous skip (varsayılan) atlar; drop o alarmları
    scanner_output'tan çıkarıp kaydı tutar.

Toplu çalışır: kayıt başına bir alt klasör, dil başına tek tarama.
Projeye özgü araçlar (osv, gosec, govulncheck, brakeman) tek dosyalık
örneklerde anlamsız olduğundan atlanır.
"""
from __future__ import annotations

import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanners"))
import run_scanners as rs  # noqa: E402

ScanFn = Callable[[str, str], list[dict]]

_PROJECT_LEVEL = {"run_osv", "run_gosec", "run_govulncheck", "run_brakeman"}
_EXT = {
    "python": ".py", "java": ".java", "kotlin": ".kt", "cpp": ".cpp",
    "csharp": ".cs", "typescript": ".ts", "javascript": ".js", "go": ".go",
    "rust": ".rs", "php": ".php", "ruby": ".rb", "swift": ".swift",
    "terraform": ".tf", "kubernetes": ".yaml",
}
_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_DIR = re.compile(r"^rec_(\d+)$")
MAX_ALARMS = 20


def _safe_name(rec: dict) -> str:
    """Veri setindeki dosya adı güvenilmezdir: yalnızca temiz bir taban ad kullan."""
    if rec["language"] == "docker":
        return "Dockerfile"
    base = _SAFE.sub("_", Path(rec["file"]).name) or "file"
    ext = _EXT.get(rec["language"], "")
    return base if base.endswith(ext) else base + ext


def snippet_scan(path: str, language: str) -> list[dict]:
    """Yalnızca tek dosyada anlamlı tarayıcıları çalıştırır."""
    from dataclasses import asdict
    runners = rs._BY_LANG.get(rs.normalize_language(language), [])
    return [asdict(f) for r in runners if r.__name__ not in _PROJECT_LEVEL
            for f in r(path)]


def _record_index(file: str) -> int | None:
    for part in Path(file).parts:
        m = _DIR.match(part)
        if m:
            return int(m.group(1))
    return None


def format_alarm(a: dict, file: str) -> str:
    msg = " ".join((a.get("message") or "").split())[:200]
    return (f"{a['tool']}: [{a['rule_id']}] {msg} "
            f"({file}:{a.get('line')}, severity: {a.get('severity')})")


def format_output(alarms: list[dict], file: str) -> str:
    ordered = sorted(alarms, key=lambda a: (a.get("line") or 0, a["tool"]))
    return "\n".join(format_alarm(a, file) for a in ordered[:MAX_ALARMS])


def _fp_finding(alarm: dict, code: str) -> dict | None:
    line = alarm.get("line")
    lines = code.splitlines()
    if not isinstance(line, int) or not 1 <= line <= len(lines):
        return None
    return {
        "cwe": alarm["cwe"], "line": line,
        "title": f"Tarayıcı uyarısı ({alarm['tool']} {alarm['rule_id']}) — yanlış alarm"[:160],
        "evidence": lines[line - 1].strip() or "(boş satır)",
        "fix": ("Düzeltme gerekmiyor: bu kod, ilgili zafiyetin upstream "
                "düzeltmesinden sonraki sürümdür; tarayıcı uyarısı yanlış alarm."),
        "false_positive": True,
    }


def label_record(rec: dict, alarms: list[dict], ambiguous: str = "skip") -> dict | None:
    """Tek kaydı etiketler. None: kayıt atlanmalı."""
    gold = rec["findings"][0]["cwe"] if rec.get("findings") else rec.get("pair_cwe")
    clear = [a for a in alarms if a.get("cwe") == gold and isinstance(a.get("line"), int)]
    unclear = [a for a in alarms if a not in clear]
    if unclear and ambiguous == "skip":
        return None

    if rec.get("findings"):
        return {**rec, "scanner_output": format_output(clear, rec["file"])}

    fps, seen = [], set()
    for a in clear:
        f = _fp_finding(a, rec["code"])
        if f is None:
            if ambiguous == "skip":
                return None
            continue
        if (f["cwe"], f["line"]) not in seen:
            seen.add((f["cwe"], f["line"]))
            fps.append(f)
    summary = ("Tarayıcı uyarıları yanlış alarm; düzeltilmiş kodda gerçek bulgu yok."
               if fps else rec.get("summary", ""))
    return {**rec, "scanner_output": format_output(clear, rec["file"]),
            "findings": fps, "summary": summary}


def _scan_batch(batch: list[tuple[int, dict]], language: str, scan_fn: ScanFn
                ) -> dict[int, list[dict]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for idx, rec in batch:
            d = root / f"rec_{idx}"
            d.mkdir()
            (d / _safe_name(rec)).write_text(rec["code"], encoding="utf-8")
        found: dict[int, list[dict]] = defaultdict(list)
        for a in scan_fn(str(root), language):
            idx = _record_index(a.get("file", ""))
            if idx is not None:
                found[idx].append(a)
    return found


def enrich(records: Iterable[dict], batch_size: int = 200, ambiguous: str = "skip",
           scan_fn: ScanFn = snippet_scan) -> tuple[list[dict], dict[str, int]]:
    """(zenginleştirilmiş kayıtlar, sayaçlar) döndürür; girdiyi değiştirmez."""
    recs = list(records)
    by_lang: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for i, rec in enumerate(recs):
        if rec.get("scanner_output"):          # elle yazılmış örneğe dokunma
            continue
        by_lang[rec["language"]].append((i, rec))

    out = list(recs)
    stats = {"enriched": 0, "skipped_ambiguous": 0, "new_false_positive": 0}
    for lang, items in by_lang.items():
        for s in range(0, len(items), batch_size):
            batch = items[s:s + batch_size]
            alarms = _scan_batch(batch, lang, scan_fn)
            for idx, rec in batch:
                labeled = label_record(rec, alarms.get(idx, []), ambiguous)
                if labeled is None:
                    out[idx] = None
                    stats["skipped_ambiguous"] += 1
                    continue
                out[idx] = labeled
                stats["enriched"] += 1
                if not rec.get("findings"):
                    stats["new_false_positive"] += len(labeled["findings"])
    return [r for r in out if r is not None], stats
