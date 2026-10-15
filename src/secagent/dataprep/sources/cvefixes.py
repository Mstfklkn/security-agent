"""
CVEfixes okuyucusu (SQLite).

Girdi: CVEfixes.db yolu (Zenodo SQL dökümünden `gzcat ... | sqlite3` ile üretilir).
Her (CVE, değişen dosya) çiftinden iki kayıt çıkar:
  - zafiyetli sürüm (code_before)  -> CWE bulgusu, false_positive=False
  - düzeltilmiş sürüm (code_after) -> boş bulgu (temiz örnek)
Düzeltilmiş sürümde tarayıcı hâlâ alarm verirse, o örnek sonraki aşamada
false_positive=True olarak zenginleştirilir (bkz. dataprep/enrich.py).

Tablo/sütun adları CVEfixes şemasına göre (Doc/DataDictionary.md ile doğrulandı).
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Iterator

from ... import mappings
from ...schema import LANGUAGES
from .common import (enclosing_function, first_changed_line, group_key, line_text,
                     removed_lines, template_fix)

LANG_MAP = {
    "python": "python", "java": "java", "kotlin": "kotlin", "c": "cpp",
    "c++": "cpp", "c#": "csharp", "typescript": "typescript",
    "javascript": "javascript", "go": "go", "rust": "rust", "php": "php",
    "ruby": "ruby", "swift": "swift",
}
_CWE = re.compile(r"^CWE-\d+$")
MAX_CODE_CHARS = 12_000
MAX_FUNC_CHARS = 6_000
MAX_FUNCS_PER_FILE = 2

# Sıra, dosya kimliğinin deterministik karıştırmasıdır: dil başına örneklemede
# tek bir repo/CVE kümesinin baskın çıkmasını önler, her çalıştırmada aynıdır.
_QUERY = """
SELECT DISTINCT fx.cve_id, fx.repo_url, fc.file_change_id, fc.filename, fc.diff,
       fc.code_before, fc.code_after, fc.programming_language
FROM fixes fx
JOIN file_change fc ON fc.hash = fx.hash
WHERE fc.code_before IS NOT NULL AND fc.code_after IS NOT NULL
  AND fc.code_before != 'None' AND fc.code_after != 'None'
  AND fx.cve_id IN (SELECT cve_id FROM cwe_classification{cwe_clause})
  AND lower(fc.programming_language) IN ({marks})
ORDER BY (fc.rowid * 2654435761) % 1000003
"""


def _methods(conn: sqlite3.Connection, fc_id: str, before: bool
             ) -> list[tuple[str, int, int]]:
    return [(n, s, e) for n, s, e, _ in _methods_with_code(conn, fc_id, before)]


def _methods_with_code(conn: sqlite3.Connection, fc_id: str, before: bool
                       ) -> list[tuple[str, int, int, str]]:
    flag = "True" if before else "False"
    rows = conn.execute(
        "SELECT name, start_line, end_line, code FROM method_change "
        "WHERE file_change_id = ? AND before_change = ?", (fc_id, flag))
    out = []
    for n, s, e, code in rows:
        try:
            out.append((n, int(s), int(e), code or ""))
        except (TypeError, ValueError):
            continue
    return out


def _cvss(conn: sqlite3.Connection, cve_id: str) -> tuple[float, str] | None:
    """NVD'den gelen GERÇEK CVSS v3; yoksa/bozuksa None (varsayılan devreye girer)."""
    try:
        row = conn.execute(
            "SELECT cvss3_base_score, cvss3_vector_string FROM cve WHERE cve_id = ?",
            (cve_id,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if not row:
        return None
    try:
        score, vector = float(row[0]), str(row[1])
    except (TypeError, ValueError):
        return None
    if not 0.0 <= score <= 10.0 or not vector.startswith("CVSS:3"):
        return None
    return score, vector


def _context(conn: sqlite3.Connection, row: tuple,
             cwes: frozenset[str] | None = None) -> tuple[str, str] | None:
    """(normalize dil, CWE) — dil desteklenmiyorsa, geçerli CWE yoksa veya dosya
    çok büyükse None. _pair ve _function_pairs ortak girişi."""
    cve_id, _repo, _fc_id, _filename, _diff, before, after, lang = row
    language = LANG_MAP.get((lang or "").strip().lower())
    if language is None or language not in LANGUAGES:
        return None
    found = [c for (c,) in conn.execute(
        "SELECT cwe_id FROM cwe_classification WHERE cve_id = ?", (cve_id,))]
    cwe = next((c for c in found if _CWE.match(c or "") and (cwes is None or c in cwes)), None)
    if cwe is None or max(len(before), len(after)) > MAX_CODE_CHARS:
        return None
    return language, cwe


def cvss_map(db_path: str | Path) -> dict[str, tuple[float, str]]:
    """Tüm CVE'ler için gerçek (NVD) CVSS v3: {cve_id: (skor, vektör)}. Başka kaynaklar
    (PrimeVul) CVE kimliğiyle bu tablodan gerçek CVSS alır."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        out = {}
        for cve_id, score, vector in conn.execute(
                "SELECT cve_id, cvss3_base_score, cvss3_vector_string FROM cve"):
            try:
                s, v = float(score), str(vector)
            except (TypeError, ValueError):
                continue
            if 0.0 <= s <= 10.0 and v.startswith("CVSS:3"):
                out[cve_id] = (s, v)
        return out
    finally:
        conn.close()


def _pair(conn: sqlite3.Connection, row: tuple,
          cwes: frozenset[str] | None = None) -> tuple[dict, dict] | None:
    """Bir satırı (zafiyetli, temiz) kayıt çiftine çevirir; uygun değilse None."""
    cve_id, repo, fc_id, filename, diff, before, after, lang = row
    context = _context(conn, row, cwes)
    if context is None:
        return None
    language, cwe = context
    line = first_changed_line(diff or "", before)
    if line is None:
        return None

    title = mappings.title_for(cwe)
    group = group_key(repo or cve_id)
    real_cvss = _cvss(conn, cve_id)
    finding = {
        "cwe": cwe, "line": line,
        "function": enclosing_function(iter(_methods(conn, fc_id, True)), line),
        "title": title[:160],
        "evidence": line_text(before, line),
        "fix": template_fix(title, diff or ""),
        "cve_id": cve_id,
        **({"cvss": list(real_cvss)} if real_cvss else {}),
    }
    vulnerable = {
        "file": filename, "language": language, "code": before,
        "scanner_output": "", "group": group, "pair_cwe": cwe,
        "findings": [finding],
        "summary": f"{filename} dosyasında {title} bulgusu (upstream düzeltmesinden).",
    }
    clean = {
        "file": filename, "language": language, "code": after,
        "scanner_output": "", "group": group, "pair_cwe": cwe, "findings": [],
        "summary": "Tarayıcı ve inceleme sonucu bulgu yok (düzeltilmiş sürüm).",
    }
    return vulnerable, clean


def _slice_matches(full: str, start: int, end: int, code: str) -> bool:
    """method_change satır aralığı dosya içeriğiyle uyuşuyor mu (CVEfixes'ta ~%98)."""
    seg = "\n".join(full.splitlines()[start - 1:end])
    return bool(code.strip()) and seg.strip() == code.strip()


def _function_pairs(conn: sqlite3.Connection, row: tuple,
                    cwes: frozenset[str] | None = None) -> list[tuple[dict, dict]]:
    """Değişen her fonksiyon için (zafiyetli, temiz) kayıt çifti.

    Tarayıcı DOSYA üzerinde çalışır (scan_code); model yalnızca fonksiyonu ve
    fonksiyon içine düşen alarmları görür (çalışma anındaki parçalamayla aynı)."""
    cve_id, repo, fc_id, filename, diff, before, after, lang = row
    context = _context(conn, row, cwes)
    if context is None:
        return []
    language, cwe = context

    changed = set(removed_lines(diff or ""))
    before_lines = before.splitlines()
    old = _methods_with_code(conn, fc_id, True)
    new = _methods_with_code(conn, fc_id, False)
    new_by_name: dict[str, list] = {}
    for m in new:
        new_by_name.setdefault(m[0], []).append(m)
    old_names = [m[0] for m in old]

    title = mappings.title_for(cwe)
    real_cvss = _cvss(conn, cve_id)
    group = group_key(repo or cve_id)
    pairs: list[tuple[dict, dict]] = []
    for name, s, e, code in sorted(old, key=lambda m: m[2] - m[1]):
        lines = code.splitlines()
        hits = [n for n in changed
                if s <= n <= e and n <= len(before_lines) and before_lines[n - 1].strip()]
        counterpart = new_by_name.get(name, [])
        if (not hits or len(counterpart) != 1 or old_names.count(name) != 1
                or len(code) > MAX_FUNC_CHARS or len(lines) < 2
                or not _slice_matches(before, s, e, code)):
            continue
        _, ns, ne, ncode = counterpart[0]
        if len(ncode) > MAX_FUNC_CHARS or not _slice_matches(after, ns, ne, ncode):
            continue
        rel = min(hits) - s + 1
        finding = {
            "cwe": cwe, "line": rel, "function": name,
            "title": title[:160],
            "evidence": line_text(code, rel),
            "fix": template_fix(title, diff or ""),
            "cve_id": cve_id,
            **({"cvss": list(real_cvss)} if real_cvss else {}),
        }
        pairs.append(({
            "file": filename, "language": language, "code": code,
            "scan_code": before, "scan_start": s, "scan_end": e,
            "scanner_output": "", "group": group, "pair_cwe": cwe,
            "findings": [finding],
            "summary": f"{name} fonksiyonunda {title} bulgusu (upstream düzeltmesinden).",
        }, {
            "file": filename, "language": language, "code": ncode,
            "scan_code": after, "scan_start": ns, "scan_end": ne,
            "scanner_output": "", "group": group, "pair_cwe": cwe, "findings": [],
            "summary": "Tarayıcı ve inceleme sonucu bulgu yok (düzeltilmiş fonksiyon).",
        }))
        if len(pairs) >= MAX_FUNCS_PER_FILE:
            break
    return pairs


def _pairs_for_language(conn: sqlite3.Connection, language: str,
                        granularity: str = "file",
                        cwes: frozenset[str] | None = None) -> Iterator[tuple[dict, dict]]:
    raws = [raw for raw, norm in LANG_MAP.items() if norm == language]
    clause = f" WHERE cwe_id IN ({','.join('?' * len(cwes))})" if cwes else ""
    query = _QUERY.format(marks=",".join("?" * len(raws)), cwe_clause=clause)
    params = [*(sorted(cwes) if cwes else []), *raws]
    for row in conn.execute(query, params):
        if granularity in ("file", "both"):
            pair = _pair(conn, row, cwes)
            if pair is not None:
                yield pair
        if granularity in ("function", "both"):
            yield from _function_pairs(conn, row, cwes)


def read(db_path: str | Path, limit: int | None = None,
         per_language: int | None = None, granularity: str = "file",
         cwes: frozenset[str] | set[str] | None = None) -> Iterator[dict]:
    """limit: toplam çift üst sınırı. per_language: her normalize dilden en çok N
    çift. granularity: file | function | both (function: değişen fonksiyon düzeyi).
    cwes: yalnızca bu CWE'lerin CVE'leri (odaklı örnekleme, örn. mappings.LOGIC_CWES)."""
    cwes = frozenset(cwes) if cwes else None
    if granularity not in ("file", "function", "both"):
        raise ValueError(f"geçersiz granularity: {granularity!r}")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        total = 0
        for language in sorted(set(LANG_MAP.values())):
            taken = 0
            for vulnerable, clean in _pairs_for_language(conn, language, granularity, cwes):
                if (limit and total >= limit) or (per_language and taken >= per_language):
                    break
                yield vulnerable
                yield clean
                taken += 1
                total += 1
            if limit and total >= limit:
                return
    finally:
        conn.close()
