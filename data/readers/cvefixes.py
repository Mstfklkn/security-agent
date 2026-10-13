"""
CVEfixes okuyucusu (SQLite dump).

Girdi: CVEfixes.db yolu (Zenodo'dan indirilir, elle verilir).
Her (CVE, değişen dosya) çiftinden iki kayıt çıkar:
  - zafiyetli sürüm (code_before)  -> CWE bulgusu, false_positive=False
  - düzeltilmiş sürüm (code_after) -> boş bulgu (temiz örnek)
Düzeltilmiş sürümde tarayıcı hâlâ alarm verirse, o örnek sonraki aşamada
false_positive=True olarak zenginleştirilir (bkz. build/enrich_scanners.py).

Tablo/sütun adları CVEfixes şemasına göre; eksik sütunlarda sessiz
varsayım yapılmaz, okuyucu hata verir.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "build"))
import mappings  # noqa: E402
from schema import LANGUAGES  # noqa: E402

from .common import (enclosing_function, first_changed_line, line_text,  # noqa: E402
                     template_fix)

LANG_MAP = {
    "python": "python", "java": "java", "kotlin": "kotlin", "c": "cpp",
    "c++": "cpp", "c#": "csharp", "typescript": "typescript",
    "javascript": "javascript", "go": "go", "rust": "rust", "php": "php",
    "ruby": "ruby", "swift": "swift",
}
_CWE = re.compile(r"^CWE-\d+$")
MAX_CODE_CHARS = 12_000

_QUERY = """
SELECT DISTINCT fx.cve_id, fx.repo_url, fc.file_change_id, fc.filename, fc.diff,
       fc.code_before, fc.code_after, fc.programming_language
FROM fixes fx
JOIN file_change fc ON fc.hash = fx.hash
WHERE fc.code_before IS NOT NULL AND fc.code_after IS NOT NULL
  AND fc.code_before != 'None' AND fc.code_after != 'None'
  AND fx.cve_id IN (SELECT cve_id FROM cwe_classification)
"""


def _methods(conn: sqlite3.Connection, fc_id: str, before: bool
             ) -> list[tuple[str, int, int]]:
    flag = "True" if before else "False"
    rows = conn.execute(
        "SELECT name, start_line, end_line FROM method_change "
        "WHERE file_change_id = ? AND before_change = ?", (fc_id, flag))
    return [(n, int(s), int(e)) for n, s, e in rows]


def read(db_path: str | Path, limit: int | None = None) -> Iterator[dict]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        count = 0
        for (cve_id, repo, fc_id, filename, diff, before, after, lang) in conn.execute(_QUERY):
            cwe = None
            language = LANG_MAP.get((lang or "").strip().lower())
            if language is None or language not in LANGUAGES:
                continue
            cwe_row = conn.execute(
                "SELECT cwe_id FROM cwe_classification WHERE cve_id = ?", (cve_id,)
            ).fetchall()
            cwe = next((c for (c,) in cwe_row if _CWE.match(c or "")), None)
            if cwe is None or max(len(before), len(after)) > MAX_CODE_CHARS:
                continue
            line = first_changed_line(diff or "", before)
            if line is None:
                continue
            title = mappings.title_for(cwe)
            fn = enclosing_function(iter(_methods(conn, fc_id, True)), line)
            group = repo or cve_id
            yield {
                "file": filename, "language": language, "code": before,
                "scanner_output": "", "group": group, "pair_cwe": cwe,
                "findings": [{
                    "cwe": cwe, "line": line, "function": fn,
                    "title": f"{title} ({cve_id})"[:160],
                    "evidence": line_text(before, line),
                    "fix": template_fix(title, diff or ""),
                    "cve_id": cve_id,
                }],
                "summary": f"{filename} dosyasında {title} bulgusu ({cve_id} ile ilişkili yama).",
            }
            yield {
                "file": filename, "language": language, "code": after,
                "scanner_output": "", "group": group, "pair_cwe": cwe, "findings": [],
                "summary": "Tarayıcı ve inceleme sonucu bulgu yok (düzeltilmiş sürüm).",
            }
            count += 1
            if limit and count >= limit:
                return
    finally:
        conn.close()
