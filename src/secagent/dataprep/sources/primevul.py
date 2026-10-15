"""
PrimeVul okuyucusu (C/C++ fonksiyon düzeyi; MIT, Drive'dan indirilen v0.1).

`primevul_{train,valid,test}_paired.jsonl`: aynı commit'in zafiyetli (target=1) ve
düzeltilmiş (target=0) fonksiyonu ardışık satırlardır. Her çiftten iki kayıt çıkar:
  - zafiyetli fonksiyon -> CWE bulgusu (satır: iki sürüm farkından, fonksiyona göre)
  - düzeltilmiş fonksiyon -> boş bulgu (temiz); tarayıcı alarmı kalırsa enrich yanlış
    alarm yapar.
PrimeVul'ün kendi train/valid/test ayrımı KULLANILMAZ: bölme depo adına göre bizim
splits.py tarafından yapılır (CVEfixes ile aynı depolar örtüşür, sızıntı olmasın).
Tarayıcı, dosya bağlamı olmadığı için fonksiyon parçası üzerinde çalışır.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import re
from pathlib import Path
from typing import Iterator

from ... import mappings
from .common import (MAX_FUNC_CHARS, c_function_name, first_diff_line, group_key, line_text,
                     template_fix, unified_change)

SPLIT_FILES = ("train", "valid", "test")
_CWE = re.compile(r"^CWE-\d+$")


def _rows(path: Path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _norm(code: str) -> str:
    return "\n".join(ln.strip() for ln in code.splitlines() if ln.strip())


def _cwe(row: dict) -> str | None:
    return next((c for c in (row.get("cwe") or []) if _CWE.match(c or "")), None)


def _file_name(a: dict, b: dict, fn: str | None) -> str:
    for row in (a, b):
        name = row.get("file_name")
        if name and name != "None":
            return name
    return f"{fn or 'func'}.c"


def _record_pair(vuln: dict, fixed: dict, cvss: dict | None) -> tuple[dict, dict] | None:
    cwe = _cwe(vuln) or _cwe(fixed)
    code_v, code_f = vuln["func"], fixed["func"]
    if (cwe is None or max(len(code_v), len(code_f)) > MAX_FUNC_CHARS
            or _norm(code_v) == _norm(code_f)):
        return None
    line = first_diff_line(code_v, code_f)
    if line is None:
        return None

    title = mappings.title_for(cwe)
    cve = vuln.get("cve") or fixed.get("cve")
    fn = c_function_name(code_v)
    group = group_key(vuln.get("project_url") or vuln.get("project"))
    real = (cvss or {}).get(cve)
    finding = {
        "cwe": cwe, "line": line, "function": fn,
        "title": title[:160],
        "evidence": line_text(code_v, line),
        "fix": template_fix(title, unified_change(code_v, code_f)),
        **({"cve_id": cve} if cve else {}),
        **({"cvss": list(real)} if real else {}),
    }
    name = _file_name(vuln, fixed, fn)
    base = {"file": name, "language": "cpp", "scanner_output": "", "group": group,
            "pair_cwe": cwe, "origin": "primevul"}
    return ({**base, "code": code_v, "findings": [finding],
             "summary": f"{fn or 'Fonksiyon'} içinde {title} bulgusu (düzeltilmiş sürümle farkından)."},
            {**base, "code": code_f, "findings": [],
             "summary": "Tarayıcı ve inceleme sonucu bulgu yok (düzeltilmiş fonksiyon)."})


def read(raw_dir: str | Path, limit: int | None = None,
         cvss: dict | None = None) -> Iterator[dict]:
    """Eşli dosyalardan (zafiyetli, temiz) kayıt çiftleri. limit: en çok N çift."""
    raw = Path(raw_dir)
    taken = 0
    for split in SPLIT_FILES:
        path = raw / f"primevul_{split}_paired.jsonl"
        if not path.exists():
            continue
        rows = list(_rows(path))
        i = 0
        while i + 1 < len(rows):
            a, b = rows[i], rows[i + 1]
            if a["commit_id"] != b["commit_id"] or a["target"] == b["target"]:
                i += 1                                   # eşleşmeyen satırı atla
                continue
            i += 2
            vuln, fixed = (a, b) if a["target"] == 1 else (b, a)
            pair = _record_pair(vuln, fixed, cvss)
            if pair is None:
                continue
            yield from pair
            taken += 1
            if limit and taken >= limit:
                return


def read_clean(raw_dir: str | Path, n: int) -> Iterator[dict]:
    """Eşsiz `train` dosyasından n temiz (target=0) fonksiyon; deterministik seçim.
    Gerçek kodun çoğu temizdir; alarmsız temiz örnekler 'alarm yok -> bulgu yok'u öğretir.
    (Alarmı olan kayıtlar enrich'te belirsiz sayılıp atılır; etiketi CWE'siz bilinmez.)"""
    path = Path(raw_dir) / "primevul_train.jsonl"
    if n <= 0 or not path.exists():
        return

    def usable(r: dict) -> bool:
        code = r["func"]
        return r["target"] == 0 and 3 <= len(code.splitlines()) and len(code) <= MAX_FUNC_CHARS

    def key(r: dict) -> str:
        return hashlib.sha256(str(r["func_hash"]).encode()).hexdigest()

    for r in heapq.nsmallest(n, (r for r in _rows(path) if usable(r)), key=key):
        yield {"file": _file_name(r, r, c_function_name(r["func"])), "language": "cpp",
               "code": r["func"], "scanner_output": "", "findings": [],
               "group": group_key(r.get("project_url") or r.get("project")),
               "pair_cwe": None, "origin": "primevul-clean",
               "summary": "Bilinen zafiyeti yok (PrimeVul temiz fonksiyon)."}
