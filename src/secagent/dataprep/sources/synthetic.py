"""
Sentetik örnek üreteci (kotlin, swift, docker, terraform, kubernetes).

Şablonlardaki <<yer_tutucu>>'lar deterministik değer havuzlarından doldurulur.
Her şablondan şunlar çıkar:
  - zafiyetli kayıt   (altın bulgu)
  - düzeltilmiş kayıt (temiz; tarayıcı alarmı kalırsa enrich yanlış alarm yapar)
  - fp_code varsa "yanlış alarm" kaydı: require_alarm=True. Yalnızca GERÇEK bir
    tarayıcı o CWE için alarm verirse tutulur (bkz. keep_validated_false_positives).
Grup = şablon kimliği: bir şablonun tüm varyantları aynı bölmeye düşer (sızıntı yok).
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterator

from ..splits import pick_holdout
from .templates import TEMPLATES, Template

_POOLS: dict[str, list[str]] = {
    "cls": ["UserRepository", "AccountStore", "OrderDao", "ProfileService",
            "InventoryRepo", "SessionStore", "InvoiceGateway", "DeviceRegistry"],
    "fn": ["findUser", "lookupAccount", "getOrders", "fetchProfile",
           "searchItems", "loadSession", "getInvoice", "listDevices"],
    "var": ["id", "userId", "name", "email", "term", "key", "path", "ref"],
    "tbl": ["users", "accounts", "orders", "profiles", "items", "sessions", "invoices"],
    "secret": ["Sup3rS3cret!2024", "prod-Passw0rd#91", "Tr0ub4dor&3x",
               "xK9mQ2vLp8Rz", "Winter2024!ops", "Zq7#mP2$kL9"],
    "name": ["api", "worker", "web", "billing", "auth", "reports", "gateway", "queue"],
    "image": ["python:3.12-slim", "python:3.11-slim", "node:20-slim", "python:3.12-alpine"],
    "size": ["20", "50", "100", "200"],
}
_K8S_IMAGES = ["registry.example.com/{n}:1.4.2", "registry.example.com/{n}:2.0.1",
               "registry.example.com/{n}:3.1.0"]
_STEPS = (1, 3, 5, 7, 11)
_MARK = re.compile(r"<<(\w+)>>")


def _values(template: Template, i: int) -> dict[str, str]:
    salt = sum(map(ord, template.id))
    vals = {k: pool[(i * _STEPS[n % len(_STEPS)] + salt + n) % len(pool)]
            for n, (k, pool) in enumerate(_POOLS.items())}
    if template.language == "kubernetes":
        vals["image"] = _K8S_IMAGES[(i + salt) % len(_K8S_IMAGES)].format(n=vals["name"])
    vals["sha"] = hashlib.sha256(f"{template.id}{i}".encode()).hexdigest()
    return vals


def _render(text: str, vals: dict[str, str]) -> str:
    return _MARK.sub(lambda m: vals[m.group(1)], text)


def _line_of(code: str, needle: str) -> int | None:
    for no, line in enumerate(code.splitlines(), 1):
        if needle in line:
            return no
    return None


def _base(template: Template, vals: dict[str, str], code: str) -> dict:
    return {"file": _render(template.file, vals), "language": template.language,
            "code": code, "scanner_output": "", "pair_cwe": template.cwe,
            "group": f"synthetic-{template.id}", "synthetic": True}


def records_for(template: Template, i: int) -> list[dict]:
    vals = _values(template, i)
    vuln = _render(template.vulnerable, vals)
    fixed = _render(template.fixed, vals)
    evidence = _render(template.evidence, vals)
    line = _line_of(vuln, evidence)
    if line is None:
        return []
    fn = _render(template.function, vals) if template.function else None
    title = template.title
    out = [
        {**_base(template, vals, vuln), "findings": [{
            "cwe": template.cwe, "severity": template.severity, "line": line,
            "function": fn, "title": title, "evidence": vuln.splitlines()[line - 1].strip(),
            "fix": template.fix}],
         "summary": f"{title}."},
        {**_base(template, vals, fixed), "findings": [],
         "summary": "Tarayıcı ve inceleme sonucu bulgu yok (düzeltilmiş sürüm)."},
    ]
    if template.fp_code and template.fp_evidence:
        fp = _render(template.fp_code, vals)
        fp_line = _line_of(fp, _render(template.fp_evidence, vals))
        if fp_line is not None:
            out.append({**_base(template, vals, fp), "require_alarm": True, "findings": [{
                "cwe": template.cwe, "severity": "info", "line": fp_line,
                "function": None, "title": f"{title} — yanlış alarm"[:160],
                "evidence": fp.splitlines()[fp_line - 1].strip(),
                "fix": f"Düzeltme gerekmiyor: {template.fp_reason}",
                "false_positive": True}],
                "summary": f"Tarayıcı uyarısı yanlış alarm: {template.fp_reason}"})
    return out


def holdout_groups() -> frozenset[str]:
    """Eğitimden ayrılan şablon grupları (test_synthetic). --synthetic N'den bağımsızdır."""
    by_language: dict[str, list[str]] = {}
    for t in TEMPLATES:
        by_language.setdefault(t.language, []).append(f"synthetic-{t.id}")
    return pick_holdout(by_language)


def generate(per_template: int, languages: set[str] | None = None) -> Iterator[dict]:
    """Şablon başına `per_template` varyant üretir."""
    for template in TEMPLATES:
        if languages and template.language not in languages:
            continue
        for i in range(per_template):
            yield from records_for(template, i)


def keep_validated_false_positives(records: list[dict]) -> tuple[list[dict], int]:
    """require_alarm kayıtlarından, hiçbir gerçek tarayıcının işaretlemediklerini eler.
    (tutulan kayıtlar, elenen sayısı) döndürür."""
    kept = [r for r in records if not r.get("require_alarm") or r.get("scanner_output")]
    return kept, len(records) - len(kept)
