"""Okuyucuların ortak yardımcıları: diff çözümleme, şablon düzeltme metni."""
from __future__ import annotations

import re
from typing import Iterator

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
MAX_FIX_DIFF_CHARS = 1500


def removed_lines(diff: str) -> list[int]:
    """Unified diff'teki silinen satırların ESKİ dosyadaki numaralarını verir."""
    result: list[int] = []
    old_no = 0
    for raw in diff.splitlines():
        m = _HUNK.match(raw)
        if m:
            old_no = int(m.group(1))
            continue
        if raw.startswith("---") or raw.startswith("+++") or old_no == 0:
            continue
        if raw.startswith("-"):
            result.append(old_no)
            old_no += 1
        elif raw.startswith("+"):
            continue
        else:
            old_no += 1
    return result


def first_changed_line(diff: str, code: str) -> int | None:
    """Silinen ilk anlamlı (boş olmayan) satırın numarası; yoksa None."""
    lines = code.splitlines()
    for no in removed_lines(diff):
        if 1 <= no <= len(lines) and lines[no - 1].strip():
            return no
    return None


def line_text(code: str, line: int) -> str:
    return code.splitlines()[line - 1].strip()


def template_fix(cwe_title: str, diff: str) -> str:
    """Düzeltme metni: gerçek yama (diff) + sabit açıklama. Uydurma içermez."""
    patch = diff.strip()
    if len(patch) > MAX_FIX_DIFF_CHARS:
        patch = patch[:MAX_FIX_DIFF_CHARS] + "\n... (kısaltıldı)"
    return (
        f"{cwe_title} zafiyetini gideren upstream düzeltmesi aşağıdadır; "
        f"benzer bir değişiklik uygula:\n{patch}"
    )


def enclosing_function(methods: Iterator[tuple[str, int, int]], line: int) -> str | None:
    """(ad, başlangıç, bitiş) üçlülerinden `line`'ı kapsayan en dar fonksiyonu seçer."""
    best: tuple[str, int] | None = None
    for name, start, end in methods:
        if start <= line <= end:
            span = end - start
            if best is None or span < best[1]:
                best = (name, span)
    return best[0] if best else None
