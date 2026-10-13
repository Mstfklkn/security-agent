"""JSONL için dil / CWE / örnek türü dağılımı raporu.

Kullanım: secagent-stats data/out/train.jsonl
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from ..schema import LANGUAGES, iter_valid


def compute(path: str | Path) -> dict:
    langs: Counter = Counter()
    cwes: Counter = Counter()
    kinds: Counter = Counter()
    for ex in iter_valid(path):
        langs[ex.input.language] += 1
        fs = ex.output.findings
        if not fs:
            kinds["temiz"] += 1
        for f in fs:
            cwes[f.cwe] += 1
            kinds["yanlış_alarm" if f.false_positive else "gerçek_bulgu"] += 1
    return {"languages": langs, "cwes": cwes, "kinds": kinds,
            "missing_languages": [l for l in LANGUAGES if langs[l] == 0]}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Kullanım: secagent-stats <jsonl>")
    r = compute(sys.argv[1])
    print("Dil:", dict(r["languages"].most_common()))
    print("Tür:", dict(r["kinds"]))
    print("En sık CWE:", r["cwes"].most_common(10))
    print("Verisi olmayan diller:", r["missing_languages"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
