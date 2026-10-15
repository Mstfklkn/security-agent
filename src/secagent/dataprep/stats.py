"""Dağılım raporları.

  secagent-stats <jsonl>          dil / tür / CWE dağılımı
  secagent-stats --card [klasör]  bölmeler için veri kartı (data_card.json)
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from .. import mappings
from ..paths import OUT
from ..schema import LANGUAGES, iter_valid
from .splits import SPLITS

NOTES = (
    "Yanlış alarm etiketleri zayıf denetimlidir: 'düzeltmeden sonra aynı CWE'de kalan alarm' "
    "kuralından gelir (gerçek veri) ya da elle seçilmiş sentetik istisnalardır (tarayıcı "
    "doğrulamalı).",
    "Enjeksiyon, kod çalıştırma, deserialization ve gömülü sır ailelerinde (mappings."
    "is_risky_dismissal) otomatik yanlış alarm etiketi ÜRETİLMEZ.",
    "Bölme depo adına göre (CVEfixes ve PrimeVul aynı depoları örtüşür) ve gerçek veri için dil "
    "katmanlıdır. Sentetik veri yalnızca train'dedir; her dilden ayrılan şablonlar "
    "test_synthetic'tedir. Gerçek verisi olmayan diller (kotlin, docker, terraform, kubernetes) "
    "yalnızca test_synthetic ile ölçülür.",
    "DiverseVul ham veride duruyor ama eğitime alınmadı (etiket gürültüsü; PrimeVul temizlenmiş "
    "üst kümesi). Vul4J: tam kaynak kodu yok, okuyucu yazılmadı.",
    "Model çıktısı cvss/references içermez; bunlar çıkarım sonrası mappings.py'den eklenir.",
)


def _kind(findings) -> str:
    if not findings:
        return "temiz"
    return "yanlış_alarm" if any(f.false_positive for f in findings) else "gerçek"


def compute(path: str | Path) -> dict:
    langs: Counter = Counter()
    cwes: Counter = Counter()
    kinds: Counter = Counter()
    logic = 0
    n = 0
    for ex in iter_valid(path):
        n += 1
        langs[ex.input.language] += 1
        fs = ex.output.findings
        kinds[_kind(fs)] += 1
        for f in fs:
            cwes[f.cwe] += 1
        if any(mappings.is_logic(f.cwe) and not f.false_positive for f in fs):
            logic += 1
    return {"examples": n, "languages": langs, "cwes": cwes, "kinds": kinds, "logic_examples": logic,
            "missing_languages": [lang for lang in LANGUAGES if langs[lang] == 0]}


def fingerprint(path: Path) -> str | None:
    """Dosya özeti: bölmeler veri sürümüne bağlıdır (kaynak eklenince depolar yer değiştirebilir);
    eski bir adaptörü yeni test kümesinde değerlendirmeden önce bunu karşılaştır."""
    if not path.exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def card(out_dir: str | Path) -> dict:
    out = Path(out_dir)
    splits, missing = {}, {}
    for name in SPLITS:
        p = out / f"{name}.jsonl"
        r = compute(p) if p.exists() else {"examples": 0, "languages": Counter(), "cwes": Counter(),
                                           "kinds": Counter(), "logic_examples": 0,
                                           "missing_languages": list(LANGUAGES)}
        splits[name] = {"fingerprint": fingerprint(p), "examples": r["examples"], "kinds": dict(r["kinds"]),
                        "logic_examples": r["logic_examples"], "languages": dict(r["languages"]),
                        "top_cwes": r["cwes"].most_common(10)}
        missing[name] = r["missing_languages"]
    return {"splits": splits, "languages_missing_in_split": missing, "notes": list(NOTES)}


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--card"]:
        out = Path(args[1]) if len(args) > 1 else OUT
        c = card(out)
        (out / "data_card.json").write_text(json.dumps(c, indent=2, ensure_ascii=False), encoding="utf-8")
        for name, s in c["splits"].items():
            print(f"{name:15} {s['examples']:6}  {s['kinds']}  mantık_hatası={s['logic_examples']}")
        print(f"-> {out / 'data_card.json'}")
        return 0
    if len(args) != 1:
        raise SystemExit("Kullanım: secagent-stats <jsonl> | secagent-stats --card [klasör]")
    r = compute(args[0])
    print("Dil:", dict(r["languages"].most_common()))
    print("Tür:", dict(r["kinds"]))
    print("En sık CWE:", r["cwes"].most_common(10))
    print("Verisi olmayan diller:", r["missing_languages"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
