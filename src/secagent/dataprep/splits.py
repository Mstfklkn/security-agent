"""Sızıntısız bölmeler.

- Gerçek veri: aynı depo (group, bkz. sources.common.group_key) hep aynı bölmeye düşer.
  Bölme DİL KATMANLIDIR (plan_real_splits): her dilin yaklaşık %5'i val, %5'i test olur;
  dev depolar bir bölmeyi yutmaz; en az 3 deposu olan her dil val ve test'te temsil edilir.
- Sentetik veri: yalnızca train'e girer; her dilden en az bir ŞABLON bütünüyle ayrılıp
  `test_synthetic`e konur. Böylece gerçek verisi olmayan diller (kotlin, docker, ...) de
  eğitimde hiç görülmemiş şablonlarla ölçülür; gerçek test metrikleriyle karışmaz.
- Elle hazırlanmış örnekler (samples/): train.
"""
from __future__ import annotations

import hashlib
from collections import Counter

SPLITS = ("train", "val", "test", "test_synthetic")


def _digest(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)


def split_for(group: str, val_pct: int = 5, test_pct: int = 5) -> str:
    """Gerçek veri için repo bazlı bölme (train/val/test)."""
    bucket = _digest(group) % 100
    if bucket < test_pct:
        return "test"
    if bucket < test_pct + val_pct:
        return "val"
    return "train"


def pick_holdout(groups_by_language: dict[str, list[str]], fraction: float = 0.2) -> frozenset[str]:
    """Her dilden deterministik olarak en az bir grubu (şablonu) ayırır; tek gruplu
    dilde bölünecek bir şey olmadığından hiçbir şey ayrılmaz."""
    held: set[str] = set()
    for groups in groups_by_language.values():
        if len(groups) < 2:
            continue
        ranked = sorted(groups, key=_digest)
        held.update(ranked[:max(1, round(len(groups) * fraction))])
    return frozenset(held)


def plan_real_splits(records: list[dict], val_frac: float = 0.05, test_frac: float = 0.05,
                     min_groups: int = 3) -> dict[str, str]:
    """Gerçek veri için depo -> bölme planı (dil katmanlı, deterministik).

    Nadir diller önce işlenir. Bir dil için depolar özet sırasıyla seçilir; hedefi
    (dilin kayıtlarının frac'ı) aşan dev depolar atlanır. Dilin en az `min_groups`
    deposu varsa her bölmeye en az bir depo (en küçüğü) garanti edilir; daha azında
    bölünecek bir şey yoktur ve hepsi train'de kalır."""
    real = [r for r in records if not r.get("synthetic") and r.get("origin") != "sample"]
    names = {r.get("group") or r["file"] for r in real}

    def canon(group: str) -> str:
        """'qemu-kvm' korpusta 'qemu' da varsa 'qemu' ile aynı kod tabanıdır: birleştir
        (fazla gruplama güvenli, eksik gruplama sızıntı)."""
        head = group.split("-", 1)[0]
        return head if "-" in group and len(head) >= 3 and head in names else group

    per_group: dict[str, Counter] = {}
    lang_total: Counter = Counter()
    lang_groups: dict[str, set[str]] = {}
    for r in real:
        g = canon(r.get("group") or r["file"])
        per_group.setdefault(g, Counter())[r["language"]] += 1
        lang_total[r["language"]] += 1
        lang_groups.setdefault(r["language"], set()).add(g)

    plan: dict[str, str] = {}
    got: dict[str, Counter] = {"val": Counter(), "test": Counter()}

    def assign(group: str, split: str) -> None:
        plan[group] = split
        for lang, n in per_group[group].items():
            got[split][lang] += n

    for lang in sorted(lang_total, key=lambda l: (lang_total[l], l)):
        if len(lang_groups[lang]) < min_groups:
            continue
        for split, frac in (("test", test_frac), ("val", val_frac)):
            target = frac * lang_total[lang]
            cands = sorted((g for g in lang_groups[lang] if g not in plan),
                           key=lambda g: _digest(f"{split}:{g}"))
            for g in cands:
                if got[split][lang] >= target:
                    break
                if per_group[g][lang] <= max(2 * target, 1):
                    assign(g, split)
            if got[split][lang] == 0:
                left = [g for g in cands if g not in plan]
                if left:
                    assign(min(left, key=lambda g: (per_group[g][lang], _digest(f"{split}:{g}"))), split)
    return {g: plan.get(canon(g), "train") for g in names}


def assign_split(rec: dict, holdout: frozenset[str],
                 plan: dict[str, str] | None = None) -> str:
    if rec.get("origin") == "sample":
        return "train"
    if rec.get("synthetic"):
        return "test_synthetic" if rec.get("group") in holdout else "train"
    group = rec.get("group") or rec["file"]
    if plan is not None and group in plan:
        return plan[group]
    return split_for(group)


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
