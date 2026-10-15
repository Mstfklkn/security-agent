import json

from secagent.dataprep import build
from secagent.dataprep.sources import synthetic as sy
from secagent.dataprep.sources.templates import TEMPLATES
from secagent.dataprep.splits import SPLITS, assign_split, pick_holdout, split_for


def test_splits_include_synthetic_holdout():
    assert SPLITS == ("train", "val", "test", "test_synthetic")


def test_pick_holdout_is_deterministic_and_per_language():
    groups = {"kotlin": ["a", "b", "c", "d", "e"], "swift": ["x", "y"], "docker": ["only"]}
    h1, h2 = pick_holdout(groups), pick_holdout(groups)
    assert h1 == h2
    assert len(h1 & set(groups["kotlin"])) == 1          # round(5*0.2)=1
    assert len(h1 & set(groups["swift"])) == 1           # en az 1
    assert not (h1 & set(groups["docker"]))              # tek şablon bölünemez


def test_synthetic_holdout_groups_cover_languages_with_two_or_more_templates():
    held = sy.holdout_groups()
    by_lang = {}
    for t in TEMPLATES:
        by_lang.setdefault(t.language, []).append(f"synthetic-{t.id}")
    for lang, groups in by_lang.items():
        if len(groups) >= 2:
            assert held & set(groups), lang
        assert len(held & set(groups)) < len(groups)     # hiçbir dil tamamen dışarıda kalmaz


def test_assign_split_rules():
    held = frozenset({"synthetic-h"})
    assert assign_split({"origin": "sample", "group": None, "file": "x"}, held) == "train"
    assert assign_split({"synthetic": True, "group": "synthetic-t"}, held) == "train"
    assert assign_split({"synthetic": True, "group": "synthetic-h"}, held) == "test_synthetic"
    real = {"group": "https://github.com/a/b", "file": "f"}
    assert assign_split(real, held) == split_for("https://github.com/a/b")
    assert assign_split(real, held) in {"train", "val", "test"}   # gerçek veri asla test_synthetic'e gitmez


def _rec(group, synthetic=False, code="x = 1\n"):
    return {"file": "a.py", "language": "python", "code": code, "scanner_output": "",
            "group": group, "findings": [], "summary": "s", **({"synthetic": True} if synthetic else {})}


def test_write_split_routes_synthetic_holdout_and_never_leaks_into_real_splits(tmp_path):
    recs = [_rec("synthetic-h", True, "a\n"), _rec("synthetic-t", True, "b\n"),
            *[_rec(f"r{i}", code=f"c{i}\n") for i in range(60)]]
    counts = build.write_split(recs, tmp_path, training=True, holdout=frozenset({"synthetic-h"}))
    assert counts["test_synthetic"] == 1
    assert sum(counts.values()) == 62
    for name in ("val", "test"):                          # val/test yalnızca gerçek veri
        for line in (tmp_path / f"{name}.jsonl").read_text().splitlines():
            assert not json.loads(line)["input"]["code"] in ("a\n", "b\n")
    train_codes = [json.loads(l)["input"]["code"]
                   for l in (tmp_path / "train.jsonl").read_text().splitlines()]
    assert "b\n" in train_codes and "a\n" not in train_codes   # tutulan şablon train'de, ayrılan değil


# --- dil katmanlı gerçek veri bölmesi (H1c) ---------------------------------
from secagent.dataprep.splits import plan_real_splits  # noqa: E402


def _real(group, lang, i=0):
    return {"group": group, "language": lang, "file": "f", "code": f"{group}{i}", "findings": []}


def _corpus():
    recs = [_real(f"py{g}", "python", i) for g in range(100) for i in range(2)]      # 200 kayıt
    recs += [_real(f"sw{g}", "swift", i) for g in range(5) for i in range(3)]       # 5 depo
    recs += [_real(f"rs{g}", "rust", i) for g in range(2) for i in range(3)]        # 2 depo
    return recs


def test_plan_is_deterministic_and_group_consistent():
    recs = _corpus()
    plan = plan_real_splits(recs)
    assert plan == plan_real_splits(list(reversed(recs)))
    assert set(plan.values()) <= {"train", "val", "test"}
    assert all(g in plan for g in {r["group"] for r in recs})


def test_plan_every_language_with_enough_repos_reaches_val_and_test():
    recs = _corpus()
    plan = plan_real_splits(recs)
    seen = {}
    for r in recs:
        seen.setdefault(r["language"], set()).add(plan[r["group"]])
    assert {"val", "test"} <= seen["python"]
    assert {"val", "test"} <= seen["swift"]            # 5 depo >= 3: en az birer depo
    assert seen["rust"] == {"train"}                   # 2 depo: bölünemez, hepsi train


def test_plan_fractions_are_roughly_respected_and_big_repos_do_not_swallow_a_split():
    recs = [_real(f"r{g}", "go", i) for g in range(60) for i in range(5)]            # 300
    recs += [_real("kernel", "go", i) for i in range(500)]                          # dev depo
    plan = plan_real_splits(recs)
    counts = {"train": 0, "val": 0, "test": 0}
    for r in recs:
        counts[plan[r["group"]]] += 1
    total = len(recs)
    assert counts["train"] > 0.8 * total               # dev depo test'e yığılmadı
    assert counts["val"] > 0 and counts["test"] > 0
    assert plan["kernel"] == "train"


def test_assign_split_uses_plan_for_real_records_and_ignores_it_for_others():
    plan = {"g1": "test"}
    assert assign_split({"group": "g1", "file": "f"}, frozenset(), plan) == "test"
    assert assign_split({"group": "g2", "file": "f"}, frozenset(), plan) == split_for("g2")
    assert assign_split({"synthetic": True, "group": "g1"}, frozenset(), plan) == "train"
    assert assign_split({"origin": "sample", "group": "g1", "file": "f"}, frozenset(), plan) == "train"


def test_plan_merges_hyphenated_variants_of_a_repo_present_in_the_corpus():
    recs = [_real("qemu", "cpp", i) for i in range(3)] + [_real("qemu-kvm", "cpp", i) for i in range(3)]
    recs += [_real(f"x{g}", "cpp", 0) for g in range(40)]
    plan = plan_real_splits(recs)
    assert plan["qemu"] == plan["qemu-kvm"]                         # aynı kod tabanı, aynı bölme
    recs2 = [_real("node-sass", "javascript", 0)] + [_real(f"y{g}", "javascript", 0) for g in range(30)]
    assert plan_real_splits(recs2)["node-sass"] in {"train", "val", "test"}      # 'node' yoksa dokunulmaz
