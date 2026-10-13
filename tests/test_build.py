import json

from helpers import make_db, run_build
from secagent import mappings
from secagent.dataprep import build as make_examples
from secagent.dataprep import stats
from secagent.dataprep.splits import split_for
from secagent.paths import SAMPLES
from secagent.schema import Example, validate_file


def test_split_is_deterministic_and_covers_all():
    assert split_for("repo-a") == split_for("repo-a")
    names = {split_for(f"r{i}") for i in range(500)}
    assert names == {"train", "val", "test"}


def test_strip_removes_cvss_and_refs(tmp_path):
    out = tmp_path / "t.jsonl"
    run_build("--out", str(out), "--strip")
    for line in out.read_text().splitlines():
        for f in json.loads(line)["output"]["findings"]:
            assert "cvss" not in f and "references" not in f


def test_default_keeps_cvss_and_refs(tmp_path):
    out = tmp_path / "t.jsonl"
    run_build("--out", str(out))
    first = json.loads(out.read_text().splitlines()[0])
    assert first["output"]["findings"][0]["references"]


def test_cvefixes_end_to_end_split(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    out = tmp_path / "o"
    run_build("--out-dir", str(out), "--cvefixes", str(db))
    total = 0
    for name in ("train", "val", "test"):
        ok, bad = validate_file(out / f"{name}.jsonl")
        assert bad == 0
        total += ok
    assert total == 4  # 2 örnek (samples) + zafiyetli + temiz


def test_invalid_language_rejected():
    import pytest
    with pytest.raises(Exception):
        Example.model_validate({"input": {"file": "a", "language": "cobol", "code": "x"},
                               "output": {"findings": []}})


def test_main_split_dedupes_and_validates(tmp_path, monkeypatch):
    db = tmp_path / "c.db"
    make_db(db)
    out = tmp_path / "o"
    monkeypatch.setattr("sys.argv", ["x", "--out-dir", str(out), "--cvefixes", str(db),
                                     "--limit", "5"])
    assert make_examples.main() == 0
    assert sum(validate_file(out / f"{n}.jsonl")[0] for n in ("train", "val", "test")) == 4
    # ikinci çalıştırma aynı kodu tekrar üretmemeli (hash tekilleştirme)
    recs = [json.loads(p.read_text())
            for p in SAMPLES.glob("*.json")]
    counts = make_examples.write_split(recs + recs, tmp_path / "d", training=True)
    assert sum(counts.values()) == len(recs)


def test_main_requires_exactly_one_output(monkeypatch):
    import pytest
    monkeypatch.setattr("sys.argv", ["x"])
    with pytest.raises(SystemExit):
        make_examples.main()


def test_stats_reports_missing_languages(tmp_path):
    out = tmp_path / "t.jsonl"
    monkeypatch_args = ["--out", str(out)]
    import sys
    old = sys.argv
    sys.argv = ["x", *monkeypatch_args]
    try:
        make_examples.main()
    finally:
        sys.argv = old
    r = stats.compute(out)
    assert r["languages"]["python"] == 2
    assert "swift" in r["missing_languages"]
    assert r["kinds"]["yanlış_alarm"] == 1


def test_mapping_helpers():
    assert mappings.title_for("CWE-89") == "SQL enjeksiyonu"
    assert mappings.title_for("CWE-99999").startswith("CWE-99999")
    assert mappings.defaults_for("CWE-99999") == ("medium", None, None)
    assert mappings.references_for("CWE-89", "CVE-2020-1")[-1].endswith("CVE-2020-1")


def test_cvefixes_flag_without_value_uses_default_path(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr("secagent.dataprep.sources.cvefixes.read",
                        lambda path, **kw: seen.setdefault("path", str(path)) and iter(()))
    monkeypatch.setattr("sys.argv", ["x", "--out", str(tmp_path / "o.jsonl"), "--cvefixes"])
    assert make_examples.main() == 0
    assert seen["path"].endswith("data/raw/CVEfixes/CVEfixes.db")
