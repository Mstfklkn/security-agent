import json

import make_examples
import mappings
import stats
from schema import validate_file

from test_cvefixes import _db


def test_main_split_dedupes_and_validates(tmp_path, monkeypatch):
    db = tmp_path / "c.db"
    _db(db)
    out = tmp_path / "o"
    monkeypatch.setattr("sys.argv", ["x", "--out-dir", str(out), "--cvefixes", str(db),
                                     "--limit", "5"])
    assert make_examples.main() == 0
    assert sum(validate_file(out / f"{n}.jsonl")[0] for n in ("train", "val", "test")) == 4
    # ikinci çalıştırma aynı kodu tekrar üretmemeli (hash tekilleştirme)
    recs = [json.loads(p.read_text())
            for p in (make_examples.Path(__file__).parent.parent / "samples").glob("*.json")]
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
