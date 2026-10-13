import sqlite3

from helpers import AFTER, BEFORE, DIFF, make_db
from secagent.dataprep.sources import cvefixes

def test_yields_vulnerable_and_clean(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    recs = list(cvefixes.read(db))
    assert len(recs) == 2
    vuln, clean = recs
    f = vuln["findings"][0]
    assert (f["cwe"], f["line"], f["function"]) == ("CWE-89", 2, "get")
    assert "execute" in f["evidence"]
    assert vuln["group"] == "https://r/x"
    assert clean["findings"] == [] and clean["code"] == AFTER


def test_skips_unsupported_language(tmp_path):
    db = tmp_path / "c.db"
    make_db(db, lang="COBOL")
    assert list(cvefixes.read(db)) == []


def test_skips_oversized(tmp_path):
    db = tmp_path / "c.db"
    make_db(db, before=BEFORE + "#" * 13_000)
    assert list(cvefixes.read(db)) == []


def test_real_cvss_is_used(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    f = next(cvefixes.read(db))["findings"][0]
    assert f["cvss"] == [9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]


def test_bad_cvss_falls_back_to_default(tmp_path):
    for bad in (("None", "None"), ("11", "CVSS:3.1/x"), ("5.0", "AV:N/AC:L")):
        db = tmp_path / f"{bad[0]}.db"
        make_db(db, cvss=bad)
        assert "cvss" not in next(cvefixes.read(db))["findings"][0]


def _add_pair(path, n, lang):
    c = sqlite3.connect(path)
    cid = f"CVE-{n}"
    c.execute("INSERT INTO cwe_classification VALUES (?, 'CWE-89')", (cid,))
    c.execute("INSERT INTO fixes VALUES (?, ?, ?)", (cid, f"h{n}", f"https://r/{n}"))
    c.execute("INSERT INTO file_change VALUES (?, ?, 'x', ?, ?, ?, ?)",
              (f"f{n}", f"h{n}", DIFF, BEFORE, AFTER, lang))
    c.commit()
    c.close()


def test_per_language_balances_and_merges_c_and_cpp(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)                                    # CVE-1: Python
    for n, lang in [(2, "C"), (3, "C++"), (4, "C"), (5, "Python")]:
        _add_pair(db, n, lang)
    recs = list(cvefixes.read(db, per_language=1))
    langs = sorted(r["language"] for r in recs)
    assert langs == ["cpp", "cpp", "python", "python"]   # C ve C++ tek dil, 1'er çift


def test_total_limit_is_respected(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    for n in (2, 3):
        _add_pair(db, n, "Python")
    assert len(list(cvefixes.read(db, limit=2))) == 4


def test_function_granularity_pairs_and_rebases(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    recs = list(cvefixes.read(db, granularity="function"))
    assert len(recs) == 2
    vuln, clean = recs
    f = vuln["findings"][0]
    assert f["function"] == "get" and f["line"] == 2          # fonksiyona göre satır
    assert vuln["code"] == BEFORE.strip() and vuln["scan_code"] == BEFORE
    assert (vuln["scan_start"], vuln["scan_end"]) == (1, 2)
    assert clean["code"] == AFTER.strip() and clean["findings"] == []


def test_function_skips_when_slice_does_not_match_file(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    c = sqlite3.connect(db)
    c.execute("UPDATE method_change SET code = 'bozuk kod' WHERE before_change = 'True'")
    c.commit(); c.close()
    assert list(cvefixes.read(db, granularity="function")) == []


def test_function_skips_ambiguous_duplicate_names(tmp_path):
    db = tmp_path / "c.db"
    make_db(db)
    c = sqlite3.connect(db)
    c.execute("INSERT INTO method_change VALUES ('f1','get','1','2','False',?)", (AFTER.strip(),))
    c.commit(); c.close()
    assert list(cvefixes.read(db, granularity="function")) == []


def test_both_and_invalid_granularity(tmp_path):
    import pytest
    db = tmp_path / "c.db"
    make_db(db)
    assert len(list(cvefixes.read(db, granularity="both"))) == 4
    with pytest.raises(ValueError):
        list(cvefixes.read(db, granularity="x"))
