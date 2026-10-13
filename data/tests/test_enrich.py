import shutil
from pathlib import Path

import pytest

import enrich_scanners as en

CODE = "import os\nq = 'SELECT ' + x\nos.system(y)\n"


def rec(findings=None, pair="CWE-89", code=CODE, lang="python", file="app/db.py"):
    return {"file": file, "language": lang, "code": code, "scanner_output": "",
            "group": "g", "pair_cwe": pair, "findings": findings or [], "summary": "s"}


def vuln():
    return rec([{"cwe": "CWE-89", "line": 2, "title": "SQL enjeksiyonu",
                 "evidence": "q = ...", "fix": "f"}])


def alarm(line=2, cwe="CWE-89", rule="B608", file="rec_0/db.py"):
    return {"tool": "bandit", "file": file, "line": line, "rule_id": rule,
            "message": "sql", "severity": "medium", "cwe": cwe}


def test_vulnerable_with_matching_alarm_keeps_gold_and_gets_output():
    out = en.label_record(vuln(), [alarm()])
    assert "bandit: [B608]" in out["scanner_output"] and "app/db.py:2" in out["scanner_output"]
    assert out["findings"][0]["false_positive"] if "false_positive" in out["findings"][0] else True


def test_vulnerable_without_alarm_is_scanner_miss_example():
    out = en.label_record(vuln(), [])
    assert out["scanner_output"] == "" and len(out["findings"]) == 1


def test_vulnerable_with_foreign_alarm_is_ambiguous():
    assert en.label_record(vuln(), [alarm(cwe="CWE-78", line=3)]) is None


def test_clean_with_matching_alarm_becomes_false_positive():
    out = en.label_record(rec(), [alarm(), alarm()])
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["false_positive"] is True and f["cwe"] == "CWE-89" and f["line"] == 2
    assert f["evidence"] == "q = 'SELECT ' + x"


def test_clean_with_foreign_or_cwe_less_alarm_is_ambiguous():
    assert en.label_record(rec(), [alarm(cwe="CWE-78")]) is None
    assert en.label_record(rec(), [alarm(cwe=None)]) is None


def test_drop_mode_removes_unclear_alarms_but_keeps_record():
    out = en.label_record(rec(), [alarm(), alarm(cwe="CWE-78", line=3)], ambiguous="drop")
    assert len(out["findings"]) == 1 and "B608" in out["scanner_output"]
    assert "CWE-78" not in out["scanner_output"]


def test_alarm_line_out_of_range_is_not_labeled():
    assert en.label_record(rec(), [alarm(line=99)]) is None
    assert en.label_record(rec(), [alarm(line=99)], ambiguous="drop")["findings"] == []


def test_safe_name_strips_traversal():
    assert en._safe_name(rec(file="../../etc/passwd")) == "passwd.py"
    assert en._safe_name(rec(lang="docker", file="x/y")) == "Dockerfile"
    assert en._safe_name(rec(file="a b$.py")) == "a_b_.py"


def test_enrich_batches_by_language_and_maps_by_record_dir():
    recs = [vuln(), rec(), rec(lang="java", file="A.java", code="class A{}\n")]
    calls = []

    def fake(path, lang):
        calls.append(lang)
        files = sorted(Path(path).glob("rec_*/*"))
        return [{**alarm(file=str(f)), "line": 2} for f in files if lang == "python"]

    out, st = en.enrich(recs, scan_fn=fake)
    assert sorted(calls) == ["java", "python"]          # dil başına tek tarama
    assert st["enriched"] == 3 and st["new_false_positive"] == 1
    assert out[1]["findings"][0]["false_positive"] and out[2]["findings"] == []
    assert recs[1]["findings"] == []                    # girdi değişmedi


def test_enrich_skips_hand_written_and_counts_ambiguous():
    hand = {**vuln(), "scanner_output": "elle yazıldı"}
    amb = rec()
    out, st = en.enrich([hand, amb],
                        scan_fn=lambda p, l: [alarm(cwe="CWE-78", file=str(next(Path(p).glob("rec_1/*"))))])
    assert out == [hand] and st["skipped_ambiguous"] == 1


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit kurulu değil")
def test_real_bandit_end_to_end():
    code = "import subprocess\n\ndef run(c):\n    return subprocess.call(c, shell=True)\n"
    from dataclasses import asdict
    import run_scanners as rs
    bandit_only = lambda path, lang: [asdict(f) for f in rs.run_bandit(path)]
    out, st = en.enrich([rec(pair="CWE-78", code=code)], scan_fn=bandit_only)
    assert st["enriched"] + st["skipped_ambiguous"] == 1
    if out:
        assert out[0]["findings"][0]["cwe"] == "CWE-78"
        assert "bandit" in out[0]["scanner_output"]
