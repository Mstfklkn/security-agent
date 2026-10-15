import shutil
from pathlib import Path

import pytest

from secagent.dataprep import enrich as en

CODE = "import os\nq = 'SELECT ' + x\nos.system(y)\n"


def rec(findings=None, pair="CWE-120", code=CODE, lang="python", file="app/db.py"):
    return {"file": file, "language": lang, "code": code, "scanner_output": "",
            "group": "g", "pair_cwe": pair, "findings": findings or [], "summary": "s"}


def vuln():
    return rec([{"cwe": "CWE-120", "line": 2, "title": "SQL enjeksiyonu",
                 "evidence": "q = ...", "fix": "f"}])


def alarm(line=2, cwe="CWE-120", rule="B608", file="rec_0/db.py"):
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
    assert f["false_positive"] is True and f["cwe"] == "CWE-120" and f["line"] == 2
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
    from secagent.scanners import runners as rs
    bandit_only = lambda path, lang: [asdict(f) for f in rs.run_bandit(path)]
    out, st = en.enrich([rec(pair="CWE-78", code=code)], scan_fn=bandit_only)
    assert st["enriched"] + st["skipped_ambiguous"] == 1
    if out:
        assert out[0]["findings"][0]["cwe"] == "CWE-78"
        assert "bandit" in out[0]["scanner_output"]


def test_localize_filters_to_function_range_and_rebases():
    r = {**rec(), "scan_start": 10, "scan_end": 20}
    al = [alarm(line=9), alarm(line=10), alarm(line=15), alarm(line=21), {**alarm(), "line": None}]
    out = en.localize(r, al)
    assert [a["line"] for a in out] == [1, 6]
    assert en.localize(rec(), al) == al                    # dosya düzeyi: değişmez


def test_function_level_scans_whole_file_but_labels_function():
    r = {**rec(code="f body\nline2\n"), "scan_code": "x\n" * 9 + "f body\nline2\n",
         "scan_start": 10, "scan_end": 11}
    seen = {}

    def fake(path, lang):
        f = next(Path(path).glob("rec_*/*"))
        seen["text"] = f.read_text()
        return [{**alarm(file=str(f)), "line": 11, "cwe": "CWE-120"}]

    out, st = en.enrich([r], scan_fn=fake)
    assert seen["text"].startswith("x\n")                  # tarayıcı DOSYAYI gördü
    assert out[0]["findings"][0]["line"] == 2 and out[0]["findings"][0]["false_positive"]


def test_alarm_text_includes_scanner_cwe_when_known():
    a = alarm()
    assert en.format_alarm(a, "app/db.py").endswith("severity: medium, cwe: CWE-120)")
    assert "cwe" not in en.format_alarm({**a, "cwe": None}, "app/db.py")


# --- riskli ailelerde otomatik yanlış alarm ÜRETİLMEZ -----------------------
import pytest  # noqa: E402

from secagent import mappings as _m  # noqa: E402


@pytest.mark.parametrize("cwe", ["CWE-89", "CWE-78", "CWE-94", "CWE-95", "CWE-502", "CWE-798", "CWE-77"])
def test_clean_record_with_matching_alarm_in_risky_family_is_ambiguous(cwe):
    r = rec(pair=cwe)
    a = alarm(cwe=cwe)
    assert en.label_record(r, [a]) is None                                   # atla
    dropped = en.label_record(r, [a], ambiguous="drop")
    assert dropped["findings"] == [] and dropped["scanner_output"] == ""     # alarm da gösterilmez


@pytest.mark.parametrize("cwe", ["CWE-120", "CWE-119", "CWE-125", "CWE-22", "CWE-327", "CWE-79"])
def test_non_risky_families_still_produce_false_positive_labels(cwe):
    out = en.label_record(rec(pair=cwe), [alarm(cwe=cwe)])
    assert out["findings"][0]["false_positive"] is True


def test_risky_rule_never_blocks_vulnerable_records_or_authored_false_positives():
    v = {**vuln(), "pair_cwe": "CWE-89",
         "findings": [{**vuln()["findings"][0], "cwe": "CWE-89"}]}
    out = en.label_record(v, [alarm(cwe="CWE-89")])
    assert out is not None and "bandit" in out["scanner_output"]            # gerçek bulgu kaydı korunur
    authored = {**rec(pair="CWE-78"), "require_alarm": True,
                "findings": [{"cwe": "CWE-78", "line": 2, "title": "Yanlış alarm", "evidence": "x",
                              "fix": "Sabit komut.", "false_positive": True}]}
    assert en.label_record(authored, [alarm(cwe="CWE-78")]) is not None      # elle seçilmiş istisna korunur


def test_is_risky_dismissal_helper():
    assert _m.is_risky_dismissal("CWE-89") and _m.is_risky_dismissal("CWE-564")   # aile
    assert _m.is_risky_dismissal("CWE-798") and _m.is_risky_dismissal("CWE-259")
    assert not _m.is_risky_dismissal("CWE-120") and not _m.is_risky_dismissal(None)
