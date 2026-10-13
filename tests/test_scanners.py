import json

from secagent.scanners import runners as rs
from secagent.schema import LANGUAGES


def test_every_language_has_scanners_and_matches_schema():
    assert set(rs._BY_LANG) == set(LANGUAGES)
    assert all(rs._BY_LANG[l] for l in LANGUAGES)


def test_aliases():
    assert rs.normalize_language("C++") == "cpp"
    assert rs.normalize_language("c#") == "csharp"
    assert rs.normalize_language("K8s") == "kubernetes"


def test_unknown_language_returns_empty():
    assert rs.scan(".", "cobol") == []


def test_missing_tool_is_skipped(monkeypatch):
    monkeypatch.setattr(rs.shutil, "which", lambda _: None)
    assert rs.run_semgrep(".") == []
    assert rs.run_gosec(".") == []


def _fake(monkeypatch, output):
    monkeypatch.setattr(rs, "_have", lambda _: True)
    monkeypatch.setattr(rs, "_run", lambda *a, **k: output)


def test_cppcheck_parses_merged_stderr(monkeypatch):
    _fake(monkeypatch, "a.cpp:7:nullPointer:error:476:Null pointer: a:b\nnoise\n"
                       "a.cpp:9:foo:warning:0:no cwe\n")
    f = rs.run_cppcheck(".")
    assert [(x.line, x.rule_id, x.severity, x.cwe) for x in f] == [
        (7, "nullPointer", "error", "CWE-476"), (9, "foo", "warning", None)]
    assert f[0].message == "Null pointer: a:b"


def test_gosec_cwe_and_line_range(monkeypatch):
    _fake(monkeypatch, json.dumps({"Issues": [{
        "severity": "HIGH", "cwe": {"id": "89"}, "rule_id": "G201",
        "details": "SQL string formatting", "file": "m.go", "line": "12-14"}]}))
    f = rs.run_gosec(".")[0]
    assert (f.cwe, f.line, f.severity) == ("CWE-89", 12, "high")


def test_brakeman_and_flawfinder(monkeypatch):
    _fake(monkeypatch, json.dumps({"warnings": [{
        "file": "a.rb", "line": 3, "warning_type": "SQL Injection",
        "message": "m", "confidence": "High", "cwe_id": [89]}]}))
    assert rs.run_brakeman(".")[0].cwe == "CWE-89"
    _fake(monkeypatch, "File,Line,Column,Level,Category,Name,Warning,CWEs\n"
                       "a.c,5,1,4,buffer,strcpy,Dangerous,\"CWE-120, CWE-20\"\n")
    f = rs.run_flawfinder(".")[0]
    assert (f.line, f.cwe, f.severity) == (5, "CWE-120", "high")


def test_govulncheck_streamed_json(monkeypatch):
    _fake(monkeypatch,
          '{"config":{}}\n{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1",'
          '"function":"F","position":{"filename":"x.go","line":9}}]}}\n')
    f = rs.run_govulncheck(".")
    assert [(x.rule_id, x.line) for x in f] == [("GO-1", 9)]


def test_trivy_misconfig_and_vuln(monkeypatch):
    _fake(monkeypatch, json.dumps({"Results": [{
        "Target": "main.tf",
        "Misconfigurations": [{"ID": "AVD-1", "Title": "open sg", "Severity": "HIGH",
                               "CauseMetadata": {"StartLine": 4}}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p",
                             "InstalledVersion": "1", "Severity": "LOW"}]}]}))
    f = rs.run_trivy(".")
    assert [(x.rule_id, x.line) for x in f] == [("AVD-1", 4), ("CVE-1", None)]


def test_bad_json_does_not_crash(monkeypatch):
    _fake(monkeypatch, "not json")
    assert rs.run_semgrep(".") == [] and rs.run_trivy(".") == []


def test_scan_all_runs_each_runner_once(monkeypatch):
    calls = []
    for name in {r.__name__ for rl in rs._BY_LANG.values() for r in rl}:
        monkeypatch.setattr(rs, name, lambda p, n=name: calls.append(n) or [])
    # _BY_LANG fonksiyon nesnelerini tuttuğu için tabloyu yeniden kur
    monkeypatch.setattr(rs, "_BY_LANG", {l: [getattr(rs, r.__name__) for r in rl]
                                         for l, rl in rs._BY_LANG.items()})
    rs.scan_all(".")
    assert len(calls) == len(set(calls))


def test_cwe_normalization_real_world_forms():
    assert rs._cwe("CWE-119!/CWE-120") == "CWE-119"
    assert rs._cwe("CWE-89: Improper Neutralization") == "CWE-89"
    assert rs._cwe(703) == "CWE-703" and rs._cwe("703") == "CWE-703"
    assert rs._cwe("NVD-CWE-Other") is None and rs._cwe(None) is None


def test_govulncheck_import_only_is_low_and_not_called(monkeypatch):
    _fake(monkeypatch, '{"finding":{"osv":"GO-2","trace":[{"module":"m","version":"v1"}]}}')
    f = rs.run_govulncheck(".")[0]
    assert (f.severity, f.extra["called"]) == ("low", False)
