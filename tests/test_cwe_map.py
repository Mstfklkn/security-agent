from secagent import mappings
from secagent.scanners.rules import fill_cwe


def test_related_families():
    assert mappings.cwe_related("CWE-119", "CWE-120")
    assert mappings.cwe_related("CWE-89", "CWE-89")
    assert not mappings.cwe_related("CWE-89", "CWE-78")
    assert not mappings.cwe_related(None, "CWE-89")


def test_fill_cwe_from_rule_and_noise_drop():
    f = [{"tool": "hadolint", "rule_id": "DL3002", "severity": "warning", "cwe": None},
         {"tool": "hadolint", "rule_id": "DL3015", "severity": "info", "cwe": None},
         {"tool": "trivy", "rule_id": "X", "severity": "low", "cwe": None},
         {"tool": "bandit", "rule_id": "B1", "severity": "low", "cwe": "CWE-78"}]
    out = fill_cwe(f)
    assert [(x["rule_id"], x["cwe"]) for x in out] == [("DL3002", "CWE-250"), ("B1", "CWE-78")]
    assert f[0]["cwe"] is None                      # girdi değişmedi
