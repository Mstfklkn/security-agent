import json

from secagent import prompt
from secagent.schema import Example, ExampleInput, ExampleOutput, Finding

CODE = "def get(c, u):\n    q = \"SELECT %s\" % u\n    return c.execute(q)\n"


def _inp(**kw):
    base = dict(file="app/db.py", language="python", code=CODE,
                scanner_output="bandit: [B608] sql (app/db.py:2, severity: medium)")
    return ExampleInput(**{**base, **kw})


def _finding(**kw):
    base = dict(cwe="CWE-89", severity="high", function="get", line=2, title="SQL enjeksiyonu",
                evidence='q = "SELECT %s" % u', fix="Parametreli sorgu kullan.", false_positive=False)
    return Finding(**{**base, **kw})


def test_numbered_lines_and_user_message_layout():
    assert prompt.number_lines("a\nb\n") == "1| a\n2| b"
    msg = prompt.user_message(_inp())
    assert msg.index("Scanner output:") < msg.index("Code")          # kod en sonda
    assert "File: app/db.py" in msg and "Language: python" in msg
    assert "2|     q = \"SELECT %s\" % u" in msg
    assert "(none)" in prompt.user_message(_inp(scanner_output=""))


def test_messages_are_system_then_user_only():
    m = prompt.build_messages(_inp())
    assert [x["role"] for x in m] == ["system", "user"]
    assert "JSON" in m[0]["content"] and "Turkish" in m[0]["content"]
    assert "never" in m[0]["content"].lower() and "exploit" in m[0]["content"].lower()
    assert "untrusted" in m[0]["content"].lower()                    # istem enjeksiyonuna karşı


def test_render_target_drops_enrichment_sorts_and_is_compact():
    out = ExampleOutput(findings=[_finding(line=9, cwe="CWE-78"), _finding(line=2)], summary="özet")
    out.findings[1] = out.findings[1].model_copy(update={"references": ["https://x.example"],
                                                         "cvss": {"score": 8.8, "vector": "CVSS:3.1/AV:N"}})
    text = prompt.render_target(out)
    d = json.loads(text)
    assert [f["line"] for f in d["findings"]] == [2, 9]
    assert all(set(f) == {"cwe", "severity", "function", "line", "title", "evidence", "fix",
                          "false_positive"} for f in d["findings"])
    assert "references" not in text and "cvss" not in text and "https" not in text
    assert ", " not in text.replace("özet", "")                      # kompakt ayırıcı


def test_render_target_truncates_long_fields_without_breaking_evidence_prefix():
    long_fix = "x" * 5000
    f = _finding(fix=long_fix, evidence="e" * 900)
    d = json.loads(prompt.render_target(ExampleOutput(findings=[f], summary="s" * 900)))
    assert len(d["findings"][0]["fix"]) <= prompt.MAX_FIX_CHARS
    assert d["findings"][0]["evidence"] == "e" * prompt.MAX_EVIDENCE_CHARS
    assert len(d["summary"]) <= prompt.MAX_SUMMARY_CHARS
    assert d["findings"][0]["fix"].endswith("(kısaltıldı)")


def test_empty_findings_roundtrip():
    out = ExampleOutput(findings=[], summary="Bulgu yok.")
    assert prompt.render_target(out) == '{"findings":[],"summary":"Bulgu yok."}'
    assert prompt.parse_output(prompt.render_target(out)) == out


def test_roundtrip_through_parser_keeps_model_fields():
    out = ExampleOutput(findings=[_finding(function=None, false_positive=True)], summary="s")
    back = prompt.parse_output(prompt.render_target(out))
    assert back.findings[0].false_positive is True and back.findings[0].function is None
    assert back.findings[0].cwe == "CWE-89" and back.findings[0].references == []


def test_parse_output_is_tolerant_but_strict_about_structure():
    ok = '{"findings":[],"summary":"s"}'
    assert prompt.parse_output("```json\n" + ok + "\n```") is not None       # çit
    assert prompt.parse_output("Sonuç:\n" + ok + "\nbitti") is not None     # önce/sonra metin
    assert prompt.parse_output('{"findings":[{"cwe":"89"}],"summary":"s"}') is None   # şema ihlali
    assert prompt.parse_output("bulgu yok") is None
    assert prompt.parse_output('{"summary":"s"}') is None                     # findings yok
    assert prompt.parse_output('{"findings":[],"summary":"s"') is None       # kırık JSON
    assert prompt.parse_output("") is None and prompt.parse_output(None) is None


def test_parse_output_picks_first_balanced_object_even_with_braces_in_strings():
    f = _finding(evidence='if (x) { y(); }')
    text = prompt.render_target(ExampleOutput(findings=[f], summary="s")) + ' {"baska":1}'
    out = prompt.parse_output(text)
    assert out is not None and out.findings[0].evidence == "if (x) { y(); }"


def test_render_target_strips_cve_ids_as_a_safety_net_but_keeps_code_evidence():
    f = _finding(title="SQL enjeksiyonu (CVE-2019-6978)", fix="Bkz. CVE-2020-12345 yaması: parametre kullan.",
                 evidence="// CVE-2018-1111 notu")
    text = prompt.render_target(ExampleOutput(findings=[f], summary="Bulgu (CVE-2021-0001 ile ilişkili yama)."))
    d = json.loads(text)
    assert "CVE-" not in d["findings"][0]["title"] and "CVE-" not in d["findings"][0]["fix"]
    assert "CVE-" not in d["summary"]
    assert d["findings"][0]["title"] == "SQL enjeksiyonu"
    assert d["findings"][0]["evidence"] == "// CVE-2018-1111 notu"          # kod kanıtı bozulmaz


def test_parse_output_strips_model_supplied_references_cvss_and_caps_lengths():
    payload = {"findings": [{"cwe": "CWE-89", "severity": "high", "function": None, "line": 2,
                             "title": "SQL enjeksiyonu", "evidence": "e" * 5000, "fix": "f" * 9000,
                             "false_positive": False, "references": ["http://evil.example"],
                             "cvss": {"score": 10.0, "vector": "CVSS:3.1/AV:N"}}],
               "summary": "s" * 9000}
    out = prompt.parse_output(json.dumps(payload))
    f = out.findings[0]
    assert f.references == [] and f.cvss is None                       # enjeksiyonla gelen URL/skor atılır
    assert len(f.evidence) <= 1000 and len(f.fix) <= 2000 and len(out.summary) <= 1000


def test_parse_output_tries_later_candidates_when_an_earlier_brace_block_is_not_the_answer():
    ok = '{"findings":[],"summary":"s"}'
    assert prompt.parse_output("Sure {see below}: " + ok) is not None
    assert prompt.parse_output('{"a":1} ' + ok) is not None
    assert prompt.parse_output("{not json} {also: no}") is None
