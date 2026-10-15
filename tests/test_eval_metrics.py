import json

from secagent import prompt
from secagent.eval import metrics
from secagent.schema import Example, ExampleInput, ExampleOutput, Finding

CODE = "\n".join(["int f(char *s)", "{", "    char b[8];", "    strcpy(b, s);", "    return b[0];", "}"])


def F(line=4, cwe="CWE-120", fp=False, evidence="strcpy(b, s);", **kw):
    return Finding(cwe=cwe, severity="high", function="f", line=line, title="Tampon taşması",
                   evidence=evidence, fix="strncpy kullan.", false_positive=fp, **kw)


def ex(findings, scanner="flawfinder: [strcpy] x (a.c:4, severity: high)", lang="cpp", code=CODE):
    return Example(input=ExampleInput(file="a.c", language=lang, code=code, scanner_output=scanner),
                   output=ExampleOutput(findings=findings, summary="s"))


def raw(*findings, summary="s"):
    return prompt.render_target(ExampleOutput(findings=list(findings), summary=summary))


def test_perfect_prediction_scores_one():
    e = ex([F()])
    s = metrics.score_example(e, raw(F()))
    assert (s["parsed"], s["tp"], s["fn"], s["spurious"]) == (True, 1, 0, 0)
    r = metrics.aggregate([s])
    assert r["precision"] == r["recall"] == r["f1"] == 1.0 and r["parse_rate"] == 1.0


def test_related_cwe_family_and_line_tolerance():
    e = ex([F(line=4, cwe="CWE-119")])
    assert metrics.score_example(e, raw(F(line=6, cwe="CWE-120")))["tp"] == 1      # aile + |2|
    assert metrics.score_example(e, raw(F(line=7, cwe="CWE-120")), line_tol=2)["tp"] == 0   # çok uzak
    assert metrics.score_example(e, raw(F(line=4, cwe="CWE-89")))["tp"] == 0               # başka CWE


def test_missed_finding_and_spurious_finding():
    e = ex([F()])
    s = metrics.score_example(e, raw())
    assert (s["tp"], s["fn"], s["spurious"]) == (0, 1, 0)
    s = metrics.score_example(e, raw(F(), F(line=1, cwe="CWE-78", evidence="int f(char *s)")))
    assert (s["tp"], s["fn"], s["spurious"]) == (1, 0, 1)
    r = metrics.aggregate([s])
    assert r["precision"] == 0.5 and r["recall"] == 1.0


def test_one_to_one_matching_does_not_double_count():
    e = ex([F()])
    s = metrics.score_example(e, raw(F(line=4), F(line=5)))
    assert s["tp"] == 1 and s["spurious"] == 1


def test_false_positive_triage():
    gold = ex([F(fp=True)])
    assert metrics.score_example(gold, raw())["fp_right"] == 1                       # atladı
    assert metrics.score_example(gold, raw(F(fp=True)))["fp_right"] == 1             # fp olarak işaretledi
    wrong = metrics.score_example(gold, raw(F(fp=False)))
    assert (wrong["fp_wrong"], wrong["fp_right"], wrong["spurious"]) == (1, 0, 0)    # gerçek diye bildirdi
    r = metrics.aggregate([metrics.score_example(gold, raw()), wrong])
    assert r["fp_rejection_rate"] == 0.5


def test_clean_examples_false_alarm_rate():
    clean = ex([], scanner="")
    ok = metrics.score_example(clean, raw())
    bad = metrics.score_example(clean, raw(F()))
    assert ok["clean_flagged"] is False and bad["clean_flagged"] is True
    assert metrics.aggregate([ok, bad])["clean_false_alarm_rate"] == 0.5


def test_unparseable_output_counts_as_failure_and_misses_everything():
    s = metrics.score_example(ex([F()]), "bulgu yok gibi")
    assert s["parsed"] is False and s["fn"] == 1 and s["tp"] == 0
    assert metrics.aggregate([s])["parse_rate"] == 0.0


def test_hallucination_checks():
    e = ex([F()])
    far = metrics.score_example(e, raw(F(line=99)))
    assert far["bad_line"] == 1
    fake = metrics.score_example(e, raw(F(evidence="gets(buf);")))
    assert fake["bad_evidence"] == 1 and fake["tp"] == 1
    ws = metrics.score_example(e, raw(F(evidence="strcpy(b,   s);")))       # boşluk farkı sorun değil
    assert ws["bad_evidence"] == 0
    r = metrics.aggregate([far, fake, ws])
    assert r["bad_line_rate"] == round(1 / 3, 4) or abs(r["bad_line_rate"] - 1 / 3) < 1e-3


def test_logic_recall_and_empty_scanner_recall():
    logic = ex([F(cwe="CWE-639")], scanner="")
    other = ex([F()], scanner="x")
    hit = metrics.score_example(logic, raw(F(cwe="CWE-639")))
    miss = metrics.score_example(other, raw())
    r = metrics.aggregate([hit, miss])
    assert r["logic_recall"] == 1.0 and r["scanner_missed_recall"] == 1.0
    assert r["recall"] == 0.5


def test_breakdown_by_language():
    a = metrics.score_example(ex([F()], lang="cpp"), raw(F()))
    b = metrics.score_example(ex([F()], lang="python"), raw())
    rep = metrics.report([a, b])
    assert rep["overall"]["recall"] == 0.5
    assert rep["by_language"]["cpp"]["recall"] == 1.0 and rep["by_language"]["python"]["recall"] == 0.0


def test_zero_division_is_none_not_a_crash():
    r = metrics.aggregate([metrics.score_example(ex([], scanner=""), raw())])
    assert r["recall"] is None and r["precision"] is None and r["fp_rejection_rate"] is None
    assert metrics.aggregate([])["examples"] == 0


def test_run_predictions_with_oracle_and_null_generators():
    exs = [ex([F()]), ex([], scanner="")]
    oracle = lambda messages, i=iter(range(10)): None
    outs = metrics.run_predictions(exs, lambda inp: prompt.render_target(
        next(e for e in exs if e.input is inp).output))
    assert [metrics.score_example(e, o)["parsed"] for e, o in zip(exs, outs)] == [True, True]
    rep = metrics.report([metrics.score_example(e, o) for e, o in zip(exs, outs)])
    assert rep["overall"]["f1"] == 1.0 and rep["overall"]["clean_false_alarm_rate"] == 0.0
    nulls = metrics.run_predictions(exs, lambda inp: '{"findings":[],"summary":"x"}')
    assert metrics.report([metrics.score_example(e, o) for e, o in zip(exs, nulls)])["overall"]["recall"] == 0.0


def test_predictions_file_roundtrip(tmp_path):
    p = tmp_path / "p.jsonl"
    metrics.write_predictions(p, ["a", "b\nc"])
    assert metrics.read_predictions(p) == ["a", "b\nc"]


# --- İNCELEME DÜZELTMELERİ: sahte başarıyı engelle ---------------------------
def test_silent_omission_is_not_credited_as_explicit_dismissal():
    gold = ex([F(fp=True)])
    omitted = metrics.score_example(gold, raw())
    explicit = metrics.score_example(gold, raw(F(fp=True)))
    assert (omitted["fp_omitted"], omitted["fp_explicit"]) == (1, 0)
    assert (explicit["fp_omitted"], explicit["fp_explicit"]) == (0, 1)
    r_null = metrics.aggregate([omitted])
    r_good = metrics.aggregate([explicit])
    assert r_null["fp_rejection_rate"] == 1.0 and r_null["fp_explicit_rate"] == 0.0     # susan model "mükemmel" görünmez
    assert r_good["fp_explicit_rate"] == 1.0


def test_unparsed_outputs_do_not_inflate_triage_or_clean_rates():
    gold_fp, clean = ex([F(fp=True)]), ex([], scanner="")
    bad = [metrics.score_example(gold_fp, "çöp"), metrics.score_example(clean, "çöp")]
    r = metrics.aggregate(bad)
    assert r["parse_rate"] == 0.0
    assert r["fp_rejection_rate"] is None and r["clean_false_alarm_rate"] is None     # ölçülemez, 1.0 DEĞİL
    assert r["counts"]["unparsed"] == 2


def test_example_key_detects_mismatched_prediction_files(tmp_path):
    a, b = ex([F()]), ex([F()], code=CODE + "\nint other;")
    assert metrics.example_key(a) != metrics.example_key(b) and metrics.example_key(a) == metrics.example_key(ex([]))
    p = tmp_path / "p.jsonl"
    metrics.write_predictions(p, ["x", "y"], keys=[metrics.example_key(a), metrics.example_key(b)])
    rows = metrics.read_prediction_rows(p)
    assert [r["key"] for r in rows] == [metrics.example_key(a), metrics.example_key(b)]
    assert metrics.read_predictions(p) == ["x", "y"]
    old = tmp_path / "old.jsonl"                                  # eski biçim (anahtarsız) okunabilir
    old.write_text('{"i": 0, "output": "z"}\n')
    assert metrics.read_prediction_rows(old)[0].get("key") is None
