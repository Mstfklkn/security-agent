import json

import pytest

from secagent.eval import backends, cli, metrics
from secagent.schema import Example, ExampleInput, ExampleOutput, Finding


def _gold(tmp_path):
    f = Finding(cwe="CWE-89", severity="high", function="g", line=2, title="SQL enjeksiyonu",
                evidence="q = 1", fix="Parametreli sorgu.", false_positive=False)
    exs = [Example(input=ExampleInput(file="a.py", language="python", code="a = 0\nq = 1\n",
                                      scanner_output="bandit: [B608] x"),
                   output=ExampleOutput(findings=[f], summary="s")),
           Example(input=ExampleInput(file="b.py", language="python", code="x = 1\n", scanner_output=""),
                   output=ExampleOutput(findings=[], summary="temiz"))]
    p = tmp_path / "gold.jsonl"
    p.write_text("\n".join(e.to_jsonl() for e in exs) + "\n")
    return p


def test_oracle_scores_perfect_and_null_scores_zero_recall(tmp_path, capsys):
    gold = _gold(tmp_path)
    out = tmp_path / "p.jsonl"
    assert cli.main(["predict", "--gold", str(gold), "--backend", "oracle", "--out", str(out)]) == 0
    rep = tmp_path / "r.json"
    assert cli.main(["score", "--gold", str(gold), "--pred", str(out), "--out", str(rep)]) == 0
    assert json.loads(rep.read_text())["overall"]["f1"] == 1.0
    cli.main(["predict", "--gold", str(gold), "--backend", "null", "--out", str(out)])
    cli.main(["score", "--gold", str(gold), "--pred", str(out), "--out", str(rep)])
    o = json.loads(rep.read_text())["overall"]
    assert o["recall"] == 0.0 and o["clean_false_alarm_rate"] == 0.0 and o["parse_rate"] == 1.0
    assert "python" in capsys.readouterr().out


def test_score_rejects_count_mismatch_and_limit_works(tmp_path):
    gold = _gold(tmp_path)
    out = tmp_path / "p.jsonl"
    metrics.write_predictions(out, ['{"findings":[],"summary":"x"}'])
    assert cli.main(["score", "--gold", str(gold), "--pred", str(out)]) == 2
    assert cli.main(["score", "--gold", str(gold), "--pred", str(out), "--limit", "1"]) == 0


def test_backend_factory_errors_and_null():
    assert backends.build_generator("null")(None) == backends.NULL_OUTPUT
    with pytest.raises(ValueError):
        backends.build_generator("mlx")                     # --model yok
    with pytest.raises(ValueError):
        backends.build_generator("bilinmeyen", "m")


def test_score_refuses_predictions_made_for_other_examples(tmp_path, capsys):
    gold = _gold(tmp_path)
    out = tmp_path / "p.jsonl"
    cli.main(["predict", "--gold", str(gold), "--backend", "null", "--out", str(out)])
    other = tmp_path / "other.jsonl"                               # aynı sayıda ama farklı örnekler
    exs = list(cli.iter_valid(gold))
    changed = [e.model_copy(update={"input": e.input.model_copy(update={"code": e.input.code + "# yeni\n"})})
               for e in exs]
    other.write_text("\n".join(e.to_jsonl() for e in changed) + "\n")
    assert cli.main(["score", "--gold", str(other), "--pred", str(out)]) == 2
    assert "uyuşmuyor" in capsys.readouterr().err


def test_score_warns_when_many_outputs_are_unparseable(tmp_path, capsys):
    gold = _gold(tmp_path)
    out = tmp_path / "p.jsonl"
    metrics.write_predictions(out, ["çöp", "çöp"])
    assert cli.main(["score", "--gold", str(gold), "--pred", str(out)]) == 0
    assert "UYARI" in capsys.readouterr().err
