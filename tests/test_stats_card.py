import json

from secagent.dataprep import stats
from secagent.dataprep.splits import SPLITS
from secagent.schema import Example, ExampleInput, ExampleOutput, Finding


def _ex(lang, cwe=None, fp=False):
    f = [Finding(cwe=cwe, severity="high", function=None, line=1, title="Başlık metni", evidence="x",
                 fix="y", false_positive=fp)] if cwe else []
    return Example(input=ExampleInput(file="a", language=lang, code="x = 1\n"),
                   output=ExampleOutput(findings=f, summary="s"))


def _write(d, name, exs):
    (d / f"{name}.jsonl").write_text("".join(e.to_jsonl() + "\n" for e in exs))


def test_card_counts_and_flags_gaps(tmp_path):
    _write(tmp_path, "train", [_ex("python", "CWE-89"), _ex("python"), _ex("go", "CWE-639"),
                               _ex("go", "CWE-120", fp=True)])
    _write(tmp_path, "val", [_ex("python", "CWE-639")])
    _write(tmp_path, "test", [_ex("go")])
    _write(tmp_path, "test_synthetic", [])
    card = stats.card(tmp_path)
    assert card["splits"]["train"]["examples"] == 4
    assert card["splits"]["train"]["kinds"] == {"gerçek": 2, "temiz": 1, "yanlış_alarm": 1}
    assert card["splits"]["train"]["logic_examples"] == 1 and card["splits"]["val"]["logic_examples"] == 1
    assert card["splits"]["train"]["languages"] == {"python": 2, "go": 2}
    assert "python" in card["languages_missing_in_split"]["test"]
    assert "go" not in card["languages_missing_in_split"]["test"]
    assert card["languages_missing_in_split"]["test_synthetic"][0] in stats.LANGUAGES
    assert any("zayıf denetimli" in n for n in card["notes"])


def test_card_cli_writes_json(tmp_path, monkeypatch):
    for n in SPLITS:
        _write(tmp_path, n, [_ex("python", "CWE-89")])
    monkeypatch.setattr("sys.argv", ["secagent-stats", "--card", str(tmp_path)])
    assert stats.main() == 0
    assert json.loads((tmp_path / "data_card.json").read_text())["splits"]["val"]["examples"] == 1


def test_missing_split_file_is_reported_not_crash(tmp_path):
    _write(tmp_path, "train", [_ex("python")])
    card = stats.card(tmp_path)
    assert card["splits"]["val"]["examples"] == 0


def test_card_fingerprints_change_when_data_changes(tmp_path):
    _write(tmp_path, "train", [_ex("python", "CWE-89")])
    a = stats.card(tmp_path)["splits"]["train"]["fingerprint"]
    _write(tmp_path, "train", [_ex("python", "CWE-89"), _ex("go")])
    b = stats.card(tmp_path)["splits"]["train"]["fingerprint"]
    assert a and b and a != b and len(a) == 16
    assert stats.card(tmp_path)["splits"]["val"]["fingerprint"] is None        # dosya yok
