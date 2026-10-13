import json

from helpers import run_build

from secagent.dataprep.sources import synthetic as sy
from secagent.dataprep.sources.templates import TEMPLATES
from secagent.schema import LANGUAGES, Example, validate_file
from secagent.dataprep.splits import split_for


def test_templates_cover_the_missing_languages():
    langs = {t.language for t in TEMPLATES}
    assert {"kotlin", "swift", "docker", "terraform", "kubernetes"} <= langs
    assert langs <= set(LANGUAGES)


def test_every_variant_renders_fully_and_locates_evidence():
    for t in TEMPLATES:
        for i in range(8):
            recs = sy.records_for(t, i)
            assert len(recs) >= 2, f"{t.id}#{i}: kanıt satırı bulunamadı"
            for r in recs:
                assert "<<" not in r["code"] and "<<" not in r["file"], t.id
                assert "/" not in r["file"].replace("Dockerfile", "")


def test_gold_line_points_at_evidence():
    for t in TEMPLATES:
        vuln = sy.records_for(t, 0)[0]
        f = vuln["findings"][0]
        assert f["evidence"] in vuln["code"].splitlines()[f["line"] - 1]
        assert vuln["findings"][0]["false_positive"] if "false_positive" in f else True
        assert vuln["pair_cwe"] == t.cwe and f["severity"] == t.severity


def test_false_positive_candidates_require_alarm_and_are_labeled_fp():
    cands = [r for t in TEMPLATES for r in sy.records_for(t, 0) if r.get("require_alarm")]
    assert len(cands) >= 6
    assert all(r["findings"][0]["false_positive"] and r["findings"][0]["severity"] == "info"
               for r in cands)


def test_keep_validated_false_positives_drops_unflagged_only():
    recs = [{"require_alarm": True, "scanner_output": ""},
            {"require_alarm": True, "scanner_output": "semgrep: x"},
            {"scanner_output": ""}]
    kept, dropped = sy.keep_validated_false_positives(recs)
    assert dropped == 1 and len(kept) == 2


def test_variants_of_a_template_share_a_split():
    for t in TEMPLATES:
        groups = {r["group"] for i in range(5) for r in sy.records_for(t, i)}
        assert len(groups) == 1
        split_for(next(iter(groups)))


def test_variants_are_diverse():
    codes = {sy.records_for(TEMPLATES[0], i)[0]["code"] for i in range(8)}
    assert len(codes) >= 4


def test_cli_synthetic_without_scanners_drops_unvalidated_fps(tmp_path):
    out = tmp_path / "o"
    r = run_build("--synthetic", "2", "--out-dir", str(out))
    assert "elenen" in r.stdout
    rows = [json.loads(l) for n in ("train", "val", "test")
            for l in (out / f"{n}.jsonl").read_text().splitlines()]
    assert sum(validate_file(out / f"{n}.jsonl")[1] for n in ("train", "val", "test")) == 0
    assert not any(f["false_positive"] and "yanlış alarm" in f["title"]
                   for row in rows for f in row["output"]["findings"])
    assert {"kotlin", "swift", "docker", "terraform", "kubernetes"} <= \
        {row["input"]["language"] for row in rows}
    Example.model_validate(rows[0])
