import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from schema import Example, validate_file
from splits import split_for

from test_cvefixes import _db

ROOT = Path(__file__).resolve().parent.parent


def test_split_is_deterministic_and_covers_all():
    assert split_for("repo-a") == split_for("repo-a")
    names = {split_for(f"r{i}") for i in range(500)}
    assert names == {"train", "val", "test"}


def test_strip_removes_cvss_and_refs(tmp_path):
    out = tmp_path / "t.jsonl"
    subprocess.run([sys.executable, str(ROOT / "build/make_examples.py"),
                    "--out", str(out), "--strip"], check=True, capture_output=True)
    for line in out.read_text().splitlines():
        for f in json.loads(line)["output"]["findings"]:
            assert "cvss" not in f and "references" not in f


def test_default_keeps_cvss_and_refs(tmp_path):
    out = tmp_path / "t.jsonl"
    subprocess.run([sys.executable, str(ROOT / "build/make_examples.py"),
                    "--out", str(out)], check=True, capture_output=True)
    first = json.loads(out.read_text().splitlines()[0])
    assert first["output"]["findings"][0]["references"]


def test_cvefixes_end_to_end_split(tmp_path):
    db = tmp_path / "c.db"
    _db(db)
    out = tmp_path / "o"
    subprocess.run([sys.executable, str(ROOT / "build/make_examples.py"),
                    "--out-dir", str(out), "--cvefixes", str(db)],
                   check=True, capture_output=True)
    total = 0
    for name in ("train", "val", "test"):
        ok, bad = validate_file(out / f"{name}.jsonl")
        assert bad == 0
        total += ok
    assert total == 4  # 2 örnek (samples) + zafiyetli + temiz


def test_invalid_language_rejected():
    import pytest
    with pytest.raises(Exception):
        Example.model_validate({"input": {"file": "a", "language": "cobol", "code": "x"},
                               "output": {"findings": []}})
