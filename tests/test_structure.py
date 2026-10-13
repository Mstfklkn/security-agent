"""Yapısal tutarlılık: tek kaynaktan türeyen listelerin birbiriyle uyumu."""
from secagent import paths
from secagent.dataprep import enrich, fetch
from secagent.dataprep.sources import cvefixes
from secagent.dataprep.sources.templates import TEMPLATES
from secagent.scanners import runners
from secagent.schema import LANGUAGES, Language

from helpers import make_db


def test_language_lists_derive_from_single_source():
    allowed = set(LANGUAGES)
    assert set(Language.__args__) == allowed
    assert set(runners._BY_LANG) == allowed
    assert set(cvefixes.LANG_MAP.values()) <= allowed
    assert set(enrich._EXT) <= allowed
    assert {t.language for t in TEMPLATES} <= allowed
    # dosya uzantısı olmayan tek dil: Dockerfile adı özel işlenir
    assert allowed - set(enrich._EXT) == {"docker"}


def test_paths_are_inside_the_repo():
    assert paths.SAMPLES.is_dir() and any(paths.SAMPLES.glob("*.json"))
    assert paths.CVEFIXES_DB.parent == paths.RAW / "CVEfixes"


def test_fetch_prepare_and_ready_checks_files_not_flags(tmp_path):
    status = fetch.prepare(tmp_path)
    by = {s["name"]: s for s in status}
    assert not by["CVEfixes"]["ready"] and by["CVEfixes"]["reader"]
    assert (tmp_path / "CVEfixes" / "LICENSE_NOTE.txt").exists()
    assert (tmp_path / "manifest.json").exists()
    make_db(tmp_path / "CVEfixes" / "CVEfixes.db")
    assert fetch.prepare(tmp_path)[0]["ready"] is True


def test_fetch_not_ready_for_wrong_db(tmp_path):
    import sqlite3
    db = tmp_path / "x.db"
    sqlite3.connect(db).execute("CREATE TABLE t(a)").connection.close()
    assert fetch.cvefixes_ready(db) is False
    assert fetch.cvefixes_ready(tmp_path / "yok.db") is False
