import sqlite3

from readers import cvefixes

DIFF = '@@ -1,2 +1,2 @@\n def get(c, u):\n-    c.execute("SELECT * FROM t WHERE id=%s" % u)\n+    c.execute("SELECT * FROM t WHERE id=?", (u,))\n'
BEFORE = 'def get(c, u):\n    c.execute("SELECT * FROM t WHERE id=%s" % u)\n'
AFTER = 'def get(c, u):\n    c.execute("SELECT * FROM t WHERE id=?", (u,))\n'


def _db(path, lang="Python", cwe="CWE-89", before=BEFORE):
    c = sqlite3.connect(path)
    c.executescript("""
    CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
    CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);
    CREATE TABLE file_change(file_change_id TEXT, hash TEXT, filename TEXT, diff TEXT,
        code_before TEXT, code_after TEXT, programming_language TEXT);
    CREATE TABLE method_change(file_change_id TEXT, name TEXT, start_line TEXT,
        end_line TEXT, before_change TEXT);
    """)
    c.execute("INSERT INTO cwe_classification VALUES ('CVE-1','NVD-CWE-Other'),('CVE-1',?)", (cwe,))
    c.execute("INSERT INTO fixes VALUES ('CVE-1','h1','https://r/x')")
    c.execute("INSERT INTO file_change VALUES ('f1','h1','db.py',?,?,?,?)",
              (DIFF, before, AFTER, lang))
    c.execute("INSERT INTO method_change VALUES ('f1','get','1','2','True')")
    c.commit()
    c.close()


def test_yields_vulnerable_and_clean(tmp_path):
    db = tmp_path / "c.db"
    _db(db)
    recs = list(cvefixes.read(db))
    assert len(recs) == 2
    vuln, clean = recs
    f = vuln["findings"][0]
    assert (f["cwe"], f["line"], f["function"]) == ("CWE-89", 2, "get")
    assert "execute" in f["evidence"]
    assert vuln["group"] == "https://r/x"
    assert clean["findings"] == [] and clean["code"] == AFTER


def test_skips_unsupported_language(tmp_path):
    db = tmp_path / "c.db"
    _db(db, lang="COBOL")
    assert list(cvefixes.read(db)) == []


def test_skips_oversized(tmp_path):
    db = tmp_path / "c.db"
    _db(db, before=BEFORE + "#" * 13_000)
    assert list(cvefixes.read(db)) == []
