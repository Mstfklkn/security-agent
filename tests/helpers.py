"""Test yardımcıları: sahte CVEfixes SQLite'ı ve CLI çalıştırıcı."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_build(*args: str) -> subprocess.CompletedProcess:
    """secagent.dataprep.build'i alt süreçte çalıştırır (editable kurulum gerekmez)."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run([sys.executable, "-m", "secagent.dataprep.build", *args],
                          check=True, capture_output=True, text=True, env=env)


DIFF = '@@ -1,2 +1,2 @@\n def get(c, u):\n-    c.execute("SELECT * FROM t WHERE id=%s" % u)\n+    c.execute("SELECT * FROM t WHERE id=?", (u,))\n'
BEFORE = 'def get(c, u):\n    c.execute("SELECT * FROM t WHERE id=%s" % u)\n'
AFTER = 'def get(c, u):\n    c.execute("SELECT * FROM t WHERE id=?", (u,))\n'


def make_db(path, lang="Python", cwe="CWE-89", before=BEFORE, cvss=("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")):
    c = sqlite3.connect(path)
    c.executescript("""
    CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
    CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);
    CREATE TABLE file_change(file_change_id TEXT, hash TEXT, filename TEXT, diff TEXT,
        code_before TEXT, code_after TEXT, programming_language TEXT);
    CREATE TABLE method_change(file_change_id TEXT, name TEXT, start_line TEXT,
        end_line TEXT, before_change TEXT, code TEXT);
    """)
    c.execute("CREATE TABLE cve(cve_id TEXT, cvss3_base_score TEXT, cvss3_vector_string TEXT)")
    c.execute("INSERT INTO cve VALUES ('CVE-1',?,?)", cvss)
    c.execute("INSERT INTO cwe_classification VALUES ('CVE-1','NVD-CWE-Other'),('CVE-1',?)", (cwe,))
    c.execute("INSERT INTO fixes VALUES ('CVE-1','h1','https://r/x')")
    c.execute("INSERT INTO file_change VALUES ('f1','h1','db.py',?,?,?,?)",
              (DIFF, before, AFTER, lang))
    c.execute("INSERT INTO method_change VALUES ('f1','get','1','2','True',?)", (BEFORE.strip(),))
    c.execute("INSERT INTO method_change VALUES ('f1','get','1','2','False',?)", (AFTER.strip(),))
    c.commit()
    c.close()
