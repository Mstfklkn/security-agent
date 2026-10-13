from secagent.dataprep.sources.common import (enclosing_function, first_changed_line,
                            removed_lines, template_fix)

DIFF = """@@ -3,4 +3,4 @@ def f():
     a = 1
-    q = "SELECT %s" % x
+    q = "SELECT ?"
     b = 2
"""


def test_removed_lines_old_numbering():
    assert removed_lines(DIFF) == [4]


def test_first_changed_line_skips_blank():
    code = "import x\n\ndef f():\n    a = 1\n    q = 1\n"
    assert first_changed_line("@@ -2,1 +2,0 @@\n-\n@@ -5,1 +5,1 @@\n-    q = 1\n+    q = 2\n", code) == 5


def test_no_removals_returns_none():
    assert first_changed_line("@@ -1,1 +1,2 @@\n a\n+b\n", "a\n") is None


def test_enclosing_function_picks_narrowest():
    ms = [("outer", 1, 20), ("inner", 5, 8)]
    assert enclosing_function(iter(ms), 6) == "inner"
    assert enclosing_function(iter(ms), 30) is None


def test_template_fix_truncates():
    out = template_fix("SQL", "x" * 5000)
    assert "kısaltıldı" in out and len(out) < 1800
