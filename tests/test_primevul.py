import json

from secagent.dataprep.sources import primevul
from secagent.dataprep.sources.common import group_key, first_diff_line, c_function_name

VULN = "int get(char *buf, int n)\n{\n    char tmp[8];\n    memcpy(tmp, buf, n);\n    return tmp[0];\n}\n"
FIXED = "int get(char *buf, int n)\n{\n    char tmp[8];\n    if (n > 8)\n        return -1;\n    memcpy(tmp, buf, n);\n    return tmp[0];\n}\n"


def row(idx, target, func, commit="c1", cwe=("CWE-787",), cve="CVE-2020-0001", file="a.c",
        url="https://github.com/acme/Lib"):
    return {"idx": idx, "project": "lib", "commit_id": commit, "project_url": url,
            "commit_url": url + "/commit/" + commit, "target": target, "func": func,
            "func_hash": idx, "file_name": file, "cwe": list(cwe), "cve": cve}


def write(tmp_path, name, rows):
    p = tmp_path / f"primevul_{name}_paired.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_group_key_normalizes_hosts_and_forks():
    assert group_key("https://github.com/openssl/openssl") == "openssl"
    assert group_key("https://github.com/Fork/OpenSSL.git/") == "openssl"
    assert group_key("https://git.savannah.gnu.org/gitweb/?p=gnutls") == "gnutls"
    assert group_key("https://git.savannah.gnu.org/gitweb/?p=gnutls.git;a=commit") == "gnutls"
    assert group_key("Linux") == "linux"
    assert group_key("") == "unknown"


def test_first_diff_line_replace_delete_and_insert_only():
    assert first_diff_line("a\nb\nc\n", "a\nX\nc\n") == 2            # değişen satır
    assert first_diff_line("a\nb\nc\n", "a\nc\n") == 2               # silinen satır
    assert first_diff_line(VULN, FIXED) == 4                         # yalnızca ekleme: ekleme noktasındaki satır
    assert first_diff_line("a\n", "a\n") is None


def test_c_function_name():
    assert c_function_name(VULN) == "get"
    assert c_function_name("static long ssl_get_algorithm2(SSL *s)\n{\n}") == "ssl_get_algorithm2"
    assert c_function_name("if (x) {") is None


def test_pairs_vulnerable_with_fixed_and_labels_first_changed_line(tmp_path):
    write(tmp_path, "train", [row(1, 1, VULN), row(2, 0, FIXED, file="None")])
    recs = list(primevul.read(tmp_path))
    assert len(recs) == 2
    vuln, clean = recs
    f = vuln["findings"][0]
    assert (f["cwe"], f["line"], f["function"], f["cve_id"]) == ("CWE-787", 4, "get", "CVE-2020-0001")
    assert "memcpy" in f["evidence"] or "tmp" in f["evidence"] or f["evidence"]
    assert vuln["language"] == "cpp" and vuln["group"] == "lib" == clean["group"]
    assert clean["findings"] == [] and clean["code"] == FIXED and clean["pair_cwe"] == "CWE-787"
    assert "if (n > 8)" in f["fix"]                                  # gerçek yama farkı


def test_orientation_does_not_depend_on_row_order(tmp_path):
    write(tmp_path, "valid", [row(2, 0, FIXED), row(1, 1, VULN)])
    vuln, clean = list(primevul.read(tmp_path))
    assert vuln["code"] == VULN and clean["code"] == FIXED


def test_skips_unpaired_identical_nocwe_and_oversized(tmp_path):
    rows = [row(1, 1, VULN), row(2, 0, VULN),                         # özdeş
            row(3, 1, VULN, commit="c2"), row(4, 0, FIXED, commit="c3"),  # farklı commit
            row(5, 1, VULN, commit="c4", cwe=("NVD-CWE-Other",)), row(6, 0, FIXED, commit="c4", cwe=("NVD-CWE-Other",)),
            row(7, 1, VULN + "x" * 7000, commit="c5"), row(8, 0, FIXED + "x" * 7000, commit="c5")]
    write(tmp_path, "train", rows)
    assert list(primevul.read(tmp_path)) == []


def test_limit_and_real_cvss_lookup(tmp_path):
    write(tmp_path, "train", [row(1, 1, VULN, commit="a"), row(2, 0, FIXED, commit="a"),
                              row(3, 1, VULN, commit="b"), row(4, 0, FIXED, commit="b")])
    cv = {"CVE-2020-0001": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}
    recs = list(primevul.read(tmp_path, limit=1, cvss=cv))
    assert len(recs) == 2
    assert recs[0]["findings"][0]["cvss"] == [9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]


def test_unpaired_clean_negatives_are_deterministic_and_limited(tmp_path):
    clean = [row(i, 0, f"int f{i}(void)\n{{\n    return {i};\n}}\n", commit=f"k{i}") for i in range(20)]
    (tmp_path / "primevul_train.jsonl").write_text("\n".join(json.dumps(r) for r in clean))
    a = list(primevul.read_clean(tmp_path, 5)); b = list(primevul.read_clean(tmp_path, 5))
    assert len(a) == 5 and a == b
    assert all(r["findings"] == [] and r["pair_cwe"] is None for r in a)


# --- İNCELEME DÜZELTMELERİ ---------------------------------------------------
def test_group_key_real_world_urls_and_kernel_aliases():
    assert group_key("https://cgit.freedesktop.org/accountsservice/commit/?id=f9ab") == "accountsservice"
    assert group_key("https://cgit.freedesktop.org/drm/drm-misc/commit/?id=9f1f") == "drm-misc"
    assert group_key("https://git.pengutronix.de/cgit/barebox/commit/fs/nfs.c?h=next&id=574c") == "barebox"
    assert group_key("https://github.com/torvalds/linux/commit/abc") == "linux"
    assert group_key("https://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git") == "linux"
    for kernel in ("linux-2.6", "linux-stable", "linux-next", "linux-fs", "linux-fbdev"):
        assert group_key(f"https://example.org/{kernel}") == "linux", kernel
    assert group_key("https://github.com/linux-pam/linux-pam") == "linux-pam"      # ayrı proje, çekirdek değil
    assert group_key("https://github.com/o/r/commit/abc123?x=1") == "r"


def test_first_diff_line_ignores_whitespace_only_changes_and_empty_input():
    old = "a\n    b\nc\nd\n"
    new = "a\n  b\nX\nd\n"                       # 2. satır yalnızca girinti, 3. satır gerçek değişim
    assert first_diff_line(old, new) == 3
    assert first_diff_line("", "x\n") is None
    assert first_diff_line("x\n", "") == 1       # her şey silindi: ilk satır
    assert first_diff_line("a\n  b\n", "a\nb\n") is None


def test_titles_and_summaries_never_carry_cve_ids(tmp_path):
    write(tmp_path, "train", [row(1, 1, VULN, cve="CVE-2020-0001"), row(2, 0, FIXED, cve="CVE-2020-0001")])
    for rec in primevul.read(tmp_path):
        assert "CVE-" not in rec["summary"]
        for f in rec["findings"]:
            assert "CVE-" not in f["title"] and f["cve_id"] == "CVE-2020-0001"   # kimlik yalnızca üst veride
