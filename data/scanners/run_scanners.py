"""
Tarayıcı katmanı — ajanın "gözü".

Bir kod yolu alır, dile göre doğru statik analiz araçlarını çalıştırır ve
hepsinin çıktısını tek bir ortak JSON formatına toplar. Bu format hem
eğitim verisi üretmekte (make_examples.py) hem de çalışma anında ajanın
girdisi olarak kullanılır.

Bu modül yalnızca TESPİT aracı çalıştırır (SAST / bağımlılık / sır / yapılandırma
tarama). Hiçbir exploit veya saldırı yürütmez.

Kurulum (macOS):
    brew install semgrep osv-scanner gitleaks trivy cppcheck hadolint \
                 gosec govulncheck ruby flawfinder
    gem install brakeman   # Ruby >= 3.2 (macOS sistem Ruby'si yetmez)
    pip install bandit pip-audit

Her araç yoksa atlanır (uyarı basılır), böylece eksik kurulumda da çalışır.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class RawFinding:
    tool: str
    file: str
    line: int | None
    rule_id: str
    message: str
    severity: str = "medium"
    cwe: str | None = None
    extra: dict = field(default_factory=dict)


def _have(tool: str) -> bool:
    if shutil.which(tool) is None:
        print(f"[uyarı] '{tool}' bulunamadı, atlanıyor.", file=sys.stderr)
        return False
    return True


def _run(cmd: list[str], cwd: str | None = None, timeout: int = 600,
         merge_stderr: bool = False) -> str:
    """Komutu çalıştırır. Tarayıcılar bulgu varken sıfırdan farklı kodla çıkar,
    bu yüzden çıkış kodu hata sayılmaz. merge_stderr: bulguları stderr'e yazan
    araçlar (cppcheck) için."""
    try:
        p = subprocess.run(
            cmd, cwd=cwd, text=True, timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
        )
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        print(f"[uyarı] zaman aşımı: {' '.join(cmd[:2])}", file=sys.stderr)
    except OSError as e:
        print(f"[uyarı] {cmd[0]} çalıştırılamadı: {e}", file=sys.stderr)
    return ""


def _json(text: str):
    """Boş/bozuk çıktıda None döner; bir aracın çıktısı taramayı düşürmesin."""
    try:
        return json.loads(text) if text.strip() else None
    except json.JSONDecodeError:
        return None


_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _cwe(raw) -> str | None:
    """'CWE-89: ...', 89, 'CWE-119!/CWE-120' -> ilk geçerli 'CWE-<n>'."""
    if raw is None or raw == "":
        return None
    text = str(raw).strip()
    if text.isdigit():
        return f"CWE-{text}"
    m = _CWE_RE.search(text)
    return f"CWE-{m.group(1)}" if m else None


def _int(raw) -> int | None:
    """'12-14' veya 12 -> 12."""
    try:
        return int(str(raw).split("-")[0])
    except (TypeError, ValueError):
        return None


# --- Araç sarmalayıcıları ------------------------------------------------
# Her biri RawFinding listesi döndürür. Araç yoksa boş liste.

def run_semgrep(path: str) -> list[RawFinding]:
    if not _have("semgrep"):
        return []
    data = _json(_run(["semgrep", "--config", "auto", "--json", "--quiet", path]))
    res = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        cwe_meta = extra.get("metadata", {}).get("cwe")
        if isinstance(cwe_meta, list):
            cwe_meta = cwe_meta[0] if cwe_meta else None
        res.append(RawFinding(
            tool="semgrep",
            file=r.get("path", ""),
            line=r.get("start", {}).get("line"),
            rule_id=r.get("check_id", ""),
            message=extra.get("message", ""),
            severity=extra.get("severity", "medium").lower(),
            cwe=_cwe(cwe_meta),
        ))
    return res


def run_bandit(path: str) -> list[RawFinding]:
    if not _have("bandit"):
        return []
    data = _json(_run(["bandit", "-r", "-f", "json", path]))
    return [RawFinding(
        tool="bandit",
        file=r.get("filename", ""),
        line=r.get("line_number"),
        rule_id=r.get("test_id", ""),
        message=r.get("issue_text", ""),
        severity=r.get("issue_severity", "medium").lower(),
        cwe=_cwe(r.get("issue_cwe", {}).get("id")),
    ) for r in (data or {}).get("results", [])]


def run_osv(path: str) -> list[RawFinding]:
    """Bağımlılık / sürüm taraması. Bilinen CVE'li paketleri bulur."""
    if not _have("osv-scanner"):
        return []
    data = _json(_run(["osv-scanner", "--format", "json", "-r", path]))
    res = []
    for r in (data or {}).get("results", []):
        src = r.get("source", {}).get("path", "")
        for pkg in r.get("packages", []):
            name = pkg.get("package", {}).get("name", "")
            ver = pkg.get("package", {}).get("version", "")
            for v in pkg.get("vulnerabilities", []):
                vid = v.get("id", "")
                res.append(RawFinding(
                    tool="osv-scanner", file=src, line=None, rule_id=vid,
                    message=f"{name}@{ver}: {v.get('summary', vid)}",
                    severity="high",
                    extra={"package": name, "version": ver, "vuln_id": vid},
                ))
    return res


def run_gitleaks(path: str) -> list[RawFinding]:
    """Koda sızmış API anahtarı / şifre / token taraması."""
    if not _have("gitleaks"):
        return []
    # Rapor, taranan dizini kirletmesin (salt-okunur dizinlerde de çalışsın).
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        _run(["gitleaks", "detect", "--no-git", "-s", path,
              "-r", str(report), "--redact", "-f", "json"])
        data = _json(report.read_text() if report.exists() else "")
    return [RawFinding(
        tool="gitleaks", file=r.get("File", ""), line=r.get("StartLine"),
        rule_id=r.get("RuleID", ""),
        message=f"Olası sızan sır: {r.get('Description', '')}",
        severity="high", cwe="CWE-798",
    ) for r in (data or [])]


def run_trivy(path: str) -> list[RawFinding]:
    """Yapılandırma (Dockerfile/Terraform/Kubernetes) ve bağımlılık taraması."""
    if not _have("trivy"):
        return []
    data = _json(_run(["trivy", "fs", "--quiet", "--format", "json",
                       "--scanners", "vuln,misconfig", path]))
    res = []
    for block in (data or {}).get("Results", []):
        target = block.get("Target", "")
        for m in block.get("Misconfigurations", []) or []:
            res.append(RawFinding(
                tool="trivy", file=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine"),
                rule_id=m.get("ID", ""),
                message=m.get("Title") or m.get("Message", ""),
                severity=m.get("Severity", "MEDIUM").lower(),
            ))
        for v in block.get("Vulnerabilities", []) or []:
            res.append(RawFinding(
                tool="trivy", file=target, line=None,
                rule_id=v.get("VulnerabilityID", ""),
                message=f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}: "
                        f"{v.get('Title', '')}",
                severity=v.get("Severity", "MEDIUM").lower(),
                extra={"package": v.get("PkgName"),
                       "version": v.get("InstalledVersion"),
                       "fixed": v.get("FixedVersion")},
            ))
    return res


def run_cppcheck(path: str) -> list[RawFinding]:
    if not _have("cppcheck"):
        return []
    # cppcheck bulguları stderr'e yazar -> merge_stderr
    out = _run(["cppcheck", "--enable=warning,style",
                "--template={file}:{line}:{id}:{severity}:{message}",
                "--quiet", path], merge_stderr=True)
    res = []
    for ln in out.splitlines():
        parts = ln.split(":", 4)
        if len(parts) == 5 and parts[1].isdigit():
            f, line, rid, sev, msg = parts
            res.append(RawFinding(tool="cppcheck", file=f, line=int(line),
                                  rule_id=rid, message=msg, severity=sev.lower()))
    return res


def run_flawfinder(path: str) -> list[RawFinding]:
    """C/C++ için tehlikeli fonksiyon taraması."""
    if not _have("flawfinder"):
        return []
    out = _run(["flawfinder", "--csv", "--quiet", path])
    level_to_sev = {"0": "info", "1": "low", "2": "low", "3": "medium",
                    "4": "high", "5": "high"}
    res = []
    for row in csv.DictReader(io.StringIO(out)):
        cwes = (row.get("CWEs") or "").split(",")
        res.append(RawFinding(
            tool="flawfinder", file=row.get("File", ""),
            line=_int(row.get("Line")), rule_id=row.get("Name", ""),
            message=row.get("Warning", ""),
            severity=level_to_sev.get(str(row.get("Level")), "medium"),
            cwe=_cwe(cwes[0]) if cwes else None,
        ))
    return res


def run_hadolint(path: str) -> list[RawFinding]:
    """Dockerfile denetimi."""
    if not _have("hadolint"):
        return []
    res = []
    for dockerfile in Path(path).rglob("Dockerfile*"):
        data = _json(_run(["hadolint", "-f", "json", str(dockerfile)]))
        for r in data or []:
            res.append(RawFinding(
                tool="hadolint", file=str(dockerfile), line=r.get("line"),
                rule_id=r.get("code", ""), message=r.get("message", ""),
                severity=r.get("level", "medium").lower(),
            ))
    return res


def run_gosec(path: str) -> list[RawFinding]:
    if not _have("gosec"):
        return []
    data = _json(_run(["gosec", "-fmt", "json", "-quiet", "./..."], cwd=path))
    return [RawFinding(
        tool="gosec", file=r.get("file", ""), line=_int(r.get("line")),
        rule_id=r.get("rule_id", ""), message=r.get("details", ""),
        severity=r.get("severity", "medium").lower(),
        cwe=_cwe((r.get("cwe") or {}).get("id")),
    ) for r in (data or {}).get("Issues", []) or []]


def run_govulncheck(path: str) -> list[RawFinding]:
    """Go bağımlılıklarında gerçekten ÇAĞRILAN zafiyetli fonksiyonları bulur."""
    if not _have("govulncheck"):
        return []
    out = _run(["govulncheck", "-json", "./..."], cwd=path)
    dec, idx, res = json.JSONDecoder(), 0, []
    while idx < len(out):
        while idx < len(out) and out[idx].isspace():
            idx += 1
        if idx >= len(out):
            break
        try:
            obj, idx = dec.raw_decode(out, idx)
        except json.JSONDecodeError:
            break
        finding = obj.get("finding")
        if not finding:
            continue
        frame = (finding.get("trace") or [{}])[0]
        pos = frame.get("position") or {}
        res.append(RawFinding(
            tool="govulncheck", file=pos.get("filename", ""),
            line=pos.get("line"), rule_id=finding.get("osv", ""),
            message=f"{frame.get('module', '')}@{frame.get('version', '')} "
                    f"{frame.get('function', '')}".strip(),
            # Yalnızca fonksiyon düzeyinde iz varsa zafiyetli kod GERÇEKTEN
            # çağrılıyordur; modül/paket düzeyi bulgu yalnızca içe aktarmadır.
            severity="high" if frame.get("function") else "low",
            extra={"vuln_id": finding.get("osv"),
                   "called": bool(frame.get("function"))},
        ))
    return res


def run_brakeman(path: str) -> list[RawFinding]:
    """Ruby on Rails."""
    if not _have("brakeman"):
        return []
    data = _json(_run(["brakeman", "-q", "-f", "json", "-p", path]))
    conf = {"High": "high", "Medium": "medium", "Weak": "low"}
    return [RawFinding(
        tool="brakeman", file=r.get("file", ""), line=r.get("line"),
        rule_id=r.get("warning_type", ""), message=r.get("message", ""),
        severity=conf.get(r.get("confidence", ""), "medium"),
        cwe=_cwe((r.get("cwe_id") or [None])[0]),
    ) for r in (data or {}).get("warnings", [])]


# --- Dil -> çalıştırılacak tarayıcılar -----------------------------------
Runner = Callable[[str], list[RawFinding]]

_BY_LANG: dict[str, list[Runner]] = {
    "python":     [run_semgrep, run_bandit, run_osv, run_gitleaks],
    "java":       [run_semgrep, run_osv, run_gitleaks],
    "kotlin":     [run_semgrep, run_osv, run_gitleaks],
    "cpp":        [run_semgrep, run_cppcheck, run_flawfinder, run_gitleaks],
    "csharp":     [run_semgrep, run_osv, run_gitleaks],
    "typescript": [run_semgrep, run_osv, run_gitleaks],
    "javascript": [run_semgrep, run_osv, run_gitleaks],
    "go":         [run_semgrep, run_gosec, run_govulncheck, run_osv, run_gitleaks],
    "rust":       [run_semgrep, run_osv, run_gitleaks],
    "php":        [run_semgrep, run_osv, run_gitleaks],
    "ruby":       [run_semgrep, run_brakeman, run_osv, run_gitleaks],
    "swift":      [run_semgrep, run_osv, run_gitleaks],
    "docker":     [run_hadolint, run_trivy, run_gitleaks],
    "terraform":  [run_trivy, run_semgrep, run_gitleaks],
    "kubernetes": [run_trivy, run_semgrep, run_gitleaks],
}

_ALIASES = {
    "c++": "cpp", "c": "cpp", "cxx": "cpp", "c#": "csharp", "cs": "csharp",
    "ts": "typescript", "js": "javascript", "py": "python", "rb": "ruby",
    "golang": "go", "dockerfile": "docker", "tf": "terraform",
    "k8s": "kubernetes", "kt": "kotlin",
}


def normalize_language(name: str) -> str:
    key = name.strip().lower()
    return _ALIASES.get(key, key)


def scan(path: str, language: str) -> list[dict]:
    """Verilen dil için tüm uygun tarayıcıları çalıştırır,
    ortak formatta sözlük listesi döndürür."""
    lang = normalize_language(language)
    runners = _BY_LANG.get(lang)
    if runners is None:
        print(f"[uyarı] bilinmeyen dil: {language}", file=sys.stderr)
        return []
    return [asdict(f) for runner in runners for f in runner(path)]


def scan_all(path: str) -> list[dict]:
    """Tüm dillerin tarayıcı birleşimini, her tarayıcıyı YALNIZCA BİR KEZ
    çalıştırarak uygular."""
    unique: list[Runner] = []
    for runners in _BY_LANG.values():
        for r in runners:
            if r not in unique:
                unique.append(r)
    seen: set[tuple] = set()
    out: list[dict] = []
    for runner in unique:
        for f in runner(path):
            d = asdict(f)
            key = (d["tool"], d["file"], d["line"], d["rule_id"])
            if key not in seen:
                seen.add(key)
                out.append(d)
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Savunma amaçlı statik tarama")
    ap.add_argument("path", help="taranacak kod klasörü")
    ap.add_argument("--lang", default=None,
                    help="/".join(_BY_LANG) + " (boşsa hepsi)")
    args = ap.parse_args()

    results = scan(args.path, args.lang) if args.lang else scan_all(args.path)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n{len(results)} ham bulgu.", file=sys.stderr)
