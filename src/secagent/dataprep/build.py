"""
Eğitim örnekleri üreticisi.

İki kaynaktan JSONL eğitim örnekleri üretir:

  1) Zafiyet veri setleri (data/raw/*): zafiyetli kod + düzeltme commit'i.
     Her kayıttan "kod + tarayıcı çıktısı -> doğrulanmış rapor" örneği çıkar.

  2) Yerel örnek kod (samples/): kendi eklediğin, bilerek zafiyetli küçük
     dosyalar. Docker/web/UI gibi hazır veri az olan alanlar için.

Tüm çıktılar schema.Example ile doğrulanır; geçmeyen örnek yazılmaz.
Referans ve CVSS, mappings.py üzerinden deterministik eklenir — model
URL/CVE uydurmasın diye.

Kullanım:
    secagent-build --cvefixes --out-dir
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import mappings
from ..paths import CVEFIXES_DB, OUT, SAMPLES
from ..schema import CVSS, Example, ExampleInput, ExampleOutput, Finding
from . import enrich as enrich_scanners
from .sources import cvefixes, synthetic
from .splits import SPLITS, code_hash, split_for


def make_finding(
    cwe: str,
    line: int | None,
    title: str,
    evidence: str,
    fix: str,
    function: str | None = None,
    cve_id: str | None = None,
    real_cvss: tuple[float, str] | None = None,
    false_positive: bool = False,
    severity_override: str | None = None,
) -> Finding:
    """Bir bulguyu şema nesnesine çevirir; referans ve CVSS'i merkezi
    eşlemelerden deterministik ekler."""
    severity, dscore, dvector = mappings.defaults_for(cwe)
    severity = severity_override or severity

    cvss = None
    if real_cvss is not None:                 # kaynak veride gerçek CVSS varsa
        cvss = CVSS(score=real_cvss[0], vector=real_cvss[1])
    elif dscore is not None and dvector is not None:
        cvss = CVSS(score=dscore, vector=dvector)

    return Finding(
        cwe=cwe,
        severity=severity,
        cvss=cvss,
        function=function,
        line=line,
        title=title,
        evidence=evidence,
        fix=fix,
        references=mappings.references_for(cwe, cve_id),
        false_positive=false_positive,
    )


def example_from_record(rec: dict) -> Example | None:
    """Bir veri seti kaydını (normalize edilmiş) eğitim örneğine çevirir.

    Beklenen rec alanları:
        file, language, code, scanner_output (ops.),
        findings: [{cwe, line, title, evidence, fix, function?, cve_id?,
                    cvss?: [score, vector], false_positive?}]
        summary (ops.)
    """
    try:
        findings = [
            make_finding(
                cwe=f["cwe"],
                line=f.get("line"),
                title=f["title"],
                evidence=f["evidence"],
                fix=f["fix"],
                function=f.get("function"),
                cve_id=f.get("cve_id"),
                real_cvss=tuple(f["cvss"]) if f.get("cvss") else None,
                false_positive=f.get("false_positive", False),
                severity_override=f.get("severity"),
            )
            for f in rec.get("findings", [])
        ]
        return Example(
            input=ExampleInput(
                file=rec["file"],
                language=rec["language"],
                code=rec["code"],
                scanner_output=rec.get("scanner_output", ""),
            ),
            output=ExampleOutput(findings=findings, summary=rec.get("summary", "")),
        )
    except Exception as e:
        print(f"[atlandı] örnek üretilemedi: {e}", file=sys.stderr)
        return None


def load_samples(samples_dir: Path) -> list[dict]:
    """samples/*.json — elle hazırlanmış normalize kayıtlar."""
    recs = []
    if not samples_dir.exists():
        return recs
    for p in sorted(samples_dir.glob("*.json")):
        try:
            recs.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"[uyarı] {p} okunamadı: {e}", file=sys.stderr)
    return recs


def write_split(records: list[dict], out_dir: Path, training: bool) -> dict[str, int]:
    """Kayıtları repo bazında train/val/test'e böler, kod hash'iyle tekilleştirir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    handles = {n: open(out_dir / f"{n}.jsonl", "w", encoding="utf-8") for n in SPLITS}
    counts = {n: 0 for n in SPLITS}
    seen: set[tuple[str, bool]] = set()
    try:
        for rec in records:
            key = (code_hash(rec["code"]), bool(rec.get("findings")))
            if key in seen:
                continue
            ex = example_from_record(rec)
            if ex is None:
                continue
            seen.add(key)
            name = split_for(rec.get("group") or rec["file"])
            handles[name].write(ex.to_jsonl(training=training) + "\n")
            counts[name] += 1
    finally:
        for h in handles.values():
            h.close()
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="tek dosya çıktı (bölmesiz)")
    ap.add_argument("--out-dir", nargs="?", const=str(OUT),
                    help=f"train/val/test.jsonl klasörü (değer verilmezse {OUT})")
    ap.add_argument("--samples", default=str(SAMPLES))
    ap.add_argument("--cvefixes", nargs="?", const=str(CVEFIXES_DB),
                    help=f"CVEfixes.db yolu (değer verilmezse {CVEFIXES_DB})")
    ap.add_argument("--limit", type=int, help="CVEfixes'tan toplam en çok N (CVE, dosya) çifti")
    ap.add_argument("--granularity", choices=["file", "function", "both"], default="function",
                    help="CVEfixes örnek düzeyi (varsayılan: değişen fonksiyon)")
    ap.add_argument("--per-language", type=int,
                    help="CVEfixes'tan her dilden en çok N çift (dengeli örnekleme)")
    ap.add_argument("--synthetic", type=int, default=0, metavar="N",
                    help="her sentetik şablondan N varyant (kotlin/swift/docker/terraform/k8s)")
    ap.add_argument("--enrich", action="store_true",
                    help="gerçek tarayıcıları çalıştır, scanner_output ve yanlış alarmları ekle")
    ap.add_argument("--ambiguous", choices=["skip", "drop"], default="skip",
                    help="belirsiz alarmlı kayıtlar: atla (varsayılan) veya alarmı sil")
    ap.add_argument("--strip", action="store_true",
                    help="cvss/references hedeften çıkarılsın (varsayılan: kalır, "
                         "ilk istemdeki çıktı formatı)")
    args = ap.parse_args()
    if bool(args.out) == bool(args.out_dir):
        ap.error("--out veya --out-dir'den tam biri gerekli")

    records: list[dict] = list(load_samples(Path(args.samples)))
    if args.cvefixes:
        records += list(cvefixes.read(args.cvefixes, limit=args.limit,
                                         per_language=args.per_language,
                                         granularity=args.granularity))

    if args.synthetic:
        records += list(synthetic.generate(args.synthetic))
    if args.enrich:
        records, st = enrich_scanners.enrich(records, ambiguous=args.ambiguous)
        print(f"Zenginleştirme: {st}")
    records, dropped = synthetic.keep_validated_false_positives(records)
    if dropped:
        print(f"Sentetik yanlış alarm: tarayıcı işaretlemediği için elenen: {dropped}")

    training = args.strip
    if args.out_dir:
        counts = write_split(records, Path(args.out_dir), training)
        print(f"Yazıldı: {counts} -> {args.out_dir}")
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written, skipped = 0, 0
    with open(out_path, "w", encoding="utf-8") as f:
        for rec in records:
            ex = example_from_record(rec)
            if ex is None:
                skipped += 1
                continue
            f.write(ex.to_jsonl(training=training) + "\n")
            written += 1
    print(f"Yazıldı: {written}  Atlanan: {skipped}  -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
