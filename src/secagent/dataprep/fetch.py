"""
Ham veri setlerinin durumu, lisans notları ve edinme talimatları.

Bu modül veri İNDİRMEZ (CVEfixes tek bir 12,7 GB zip; indirme kullanıcı terminalinde
daha güvenilir ve kesintide devam edebilir). Yaptıkları:
  - data/raw/<Set>/ klasörlerini ve LICENSE_NOTE.txt dosyalarını kurar,
  - her setin hazır olup olmadığını DOSYADAN denetler (elle bayrak yok),
  - hazır olmayan set için tam talimatı yazdırır.

Okuyucusu olan set: yalnızca CVEfixes. Diğerleri kayıtlı ama henüz okuyucu yok.

LİSANS: Her veri setinin lisansı farklıdır; eğitimde yalnızca izin verenleri kullan.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ..paths import CVEFIXES_DB, RAW

CVEFIXES_RECORD = "https://zenodo.org/records/13118970"
CVEFIXES_ZIP = "https://zenodo.org/api/records/13118970/files/CVEfixes_v1.0.8.zip/content"

CVEFIXES_STEPS = f"""\
CVEfixes v1.0.8 (12,7 GB zip, CC BY 4.0; kayıt: {CVEFIXES_RECORD})
  mkdir -p {RAW}/CVEfixes && cd {RAW}/CVEfixes
  curl -L -C - -o CVEfixes_v1.0.8.zip "{CVEFIXES_ZIP}"     # kesilirse aynı komutla devam eder
  unzip CVEfixes_v1.0.8.zip -d extracted                   # içinde Data/CVEfixes_v1.0.8.sql.gz var
  gzcat extracted/CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz | sqlite3 CVEfixes.db   # ~48 GB
  # sonra zip ve extracted/ silinebilir; yalnızca CVEfixes.db gerekir
Daha küçük sürümler: v1.0.7 (3,9 GB, zenodo.org/records/7029359), v1.0.0 (1,1 GB, zenodo.org/records/4476564).
"""

_CVEFIXES_TABLES = {"fixes", "file_change", "method_change", "cwe_classification", "cve"}


@dataclass(frozen=True)
class Dataset:
    name: str
    repo: str
    license_note: str
    languages: tuple[str, ...]
    reader: bool = False


REGISTRY: tuple[Dataset, ...] = (
    Dataset("CVEfixes", "https://github.com/secureIT-project/CVEfixes",
            "Veri CC BY 4.0 — atıf gerekir. Kodun lisansını ayrıca kontrol et.",
            ("python", "java", "cpp", "javascript", "php", "go", "ruby", "rust", "swift",
             "typescript", "csharp"), reader=True),
    Dataset("Vul4J", "https://github.com/tuhh-softsec/vul4j",
            "Repo lisansını kontrol et.", ("java",)),
    Dataset("DiverseVul", "https://github.com/wagner-group/diversevul",
            "Araştırma amaçlı. Yeniden dağıtım şartlarını kontrol et.", ("cpp",)),
    Dataset("PrimeVul", "https://github.com/DLVulDet/PrimeVul",
            "Araştırma amaçlı. Şartları kontrol et.", ("cpp",)),
)


def cvefixes_ready(db: Path = CVEFIXES_DB) -> bool:
    """DB var mı ve beklenen tablolar mevcut mu (salt okunur)."""
    if not db.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return _CVEFIXES_TABLES <= names


def prepare(root: Path = RAW) -> list[dict]:
    """Klasörleri ve lisans notlarını kurar; durum listesini döndürür."""
    root.mkdir(parents=True, exist_ok=True)
    status = []
    for ds in REGISTRY:
        d = root / ds.name
        d.mkdir(exist_ok=True)
        note = d / "LICENSE_NOTE.txt"
        if not note.exists():
            note.write_text(f"{ds.name}\nKaynak: {ds.repo}\nLisans: {ds.license_note}\n",
                            encoding="utf-8")
        ready = cvefixes_ready(root / "CVEfixes" / "CVEfixes.db") if ds.name == "CVEfixes" else False
        status.append({"name": ds.name, "repo": ds.repo, "license": ds.license_note,
                       "languages": list(ds.languages), "reader": ds.reader,
                       "ready": ready, "path": str(d)})
    (root / "manifest.json").write_text(
        json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
    return status


def main() -> int:
    status = prepare()
    for s in status:
        mark = "HAZIR" if s["ready"] else ("okuyucu yok" if not s["reader"] else "EKSİK")
        print(f"{s['name']:11} {mark}")
    if not any(s["name"] == "CVEfixes" and s["ready"] for s in status):
        print("\n" + CVEFIXES_STEPS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
