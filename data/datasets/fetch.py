"""
Zafiyet / düzeltme veri setlerini indirir.

ÖNEMLİ — LİSANS: Her veri setinin lisansı farklıdır. Eğitimde yalnızca
lisansı buna izin veren setler kullanılmalıdır. İndirmeden önce aşağıdaki
notları oku. Bu script indirir ama lisans sorumluluğu sende; ticari kullanım
planlıyorsan her setin lisansını ayrıca teyit et.

Kaynaklar (hepsi savunma/araştırma amaçlı, zafiyet+düzeltme çiftleri içerir):

  CVEfixes   - Çok dilli (Python, Java, C/C++, JS...). Gerçek CVE'lere bağlı
               commit'ler. Lisans: veri CC BY 4.0, kod farklı olabilir.
               https://github.com/secureIT-project/CVEfixes
  Vul4J      - Java, derlenebilir/çalıştırılabilir zafiyetler.
               Lisans: repo'da belirtilen (kontrol et).
               https://github.com/tuhh-softsec/vul4j
  DiverseVul - C/C++, büyük ölçekli fonksiyon düzeyi zafiyet etiketleri.
               https://github.com/wagner-group/diversevul
  PrimeVul   - C/C++, yüksek kaliteli etiketlerle temizlenmiş set.
               https://github.com/DLVulDet/PrimeVul

Bu dosya iskelettir: her setin gerçek indirme mantığını kendi reposundaki
talimata göre dolduracağız. Şimdilik klasör yapısını ve lisans kaydını
hazırlar; böylece make_examples.py bu klasörlerden okuyabilir.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DATA_ROOT = Path(__file__).resolve().parent / "raw"


@dataclass
class Dataset:
    name: str
    repo: str
    license_note: str
    languages: list[str]


REGISTRY: list[Dataset] = [
    Dataset("CVEfixes", "https://github.com/secureIT-project/CVEfixes",
            "Veri CC BY 4.0 — atıf gerekir. Kodun lisansını ayrıca kontrol et.",
            ["python", "java", "cpp", "javascript"]),
    Dataset("Vul4J", "https://github.com/tuhh-softsec/vul4j",
            "Repo lisansını kontrol et.", ["java"]),
    Dataset("DiverseVul", "https://github.com/wagner-group/diversevul",
            "Araştırma amaçlı. Yeniden dağıtım şartlarını kontrol et.", ["cpp"]),
    Dataset("PrimeVul", "https://github.com/DLVulDet/PrimeVul",
            "Araştırma amaçlı. Şartları kontrol et.", ["cpp"]),
]


def prepare() -> None:
    """Klasör yapısını kurar ve lisans kaydını yazar.
    Gerçek indirme adımları her set için ayrıca eklenecek."""
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = []
    for ds in REGISTRY:
        d = DATA_ROOT / ds.name
        d.mkdir(exist_ok=True)
        (d / "LICENSE_NOTE.txt").write_text(
            f"{ds.name}\nKaynak: {ds.repo}\nLisans: {ds.license_note}\n",
            encoding="utf-8",
        )
        manifest.append({
            "name": ds.name, "repo": ds.repo,
            "license": ds.license_note, "languages": ds.languages,
            "path": str(d), "downloaded": False,
        })
    (DATA_ROOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Hazırlandı: {DATA_ROOT}")
    print("Her set için indirme talimatı ilgili repo'da. İndirince "
          "manifest.json içindeki 'downloaded' alanını True yap.")


if __name__ == "__main__":
    prepare()
