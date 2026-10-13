# data/ — Eğitim verisi hazırlama

Savunma amaçlı güvenlik denetim ajanı için eğitim verisi üretir.
Bu aşama **GPU gerektirmez**, tamamen yerelde (Mac) çalışır. AWS GPU'yu
yalnızca eğitim adımında açacağız.

## Ne üretiyoruz

Her eğitim örneği bir JSONL satırı:

```json
{
  "input":  { "file": "...", "language": "python", "code": "...", "scanner_output": "..." },
  "output": { "findings": [ { "cwe": "CWE-89", "severity": "high",
              "cvss": {"score": 8.8, "vector": "CVSS:3.1/..."},
              "function": "get_user_by_id", "line": 42,
              "title": "...", "evidence": "...", "fix": "...",
              "references": ["..."], "false_positive": false } ],
              "summary": "..." }
}
```

Model öğreneceği iş: kod + tarayıcı çıktısı → **doğrulanmış** bulgu raporu.
En değerli beceri yanlış alarmları (false_positive) ayıklamak.

## Kurulum

```bash
cd data
pip install -r requirements.txt
brew install semgrep osv-scanner gitleaks trivy cppcheck flawfinder hadolint \
             gosec govulncheck ruby
# brakeman Homebrew'da yok; Ruby >= 3.2 gerekir (macOS sistem Ruby'si 2.6, yetmez)
export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH"
gem install brakeman
```

Araçların hepsi olmasa da boru hattı çalışır; eksik araç atlanır.

## Çalışma sırası

```bash
# 1) Bir kod klasörünü tara (ajanın "gözü")
python scanners/run_scanners.py /yol/proje --lang python

# 2) Zafiyet veri setlerinin klasör yapısını hazırla (lisans notlarıyla)
python datasets/fetch.py

# 3) Eğitim örneklerini üret (samples/ + datasets/raw/'dan)
python build/make_examples.py --out out/train.jsonl

# 4) Üretilen her örneği şemaya göre doğrula
python build/schema.py out/train.jsonl
```

## CVEfixes ile gerçek veri

CVEfixes.db'yi (SQLite, Zenodo/GitHub sayfasından) elle indir; sonra:

```bash
python build/make_examples.py --cvefixes /yol/CVEfixes.db --out-dir out/
python build/stats.py out/train.jsonl     # dil / CWE / tür dağılımı
python -m pytest tests --cov=readers --cov=build
```

- Her (CVE, dosya) için bir zafiyetli + bir temiz (düzeltilmiş) örnek üretilir.
- Bölme repo bazında (`build/splits.py`), tekilleştirme kod hash'iyle.
- `--enrich`: örneklere GERÇEK tarayıcı çıktısını ekler (`build/enrich_scanners.py`).
  Düzeltilmiş kodda yamanın CWE'siyle eşleşen kalıntı alarm `false_positive=true`
  örneği olur. Başka CWE'li/CWE'siz alarmlı kayıtlar belirsiz sayılıp atlanır
  (`--ambiguous drop`: alarmı silip kaydı tutar). Elle yazılmış `samples/`
  örneklerine dokunulmaz. Semgrep ilk çalışmada kural indirir (ağ gerekir).
- `cvss`/`references` hedef çıktıda kalır; koddan değil `mappings.py`'den
  deterministik gelir. `--strip` ile hedeften çıkarılabilir (model yalnızca
  yargıyı üretsin, bunlar çıkarım sonrası eklensin istenirse).

## Klasörler

| Yol | İş |
|-----|-----|
| `scanners/run_scanners.py` | Dile göre SAST/bağımlılık/sır tarayıcılarını çalıştırır, ortak JSON'a toplar |
| `readers/`                 | Veri seti okuyucuları (şimdilik `cvefixes.py`) → normalize kayıt |
| `build/enrich_scanners.py` | Gerçek tarayıcı çıktısı + yanlış-alarm etiketleme |
| `build/splits.py`, `build/stats.py` | Sızıntısız bölme, dağılım raporu |
| `datasets/fetch.py`        | Zafiyet/düzeltme veri setlerini hazırlar (lisans kontrolü şart) |
| `build/schema.py`          | Örnek şeması + doğrulayıcı |
| `build/mappings.py`        | CWE → referans ve CVSS eşlemeleri (uydurma referans/CVE önlenir) |
| `build/make_examples.py`   | Kayıtları şema doğrulamalı JSONL'e çevirir |
| `samples/*.json`           | Elle hazırlanmış örnek kayıtlar (Docker/web/UI gibi az-veri alanları için) |

## Kapsam

Yalnızca **tespit, denetim ve düzeltme önerisi**. Hiçbir araç exploit veya
saldırı yürütmez. Veri setleri yalnızca savunma/araştırma amaçlı kullanılır
ve her birinin lisansı ayrıca teyit edilmelidir.
