# security-agent

Savunma amaçlı güvenlik denetim ajanı: Qwen3-Coder-30B-A3B'yi LoRA ile ince ayarlayıp
Claude içinde (VS Code ve Claude Code, MCP aracı olarak) çalıştırmak.

**Kapsam yalnızca savunma:** zafiyet tespiti (SAST), bağımlılık/sır/yapılandırma denetimi ve
düzeltme önerisi. Hiçbir exploit veya saldırı yükü üretilmez/çalıştırılmaz.

Akış kodla sabit, model karar vermez: (1) tarayıcılar deterministik çalışır, (2) model çıktıları
ayıklar + kodu inceler + rapor yazar, (3) rapor Claude'a döner. Modelin asıl becerisi
tarayıcıların **yanlış alarmlarını** ayıklamak ve araçların kaçırdığı mantık hatalarını bulmaktır.

## Yapı

```
security-agent/
├── pyproject.toml            paket + bağımlılıklar + CLI giriş noktaları
├── src/secagent/             ortak kod (train/, export/, mcp_server/ bunu içe aktarır)
│   ├── schema.py             eğitim örneği şeması + doğrulayıcı (15 dilin tek kaynağı)
│   ├── mappings.py           CWE → referans/CVSS/ad/aile eşlemeleri (deterministik)
│   ├── paths.py              depo içi yollar
│   ├── scanners/
│   │   ├── runners.py        15 dil → dile göre tarayıcılar → ortak JSON
│   │   └── rules.py          CWE bildirmeyen kurallar için CWE + gürültü filtresi
│   └── dataprep/             eğitim verisi hazırlama (GPU gerektirmez)
│       ├── build.py          kayıtları şema-doğrulamalı train/val/test JSONL'e çevirir
│       ├── enrich.py         gerçek tarayıcı çıktısı + yanlış-alarm etiketleme
│       ├── splits.py         repo bazında sızıntısız bölme, kod hash'iyle tekilleştirme
│       ├── stats.py          dil / CWE / tür dağılımı
│       ├── fetch.py          ham veri durumu + edinme talimatları
│       └── sources/          veri kaynağı okuyucuları (cvefixes, sentetik şablonlar)
├── data/
│   ├── samples/              elle hazırlanmış örnekler (depoda)
│   ├── raw/                  indirilen ham veri (git dışı; CVEfixes.db burada)
│   └── out/                  üretilen train/val/test.jsonl (git dışı)
├── tests/
├── train/   export/   mcp_server/        (sıradaki fazlar; henüz yok)
```

## Kurulum

```bash
pip install -e ".[dev,scanners]"
brew install semgrep osv-scanner gitleaks trivy cppcheck flawfinder hadolint \
             gosec govulncheck ruby
# brakeman Homebrew'da yok; Ruby >= 3.2 gerekir (macOS sistem Ruby'si 2.6 yetmez)
export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH"
gem install brakeman
```

Araçların hepsi olmasa da boru hattı çalışır; eksik araç atlanır. Semgrep ilk çalışmada
kural indirir (ağ gerekir).

## Çalışma sırası

```bash
secagent-fetch                    # ham veri durumu; eksikse CVEfixes talimatını yazar
secagent-scan /yol/proje --lang python

# Eğitim verisi: gerçek (CVEfixes) + sentetik, gerçek tarayıcı çıktısıyla
secagent-build --cvefixes --per-language 40 --synthetic 8 --enrich --out-dir
secagent-validate data/out/train.jsonl
secagent-stats data/out/train.jsonl

pytest --cov=secagent
```

`--cvefixes` ve `--out-dir` değer verilmezse `data/raw/CVEfixes/CVEfixes.db` ve `data/out/`
kullanılır.

### Eğitim verisi nasıl üretiliyor

- **Düzey:** `--granularity function` (varsayılan): değişen **fonksiyon** örnek olur. Tarayıcı
  DOSYA üzerinde çalışır, modele yalnızca fonksiyon ve o fonksiyona düşen alarmlar verilir
  (satırlar fonksiyona göre yeniden numaralı). Çıkarımda aynı parçalama kullanılmalıdır.
  `file` ve `both` de var.
- **Çiftler:** her (CVE, dosya/fonksiyon) için bir zafiyetli + bir temiz (düzeltilmiş) örnek.
- **`--enrich`:** düzeltilmiş kodda yamanın CWE'siyle (veya ailesiyle) eşleşen kalıntı alarm
  `false_positive=true` örneği olur. Başka CWE'li/CWE'siz alarmlı kayıtlar belirsiz sayılıp
  atlanır (`--ambiguous drop`: alarmı silip kaydı tutar). `samples/` örneklerine dokunulmaz.
- **`--per-language N`:** her dilden en çok N çift (dengeli örnekleme).
- **`--synthetic N`:** CVEfixes'ta olmayan teknolojiler (kotlin, swift, docker, terraform,
  kubernetes) için şablon başına N varyant. Yanlış-alarm şablonları yalnızca **gerçek bir
  tarayıcı** o CWE için alarm verirse tutulur (`--enrich` gerekir). Bunlar "gerekçeli istisna"dır
  (ör. CSI eklentisi için privileged). Bir şablonun tüm varyantları aynı bölmeye düşer.
- `cvss`/`references` hedefte kalır ve koddan değil `mappings.py`'den deterministik gelir
  (model URL/CVE uydurmasın diye). `--strip` ile hedeften çıkarılabilir. CVSS, kaynak veride
  (CVEfixes/NVD) varsa gerçek değerdir; yoksa CWE varsayılanı, o da yoksa boş.
- **Bölme:** repo bazında (aynı repo hep aynı bölmede) ve kod hash'iyle tekilleştirilmiş.

## Lisans notu

Her veri setinin lisansı farklıdır; eğitimde yalnızca izin verenleri kullan. CVEfixes verisi
CC BY 4.0 (atıf gerekir; `data/raw/CVEfixes/LICENSE.txt`), kodun lisansı ayrıca kontrol
edilmelidir. Sentetik şablonlar bu depoya aittir.
