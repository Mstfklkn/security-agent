"""CWE bildirmeyen tarayıcı kuralları için (araç, kural) -> CWE yedek tablosu.

Yalnızca anlamı belirsizlik bırakmayan kurallar eşlenir. Eşlenmeyen alarm
CWE'siz kalır ve eğitim hattında 'belirsiz' sayılır (uydurma etiket yok).
"""
from __future__ import annotations

RULE_CWE: dict[tuple[str, str], str] = {
    ("hadolint", "DL3002"): "CWE-250",   # son USER root
    ("hadolint", "DL3004"): "CWE-250",   # sudo kullanımı
    ("hadolint", "DL3064"): "CWE-798",   # ENV ile sır (gözlem: ENV DB_PASSWORD satırında tetiklendi)
    # trivy — Dockerfile
    ("trivy", "DS-0002"): "CWE-250",     # imaj kullanıcısı root
    ("trivy", "DS-0031"): "CWE-798",     # ENV içinde olası sır
    # trivy — AWS / Terraform
    ("trivy", "AWS-0107"): "CWE-284",    # güvenlik grubu girişi 0.0.0.0/0
    ("trivy", "AWS-0026"): "CWE-311",    # EBS şifrelenmemiş
    ("trivy", "AWS-0132"): "CWE-311",    # S3 müşteri yönetimli anahtarla şifrelenmemiş
    ("trivy", "AWS-0080"): "CWE-311",    # RDS depolama şifrelenmemiş
    ("trivy", "AWS-0086"): "CWE-668",    # S3 genel ACL engeli yok
    ("trivy", "AWS-0087"): "CWE-668",    # S3 genel politika engeli yok
    ("trivy", "AWS-0091"): "CWE-668",    # S3 genel ACL yok sayılmıyor
    ("trivy", "AWS-0092"): "CWE-668",    # S3 ACL herkese açık
    ("trivy", "AWS-0093"): "CWE-668",    # S3 genel kovayı kısıtlamıyor
    # trivy — Kubernetes
    ("trivy", "KSV-0017"): "CWE-250",    # privileged konteyner
    ("trivy", "KSV-0012"): "CWE-250",    # root olarak çalışabilir
    ("trivy", "KSV-0001"): "CWE-269",    # ayrıcalık yükseltmeye izin
    ("trivy", "KSV-0014"): "CWE-732",    # kök dosya sistemi yazılabilir
    ("trivy", "KSV-0009"): "CWE-668",    # hostNetwork
    ("trivy", "KSV-0006"): "CWE-250",    # docker.sock hostPath
    ("trivy", "KSV-0023"): "CWE-668",    # hostPath birimi
    ("trivy", "KSV-0121"): "CWE-668",    # kısıtlı hostPath yolu (ör. /)
    ("trivy", "KSV-0118"): "CWE-250",    # güvenlik bağlamı varsayılan/gevşek
}

# Sonucu yapılandırma politikasına bağlı olan (güvenilir kayıt defteri listesi gibi)
# kurallar sinyal değil gürültüdür; hem eğitimde hem çalışma anında elenir.
NOISE_RULES: frozenset[tuple[str, str]] = frozenset({
    ("trivy", "KSV-0125"),               # "güvenilir kayıt defteri" ortama bağlı
})

# Savunma raporunda gürültü sayılan (araç, ciddiyet) çiftleri. Hem eğitimde
# hem çalışma anında AYNI filtre uygulanır; dağılım kaymasın diye.
NOISE: frozenset[tuple[str, str]] = frozenset({
    ("hadolint", "info"), ("hadolint", "style"),
    ("trivy", "low"), ("trivy", "info"), ("trivy", "unknown"),
})


def fill_cwe(findings: list[dict]) -> list[dict]:
    """CWE'si boş bulgulara tablodan CWE ekler, gürültüyü eler (girdiyi değiştirmez)."""
    out = []
    for f in findings:
        if (f["tool"], (f.get("severity") or "").lower()) in NOISE:
            continue
        if (f["tool"], f.get("rule_id", "")) in NOISE_RULES:
            continue
        cwe = f.get("cwe") or RULE_CWE.get((f["tool"], f.get("rule_id", "")))
        out.append({**f, "cwe": cwe})
    return out
