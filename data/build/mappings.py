"""
CWE -> referans linkleri ve CWE -> varsayılan CVSS eşlemeleri.

Neden burada: modelin referans URL'si veya CVE uydurmasını İSTEMİYORUZ.
Uydurma referans, güvenlik aracında en tehlikeli hatalardan biridir.
Bu yüzden referanslar eğitim verisinde koddan türetilmez; CWE numarasından
deterministik olarak üretilir. CVE linki yalnızca somut kaynağı olan
(ör. bağımlılık taraması) bulgularda, gerçek CVE kimliğiyle eklenir.

CVSS: Her CWE için TİPİK bir vektör/skor veriyoruz. Bu yalnızca kaynak
veri setinde CVSS bulunmadığında, makul bir varsayılan olarak kullanılır
ve örnekte "cvss_source": "default" olarak işaretlenir (make_examples.py).
Gerçek CVSS varsa o kullanılır.
"""
from __future__ import annotations

# --- Sabit, güvenilir referans kaynakları -------------------------------

def cwe_url(cwe: str) -> str:
    num = cwe.split("-")[1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


# CWE -> OWASP / ek güvenilir açıklama bağlantıları
_OWASP: dict[str, list[str]] = {
    "CWE-89":  ["https://owasp.org/www-community/attacks/SQL_Injection"],
    "CWE-79":  ["https://owasp.org/www-community/attacks/xss/"],
    "CWE-78":  ["https://owasp.org/www-community/attacks/Command_Injection"],
    "CWE-22":  ["https://owasp.org/www-community/attacks/Path_Traversal"],
    "CWE-352": ["https://owasp.org/www-community/attacks/csrf"],
    "CWE-918": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    "CWE-502": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    "CWE-611": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    "CWE-327": ["https://owasp.org/www-community/vulnerabilities/Using_a_broken_or_risky_cryptographic_algorithm"],
    "CWE-798": ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
    "CWE-732": ["https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File"],
    "CWE-862": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    "CWE-639": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],  # IDOR
}


def references_for(cwe: str, cve_id: str | None = None) -> list[str]:
    """Bir bulgu için güvenli referans listesi üretir.
    cve_id yalnızca gerçekten bilinen bir CVE varsa geçilmelidir."""
    refs = [cwe_url(cwe)]
    refs += _OWASP.get(cwe, [])
    if cve_id:
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    return refs


# --- CWE -> tipik ciddiyet ve CVSS varsayılanı --------------------------
# (severity, cvss_score, cvss_vector)
_DEFAULTS: dict[str, tuple[str, float, str]] = {
    "CWE-89":  ("high",     8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-78":  ("critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-79":  ("medium",   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CWE-22":  ("high",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-352": ("medium",   6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "CWE-918": ("high",     8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "CWE-502": ("critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-611": ("high",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-327": ("medium",   5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-798": ("high",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-732": ("medium",   5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-862": ("high",     8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "CWE-639": ("high",     8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
}


def defaults_for(cwe: str) -> tuple[str, float | None, str | None]:
    """(severity, cvss_score, cvss_vector) döndürür.
    Bilinmeyen CWE için ('medium', None, None) — CVSS uydurulmaz."""
    if cwe in _DEFAULTS:
        return _DEFAULTS[cwe]
    return ("medium", None, None)


# --- CWE adları (şablon başlıklar için) ---------------------------------
CWE_NAMES: dict[str, str] = {
    "CWE-20": "Yetersiz girdi doğrulama",
    "CWE-22": "Yol gezinmesi (path traversal)",
    "CWE-77": "Komut enjeksiyonu",
    "CWE-78": "OS komut enjeksiyonu",
    "CWE-79": "Cross-site scripting (XSS)",
    "CWE-89": "SQL enjeksiyonu",
    "CWE-94": "Kod enjeksiyonu",
    "CWE-119": "Bellek tamponu sınırları dışında işlem",
    "CWE-125": "Sınır dışı okuma",
    "CWE-190": "Tamsayı taşması",
    "CWE-200": "Hassas bilgi ifşası",
    "CWE-252": "Denetlenmeyen dönüş değeri",
    "CWE-269": "Hatalı ayrıcalık yönetimi",
    "CWE-287": "Hatalı kimlik doğrulama",
    "CWE-295": "Hatalı sertifika doğrulama",
    "CWE-327": "Zayıf veya riskli kriptografi",
    "CWE-352": "Cross-site request forgery (CSRF)",
    "CWE-400": "Kontrolsüz kaynak tüketimi",
    "CWE-416": "Use-after-free",
    "CWE-434": "Güvensiz dosya yükleme",
    "CWE-476": "NULL işaretçi başvurusu",
    "CWE-502": "Güvenilmeyen verinin deserialization'ı",
    "CWE-601": "Açık yönlendirme",
    "CWE-611": "XML harici varlık (XXE) işleme",
    "CWE-639": "Kullanıcı denetimli anahtarla yetkilendirme atlatma (IDOR)",
    "CWE-668": "Kaynağın yanlış kapsamda ifşası",
    "CWE-732": "Hatalı izin ataması",
    "CWE-787": "Sınır dışı yazma",
    "CWE-798": "Koda gömülü kimlik bilgisi",
    "CWE-862": "Eksik yetkilendirme",
    "CWE-918": "Sunucu taraflı istek sahteciliği (SSRF)",
}


def title_for(cwe: str) -> str:
    return CWE_NAMES.get(cwe, f"{cwe} zafiyeti")
