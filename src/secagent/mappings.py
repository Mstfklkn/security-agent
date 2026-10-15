"""
CWE -> referans linkleri ve CWE -> varsayılan CVSS eşlemeleri.

Neden burada: modelin referans URL'si veya CVE uydurmasını İSTEMİYORUZ.
Uydurma referans, güvenlik aracında en tehlikeli hatalardan biridir.
Bu yüzden referanslar eğitim verisinde koddan türetilmez; CWE numarasından
deterministik olarak üretilir. CVE linki yalnızca somut kaynağı olan
(ör. bağımlılık taraması) bulgularda, gerçek CVE kimliğiyle eklenir.

CVSS: Her CWE için TİPİK bir vektör/skor veriyoruz. Bu yalnızca kaynak
veri setinde CVSS bulunmadığında, makul bir varsayılan olarak kullanılır
(dataprep/build.py). Gerçek CVSS (CVEfixes/NVD) varsa her zaman o kullanılır.
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


# --- İlgili CWE aileleri -------------------------------------------------
# Tarayıcılar çoğu zaman yamanın CWE'sine yakın ama farklı bir CWE bildirir
# (ör. CWE-119 yerine CWE-120). Aynı ailedeki CWE'ler "eşleşen" sayılır.
_FAMILIES: tuple[frozenset[str], ...] = tuple(frozenset(f"CWE-{n}" for n in g) for g in (
    (119, 120, 121, 122, 125, 126, 127, 787, 788, 805, 823),   # bellek sınırları
    (89, 564, 943),                                            # SQL/sorgu enjeksiyonu
    (77, 78, 88, 94, 95, 917),                                 # komut/kod enjeksiyonu
    (22, 23, 36, 73),                                          # yol gezinmesi
    (79, 80, 83, 87),                                          # XSS
    (250, 266, 268, 269, 272, 273, 284, 732),                  # ayrıcalık/erişim
    (287, 288, 290, 306, 862, 863, 639, 285),                  # kimlik/yetki
    (327, 328, 326, 916, 759, 760),                            # zayıf kripto/hash
    (798, 259, 321, 547, 256, 312, 522),                       # gömülü sır/kimlik bilgisi
    (295, 297, 299),                                           # sertifika doğrulama
    (416, 415, 476, 401, 772),                                 # bellek yaşam döngüsü
    (190, 191, 681, 369),                                      # sayısal hatalar
    (502, 915),                                                # deserialization
    (200, 209, 532, 497),                                      # bilgi ifşası
    (311, 312, 313, 315, 316, 319),                            # şifrelemesiz saklama/iletim
    (668, 406, 200),                                           # kaynağın yanlış kapsamda ifşası
    (250, 668),                                                # konteynerden ana makineye kaçış yüzeyi
))


def cwe_related(a: str | None, b: str | None) -> bool:
    """Aynı CWE veya aynı aile."""
    if not a or not b:
        return False
    return a == b or any(a in fam and b in fam for fam in _FAMILIES)


# --- Mantık/yetkilendirme hataları ---------------------------------------
# Projenin başlık becerisi: tarayıcıların çoğunlukla KAÇIRDIĞI sınıf.
LOGIC_CWES: frozenset[str] = frozenset({
    "CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285",   # IDOR / yetkilendirme
    "CWE-287", "CWE-306",                                    # kimlik doğrulama
    "CWE-502", "CWE-915",                                    # deserialization / toplu atama
    "CWE-352",                                               # CSRF
})


def is_logic(cwe: str | None) -> bool:
    return cwe in LOGIC_CWES


# --- Otomatik "yanlış alarm" etiketinin YASAK olduğu aileler --------------
# "Yamadan sonra aynı CWE'de alarm kalıyor" kuralı zayıf denetimlidir. Enjeksiyon, kod
# çalıştırma, deserialization ve gömülü sır gibi sınıflarda modele "bu alarmı yoksay"
# öğretmek en pahalı hatadır (kritik açığı kaçırmak); bu yüzden orada otomatik FP etiketi
# üretilmez. Elle seçilmiş (sentetik) istisnalar bu kuralın dışındadır.
_RISKY_DISMISSAL_CORE = ("CWE-78", "CWE-89", "CWE-94", "CWE-502", "CWE-798")


def is_risky_dismissal(cwe: str | None) -> bool:
    return any(cwe_related(cwe, core) for core in _RISKY_DISMISSAL_CORE)
