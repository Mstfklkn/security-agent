"""Okuyucuların ortak yardımcıları: diff çözümleme, şablon düzeltme metni."""
from __future__ import annotations

import difflib
import re
from typing import Iterator

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
MAX_FIX_DIFF_CHARS = 1500


def removed_lines(diff: str) -> list[int]:
    """Unified diff'teki silinen satırların ESKİ dosyadaki numaralarını verir."""
    result: list[int] = []
    old_no = 0
    for raw in diff.splitlines():
        m = _HUNK.match(raw)
        if m:
            old_no = int(m.group(1))
            continue
        if raw.startswith("---") or raw.startswith("+++") or old_no == 0:
            continue
        if raw.startswith("-"):
            result.append(old_no)
            old_no += 1
        elif raw.startswith("+"):
            continue
        else:
            old_no += 1
    return result


def first_changed_line(diff: str, code: str) -> int | None:
    """Silinen ilk anlamlı (boş olmayan) satırın numarası; yoksa None."""
    lines = code.splitlines()
    for no in removed_lines(diff):
        if 1 <= no <= len(lines) and lines[no - 1].strip():
            return no
    return None


def line_text(code: str, line: int) -> str:
    return code.splitlines()[line - 1].strip()


def template_fix(cwe_title: str, diff: str) -> str:
    """Düzeltme metni: gerçek yama (diff) + sabit açıklama. Uydurma içermez."""
    patch = diff.strip()
    if len(patch) > MAX_FIX_DIFF_CHARS:
        patch = patch[:MAX_FIX_DIFF_CHARS] + "\n... (kısaltıldı)"
    return (
        f"{cwe_title} zafiyetini gideren upstream düzeltmesi aşağıdadır; "
        f"benzer bir değişiklik uygula:\n{patch}"
    )


def enclosing_function(methods: Iterator[tuple[str, int, int]], line: int) -> str | None:
    """(ad, başlangıç, bitiş) üçlülerinden `line`'ı kapsayan en dar fonksiyonu seçer."""
    best: tuple[str, int] | None = None
    for name, start, end in methods:
        if start <= line <= end:
            span = end - start
            if best is None or span < best[1]:
                best = (name, span)
    return best[0] if best else None


# --- Kaynaklar arası ortak yardımcılar ----------------------------------

MAX_FUNC_CHARS = 6_000
_GITWEB = re.compile(r"[?;&]p=([^;&]+)")
_KEYWORDS = frozenset({"if", "for", "while", "switch", "return", "sizeof", "defined",
                       "__attribute__", "__declspec", "else", "do", "case"})
_CALL = re.compile(r"([A-Za-z_]\w*)\s*\(")


_KERNEL = re.compile(r"linux-(\d[\d.]*|stable|next|fs|fbdev|mips|rt|media|mm|pm|wireless|net|nfs|sound|usb|scsi|block|crypto)")


def group_key(source: str | None) -> str:
    """Depoyu tanıtan ortak bölme anahtarı: küçük harfli DEPO ADI (konak/sahip yok).

    Aynı depo farklı kaynaklarda farklı URL ile geçer (GitHub, gitweb, cgit, yalnızca proje
    adı). Fork'lar da aynı kodu paylaşır. Fazla gruplamak güvenlidir, eksik gruplamak
    val/test sızıntısına yol açar. Commit URL'leri '/commit' öncesinden kesilir; Linux
    çekirdeğinin ağaçları (linux-2.6, linux-stable, ...) tek 'linux' grubudur."""
    text = (source or "").strip()
    if not text:
        return "unknown"
    m = _GITWEB.search(text)
    if m:
        name = m.group(1)
    else:
        path = re.sub(r"[?#].*$", "", text).rstrip("/")
        name = re.split(r"/commit(?:/|$)", path, maxsplit=1)[0]
    name = name.rsplit("/", 1)[-1].strip().lower()
    name = re.sub(r"\.git$", "", name)
    if _KERNEL.fullmatch(name):
        name = "linux"
    return name or "unknown"


def first_diff_line(old: str, new: str) -> int | None:
    """`old` içinde ANLAMLI değişimin başladığı ilk (boş olmayan) satır, 1 tabanlı.

    Karşılaştırma girinti/uç boşluklarını yok sayar (yalnızca yeniden girintilenen satırlar
    değişim sayılmaz). Silinen/değişen satır varsa o; yalnızca ekleme varsa (örn. eksik sınır
    kontrolü) ekleme noktasındaki satır. Fark yoksa None."""
    raw = old.splitlines()
    a = [x.strip() for x in raw]
    b = [x.strip() for x in new.splitlines()]
    for tag, i1, _i2, _j1, _j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if not raw:
            return None
        start = i1 if tag in ("replace", "delete") else min(i1, len(raw) - 1)
        for idx in range(start, len(raw)):
            if raw[idx].strip():
                return idx + 1
        return None
    return None


def c_function_name(code: str) -> str | None:
    """C/C++ fonksiyon adı (başlıktaki ilk 'ad(' kalıbı). Emin değilse None."""
    if "{" not in code:
        return None
    for m in _CALL.finditer(code.split("{", 1)[0]):
        if m.group(1) not in _KEYWORDS:
            return m.group(1)
    return None


def unified_change(old: str, new: str) -> str:
    """İki sürüm arasındaki birleşik fark (yama metni)."""
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        "önce", "sonra", n=2))
