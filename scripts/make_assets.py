"""README görsellerini (assets/*.svg) üretir. Yalnızca standart kütüphane.

Sayılar data/out/data_card.json'dan ve data/raw/ dosya boyutlarından okunur; elle yazılmaz.
Kullanım: python scripts/make_assets.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"
CARD = ROOT / "data" / "out" / "data_card.json"
RAW = ROOT / "data" / "raw"

BG, PANEL, INK, MUTED = "#0f172a", "#1e293b", "#f1f5f9", "#94a3b8"
ACCENT, GREEN, AMBER, RED = "#38bdf8", "#34d399", "#fbbf24", "#f87171"
FONT = "font-family=\"-apple-system,Segoe UI,Helvetica,Arial,sans-serif\""


def svg(width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">'
        f'<rect width="{width}" height="{height}" rx="14" fill="{BG}"/>{body}</svg>\n'
    )


def text(x: float, y: float, s: str, size: int = 14, fill: str = INK,
         weight: str = "400", anchor: str = "start") -> str:
    return (
        f'<text x="{x}" y="{y}" {FONT} font-size="{size}" fill="{fill}" '
        f'font-weight="{weight}" text-anchor="{anchor}">{escape(s)}</text>'
    )


def human(nbytes: float) -> str:
    gb = nbytes / 1024**3
    if gb >= 1:
        return f"{gb:.1f} GB"
    mb = nbytes / 1024**2
    return f"{mb:.0f} MB" if mb >= 10 else f"{mb:.1f} MB"


def dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def hero() -> str:
    body = (
        f'<circle cx="95" cy="110" r="44" fill="none" stroke="{ACCENT}" stroke-width="5"/>'
        f'<path d="M95 78 L119 88 V112 C119 128 108 138 95 143 C82 138 71 128 71 112 V88 Z" '
        f'fill="{PANEL}" stroke="{GREEN}" stroke-width="4"/>'
        f'<path d="M84 111 L92 120 L108 100" fill="none" stroke="{GREEN}" stroke-width="5" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        + text(170, 100, "security-agent", 46, INK, "700")
        + text(172, 134, "Savunma amaçlı güvenlik denetim ajanı", 20, ACCENT, "500")
        + text(172, 164, "Qwen3-Coder-30B-A3B + LoRA · Claude içinde MCP aracı olarak", 15, MUTED)
        + text(172, 190, "tarayıcılar bulur → model yanlış alarmı ayıklar ve mantık hatasını yakalar → rapor", 15, MUTED)
    )
    return svg(900, 230, body)


def pipeline() -> str:
    boxes = [
        ("1 · Tarayıcılar", "semgrep · bandit · gitleaks\ntrivy · osv-scanner · …", ACCENT),
        ("2 · Parçalama", "değişen fonksiyon +\no fonksiyona düşen alarmlar", AMBER),
        ("3 · Model (LoRA)", "yanlış alarmı ayıkla\nmantık hatasını bul, düzelt", GREEN),
        ("4 · Rapor", "CWE · önem · satır\nCVSS/ref: mappings.py", RED),
    ]
    body, x, w, gap = "", 30, 190, 38
    for i, (title, sub, color) in enumerate(boxes):
        bx = x + i * (w + gap)
        body += f'<rect x="{bx}" y="50" width="{w}" height="120" rx="12" fill="{PANEL}" stroke="{color}" stroke-width="2"/>'
        body += text(bx + w / 2, 82, title, 16, color, "700", "middle")
        for j, line in enumerate(sub.split("\n")):
            body += text(bx + w / 2, 112 + j * 20, line, 13, INK, "400", "middle")
        if i < len(boxes) - 1:
            ax = bx + w + 4
            body += f'<path d="M{ax} 110 H{ax + gap - 12}" stroke="{MUTED}" stroke-width="2.5"/>'
            body += f'<path d="M{ax + gap - 18} 103 L{ax + gap - 8} 110 L{ax + gap - 18} 117" fill="none" stroke="{MUTED}" stroke-width="2.5"/>'
    body += text(450, 25, "Akış kodla sabit; model karar vermez, yalnızca yargı üretir", 15, MUTED, "500", "middle")
    body += text(450, 205, "Çıktı Claude'a (VS Code / Claude Code) MCP aracı olarak döner · hiçbir exploit üretilmez", 13, MUTED, "400", "middle")
    return svg(940, 225, body)


def bar_chart(title: str, subtitle: str, rows: list[tuple[str, float, str]],
              scale: str = "linear", color: str = ACCENT) -> str:
    """Yatay çubuk grafik. rows: (etiket, değer, değer metni)."""
    label_w, bar_w, row_h, top = 130, 560, 30, 70
    vals = [max(v, 1e-9) for _, v, _ in rows]
    hi = max(vals)
    body = text(24, 32, title, 20, INK, "700") + text(24, 54, subtitle, 13, MUTED)
    for i, (label, value, shown) in enumerate(rows):
        y = top + i * row_h
        frac = (math.log10(max(value, 1)) / math.log10(max(hi, 10))) if scale == "log" else value / hi
        frac = max(frac, 0.015)
        body += text(label_w + 14, y + 17, label, 14, INK, "500", "end")
        body += f'<rect x="{label_w + 24}" y="{y + 2}" width="{bar_w * frac:.1f}" height="20" rx="4" fill="{color}"/>'
        body += text(label_w + 24 + bar_w * frac + 8, y + 17, shown, 13, MUTED)
    return svg(label_w + bar_w + 200, top + len(rows) * row_h + 20, body)


def raw_sizes() -> str:
    names = ["CVEfixes", "DiverseVul", "PrimeVul", "Vul4J"]
    rows = [(n, float(dir_size(RAW / n)), human(dir_size(RAW / n))) for n in names]
    rows.sort(key=lambda r: -r[1])
    total = sum(r[1] for r in rows)
    return bar_chart("Ham veri setleri (indirilen)", f"Toplam {human(total)} · logaritmik ölçek (CVEfixes diğerlerini ezer)",
                     rows, scale="log", color=AMBER)


def split_sizes(card: dict) -> str:
    items = [("train", "train.jsonl"), ("val", "val.jsonl"), ("test", "test.jsonl"),
             ("test_synthetic", "test_synthetic.jsonl")]
    rows = []
    for split, fname in items:
        n = card["splits"].get(split, {}).get("examples")
        size = (ROOT / "data" / "out" / fname).stat().st_size
        shown = f"{human(size)}" + (f" · {n:,} örnek".replace(",", ".") if n else "")
        rows.append((split, float(n or 0) or size / 1000, shown))
    return bar_chart("Üretilen eğitim seti", "data/out/ · örnek sayısı (çubuk) ve dosya boyutu", rows, color=GREEN)


def languages(card: dict) -> str:
    langs = card["splits"]["train"]["languages"]
    rows = [(k, float(v), f"{v:,}".replace(",", ".")) for k, v in sorted(langs.items(), key=lambda kv: -kv[1])]
    return bar_chart("Train dil dağılımı", f"{len(rows)} dil / teknoloji · toplam "
                     f"{card['splits']['train']['examples']:,}".replace(",", ".") + " örnek", rows, color=ACCENT)


def kinds(card: dict) -> str:
    train = card["splits"]["train"]["kinds"]
    total = sum(train.values())
    segs = [("gerçek", GREEN), ("temiz", ACCENT), ("yanlış_alarm", AMBER)]
    body = text(24, 32, "Örnek türleri (train)", 20, INK, "700")
    body += text(24, 54, "gerçek zafiyet · temiz (düzeltilmiş) kod · yanlış alarm", 13, MUTED)
    x, width = 24.0, 700.0
    for name, color in segs:
        w = width * train[name] / total
        body += f'<rect x="{x:.1f}" y="76" width="{max(w, 3):.1f}" height="36" fill="{color}"/>'
        x += w
    lx = 24
    for name, color in segs:
        pct = 100 * train[name] / total
        body += f'<rect x="{lx}" y="132" width="14" height="14" rx="3" fill="{color}"/>'
        body += text(lx + 22, 144, f"{name}  {train[name]:,}  (%{pct:.1f})".replace(",", "."), 13, INK)
        lx += 235
    body += text(24, 178, f"Mantık hatası örneği: {card['splits']['train']['logic_examples']} (IDOR, yetkilendirme, kimlik doğrulama, deserialization, CSRF)", 13, MUTED)
    return svg(750, 200, body)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    card = json.loads(CARD.read_text(encoding="utf-8"))
    files = {
        "hero.svg": hero(),
        "pipeline.svg": pipeline(),
        "raw-sizes.svg": raw_sizes(),
        "dataset-splits.svg": split_sizes(card),
        "languages.svg": languages(card),
        "kinds.svg": kinds(card),
    }
    for name, content in files.items():
        (OUT / name).write_text(content, encoding="utf-8")
        print("yazıldı:", OUT / name)


if __name__ == "__main__":
    main()
