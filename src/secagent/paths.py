"""Depo içi merkezi yollar. SECAGENT_ROOT ortam değişkeniyle değiştirilebilir
(paket editable değil, kurulu çalıştırılırsa kullanışlıdır)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("SECAGENT_ROOT") or Path(__file__).resolve().parents[2])
DATA = ROOT / "data"
SAMPLES = DATA / "samples"          # elle hazırlanmış örnekler (depoda)
RAW = DATA / "raw"                  # indirilen ham veri setleri (git dışı)
OUT = DATA / "out"                  # üretilen train/val/test.jsonl (git dışı)
CVEFIXES_DB = RAW / "CVEfixes" / "CVEfixes.db"
