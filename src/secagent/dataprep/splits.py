"""Sızıntısız train/val/test bölmesi: aynı repo (group) hep aynı bölmeye düşer."""
from __future__ import annotations

import hashlib

SPLITS = ("train", "val", "test")


def split_for(group: str, val_pct: int = 5, test_pct: int = 5) -> str:
    bucket = int(hashlib.sha256(group.encode("utf-8")).hexdigest(), 16) % 100
    if bucket < test_pct:
        return "test"
    if bucket < test_pct + val_pct:
        return "val"
    return "train"


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
