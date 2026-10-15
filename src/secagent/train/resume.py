"""Checkpoint bulma. Yarım yazılmış/yarım senkronlanmış checkpoint'ten ASLA devam edilmez."""
from __future__ import annotations

import re
from pathlib import Path

MARKER = "COMPLETE"                       # checkpoint tam kaydedilip (ve senkronlanıp) yazılır
_STEP = re.compile(r"^checkpoint-(\d+)$")
# Devam için gerekenler: optimizer/scheduler eksikse Trainer sessizce SIFIRDAN başlatır (LR
# takvimi bozulur), bu yüzden eksik checkpoint'ten devam EDİLMEZ.
REQUIRED = ("trainer_state.json", "adapter_model.safetensors", "optimizer.pt", "scheduler.pt")


def latest_checkpoint(output_dir: str | Path, require_marker: bool = True) -> Path | None:
    root = Path(output_dir)
    if not root.is_dir():
        return None
    best: tuple[int, Path] | None = None
    for d in root.iterdir():
        m = _STEP.match(d.name)
        if not (m and d.is_dir()):
            continue
        if not all((d / f).is_file() for f in REQUIRED):
            continue
        if require_marker and not (d / MARKER).is_file():
            continue
        step = int(m.group(1))
        if best is None or step > best[0]:
            best = (step, d)
    return best[1] if best else None
