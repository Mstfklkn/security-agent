"""Trainer geri çağırmaları. Sıra önemlidir: önce COMPLETE işareti, sonra S3 itme."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from transformers import TrainerCallback

from .resume import MARKER
from .s3sync import S3Sync
from .spot import SpotWatcher


class MarkerCallback(TrainerCallback):
    """Checkpoint tam kaydedildikten sonra COMPLETE işareti yazar."""

    def on_save(self, args, state, control, **kwargs):
        ckpt = Path(args.output_dir) / f"checkpoint-{state.global_step}"
        if ckpt.is_dir():
            (ckpt / MARKER).write_text(str(state.global_step), encoding="utf-8")


class S3Callback(TrainerCallback):
    """Ara kayıtta S3 hatası eğitimi DÜŞÜRMEZ (yeniden dener, sonra uyarır ve sürdürür);
    kesin garanti son itmedir (run.py, hata fırlatır)."""

    def __init__(self, s3: S3Sync):
        self.s3 = s3
        self.failures = 0

    def on_save(self, args, state, control, **kwargs):
        try:
            self.s3.push(args.output_dir, retries=3)
        except (subprocess.CalledProcessError, OSError) as e:
            self.failures += 1
            print(f"[uyarı] S3 itme başarısız (eğitim sürüyor): {e}", file=sys.stderr, flush=True)


class SpotCallback(TrainerCallback):
    """Spot kesinti bildirimi gelince: bu adımda kaydet ve eğitimi durdur."""

    def __init__(self, watcher: SpotWatcher):
        self.watcher = watcher

    def on_step_end(self, args, state, control, **kwargs):
        if self.watcher.notice.is_set():
            control.should_save = True
            control.should_training_stop = True
            control.should_evaluate = False        # değerlendirme 2 dk'lık uyarıdan uzun sürebilir
        return control
