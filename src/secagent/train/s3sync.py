"""S3 eşitleme (aws cli). Kesinti kaybını önlemek için her checkpoint kaydında itilir.

- pull: eğitim başında (kaldığı yerden devam için).
- push: önce COMPLETE işaretleri HARİÇ her şey, sonra yalnızca işaretler. Böylece S3'te
  işaretli checkpoint her zaman tamdır (yarım yüklemede işaret hiç gitmemiş olur).
- `--delete` ASLA kullanılmaz: pull başarısız olsa bile uzaktaki checkpoint'ler silinmez.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable

from .config import S3_URI as URI
from .resume import MARKER


class S3Sync:
    def __init__(self, uri: str | None, runner: Callable = subprocess.run,
                 sleep: Callable[[float], None] = time.sleep):
        if uri is not None and not URI.match(uri):
            raise ValueError(f"geçersiz S3 URI: {uri!r}")
        self.uri = uri.rstrip("/") if uri else None
        self._run, self._sleep = runner, sleep

    @property
    def enabled(self) -> bool:
        return self.uri is not None

    def _sync(self, *args: str, retries: int = 1) -> None:
        """En çok `retries` deneme; denemeler arasında 2, 4, 8... sn bekler. Hepsi başarısızsa
        son hatayı fırlatır (çağıran karar verir: ara kayıtta yut, son itmede düşür)."""
        for attempt in range(1, retries + 1):
            try:
                self._run(["aws", "s3", "sync", *args, "--only-show-errors"], check=True)
                return
            except (subprocess.CalledProcessError, OSError):
                if attempt == retries:
                    raise
                self._sleep(2 * 2 ** (attempt - 1))

    def pull(self, local_dir: str | Path, retries: int = 3) -> None:
        if self.enabled:
            Path(local_dir).mkdir(parents=True, exist_ok=True)
            self._sync(self.uri, str(local_dir), retries=retries)

    def push(self, local_dir: str | Path, retries: int = 1) -> None:
        if not self.enabled:
            return
        local = str(local_dir)
        self._sync(local, self.uri, "--exclude", f"*/{MARKER}", retries=retries)
        self._sync(local, self.uri, "--exclude", "*", "--include", f"*/{MARKER}", retries=retries)
