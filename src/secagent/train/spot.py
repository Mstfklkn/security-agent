"""AWS Spot kesinti uyarısı izleyicisi (IMDSv2; kesintiden ~2 dk önce bildirim gelir)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Callable

IMDS = "http://169.254.169.254"


def imds_spot_action(timeout: float = 1.0, base: str = IMDS) -> dict | None:
    """Kesinti bildirimi varsa {'action':..., 'time':...}; yoksa/ulaşılamıyorsa None."""
    try:
        tok_req = urllib.request.Request(f"{base}/latest/api/token", method="PUT",
                                         headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(tok_req, timeout=timeout) as r:
            token = r.read().decode()
        req = urllib.request.Request(f"{base}/latest/meta-data/spot/instance-action",
                                     headers={"X-aws-ec2-metadata-token": token})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None                                   # 404 = bildirim yok; ağ hatası = bilinmiyor


class SpotWatcher(threading.Thread):
    def __init__(self, fetch: Callable[[], dict | None] = imds_spot_action, poll_seconds: float = 5.0):
        super().__init__(daemon=True, name="spot-watcher")
        self._fetch, self._poll = fetch, poll_seconds
        self._stop_evt = threading.Event()
        self.notice = threading.Event()
        self.info: dict | None = None

    def run(self) -> None:
        while not self._stop_evt.is_set():
            try:
                info = self._fetch()
            except Exception:                         # izleyici eğitimi asla düşürmemeli
                info = None
            if info:
                self.info = info
                self.notice.set()
                return
            self._stop_evt.wait(self._poll)

    def stop(self) -> None:
        self._stop_evt.set()
