import json
import threading

import pytest
import yaml
from pydantic import ValidationError

from secagent.train import resume, s3sync, spot
from secagent.train.config import TrainConfig, load_config, parse_overrides


# ---- config -----------------------------------------------------------------
def test_config_defaults_and_validation(tmp_path):
    cfg = TrainConfig(train_file="t.jsonl")
    assert cfg.model_id == "Qwen/Qwen3-Coder-30B-A3B-Instruct"
    assert cfg.lora.target_modules == ["q_proj", "k_proj", "v_proj", "o_proj"]     # yalnız dikkat
    assert "router" not in " ".join(cfg.lora.target_modules) and "gate" not in " ".join(cfg.lora.target_modules)
    assert cfg.max_len == 4096 and cfg.bf16 is True and cfg.s3.uri is None
    with pytest.raises(ValidationError):
        TrainConfig(train_file="t", learning_rate=0)
    with pytest.raises(ValidationError):
        TrainConfig(train_file="t", bogus_key=1)                                    # yazım hatası yakalanır
    with pytest.raises(ValidationError):
        TrainConfig(train_file="t", s3={"uri": "http://x"})
    with pytest.raises(ValidationError):
        TrainConfig(train_file="t", lora={"target_modules": []})


def test_load_config_with_overrides(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"train_file": "a.jsonl", "epochs": 1, "lora": {"r": 8}}))
    cfg = load_config(p, parse_overrides(["epochs=3", "lora.alpha=64", "s3.uri=s3://my-bucket/run1", "max_steps=5"]))
    assert (cfg.epochs, cfg.lora.r, cfg.lora.alpha, cfg.s3.uri, cfg.max_steps) == (3, 8, 64, "s3://my-bucket/run1", 5)
    with pytest.raises(ValueError):
        parse_overrides(["bozuk"])


def test_repo_config_file_is_valid():
    from pathlib import Path
    cfg = load_config(Path(__file__).resolve().parent.parent / "train" / "config.yaml")
    assert cfg.model_id.startswith("Qwen/Qwen3-Coder-30B-A3B")


# ---- checkpoint bulma --------------------------------------------------------
def _ckpt(root, step, complete=True, files=resume.REQUIRED):
    d = root / f"checkpoint-{step}"
    d.mkdir(parents=True)
    for f in files:
        (d / f).write_text("x")
    if complete:
        (d / resume.MARKER).write_text(str(step))
    return d


def test_latest_checkpoint_numeric_order_and_completeness(tmp_path):
    _ckpt(tmp_path, 100)
    _ckpt(tmp_path, 900)
    _ckpt(tmp_path, 1000)
    _ckpt(tmp_path, 1100, complete=False)                  # yarım senkronlanmış: atlanır
    _ckpt(tmp_path, 1200, files=("trainer_state.json",))   # adaptör yok: atlanır
    _ckpt(tmp_path, 1300, files=tuple(f for f in resume.REQUIRED if f != "optimizer.pt"))  # optimizer yok: atlanır
    assert resume.latest_checkpoint(tmp_path).name == "checkpoint-1000"      # 900 < 1000 (sayısal)
    assert resume.latest_checkpoint(tmp_path / "yok") is None
    assert resume.latest_checkpoint(tmp_path, require_marker=False).name == "checkpoint-1100"


# ---- S3 eşitleme (aws cli'yi taklit eder) ------------------------------------
class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)


def test_s3_uri_validation():
    for bad in ("http://b/x", "s3://", "b/x", "s3://b;rm -rf /", "s3://b/ x"):
        with pytest.raises(ValueError):
            s3sync.S3Sync(bad)
    s3sync.S3Sync("s3://bucket-1/run_1/a")


def test_s3_push_uploads_marker_last_and_pull_is_plain_sync(tmp_path):
    rec = Rec()
    s = s3sync.S3Sync("s3://my-bucket/r", runner=rec)
    s.push(tmp_path)
    assert len(rec.calls) == 2
    first, second = rec.calls
    assert first[:3] == ["aws", "s3", "sync"] and "--exclude" in first and resume.MARKER in " ".join(first)
    assert "--include" in second and resume.MARKER in " ".join(second)           # işaret en son
    rec.calls.clear()
    s.pull(tmp_path)
    assert rec.calls == [["aws", "s3", "sync", "s3://my-bucket/r", str(tmp_path), "--only-show-errors"]]
    assert "--delete" not in " ".join(first + second)                            # uzaktakini asla silme


def test_s3_disabled_is_noop(tmp_path):
    rec = Rec()
    s = s3sync.S3Sync(None, runner=rec)
    s.push(tmp_path), s.pull(tmp_path)
    assert rec.calls == [] and s.enabled is False


# ---- spot izleyici -----------------------------------------------------------
def test_spot_watcher_sets_event_on_notice():
    seq = iter([None, None, {"action": "terminate", "time": "2026-10-16T00:00:00Z"}])
    w = spot.SpotWatcher(fetch=lambda: next(seq), poll_seconds=0.01)
    w.start()
    assert w.notice.wait(timeout=5)
    assert w.info["action"] == "terminate"


def test_spot_watcher_survives_fetch_errors_and_can_stop():
    n = {"i": 0}

    def flaky():
        n["i"] += 1
        raise OSError("ağ")

    w = spot.SpotWatcher(fetch=flaky, poll_seconds=0.01)
    w.start()
    threading.Event().wait(0.1)
    assert not w.notice.is_set() and n["i"] > 1
    w.stop()
    w.join(timeout=2)
    assert not w.is_alive()


def test_imds_fetch_returns_none_when_unreachable():
    assert spot.imds_spot_action(timeout=0.05, base="http://127.0.0.1:9") is None


# --- İNCELEME DÜZELTMELERİ ---------------------------------------------------
def test_quantization_default_is_bf16_lora_because_moe_experts_cannot_be_4bit():
    assert TrainConfig(train_file="t").quantization == "none"
    from pathlib import Path
    cfg = load_config(Path(__file__).resolve().parent.parent / "train" / "config.yaml")
    assert cfg.quantization == "none" and cfg.eval_max_examples <= 200


def test_s3_uri_regex_is_defined_once():
    from secagent.train import config
    assert s3sync.URI is config.S3_URI


def test_s3_push_retries_transient_failures_then_succeeds(tmp_path):
    import subprocess
    state = {"n": 0}

    def flaky(cmd, **kw):
        state["n"] += 1
        if state["n"] <= 2:
            raise subprocess.CalledProcessError(1, cmd)

    sl = []
    s = s3sync.S3Sync("s3://my-bucket/r", runner=flaky, sleep=sl.append)
    s.push(tmp_path, retries=3)
    assert state["n"] == 4 and len(sl) == 2 and sl[0] < sl[1]            # geri çekilme artar


def test_s3_push_raises_after_retries_when_strict_and_callback_swallows(tmp_path):
    import subprocess

    def boom(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd)

    s = s3sync.S3Sync("s3://my-bucket/r", runner=boom, sleep=lambda _: None)
    with pytest.raises(subprocess.CalledProcessError):
        s.push(tmp_path, retries=2)
    from secagent.train.callbacks import S3Callback
    cb = S3Callback(s)

    class Args:
        output_dir = str(tmp_path)
    cb.on_save(Args(), None, None)                                        # ara kayıt: eğitimi düşürmez
    assert cb.failures == 1


def test_spot_callback_cancels_evaluation_when_notice_arrived():
    from secagent.train.callbacks import SpotCallback

    class Ctl:
        should_save = should_training_stop = False
        should_evaluate = True

    w = spot.SpotWatcher(fetch=lambda: None)
    cb = SpotCallback(w)
    c = Ctl()
    assert cb.on_step_end(None, None, c) is c and c.should_evaluate is True     # bildirim yok: dokunma
    w.notice.set()
    cb.on_step_end(None, None, c)
    assert c.should_save and c.should_training_stop and c.should_evaluate is False
