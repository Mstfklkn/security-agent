"""Eğitim yolunun CPU duman testi: gerçek tokenizer + küçük rastgele Qwen3Moe modeli.
Gerçek 30B model GEREKMEZ; kod yolunun tamamı (maskeleme, LoRA hedefleri, checkpoint,
devam, spot kesintisi, S3 itme, maliyet tahmini) burada doğrulanır."""
import json
import pathlib
import threading

import pytest

torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")
pytest.importorskip("peft")

from secagent.schema import Example, ExampleInput, ExampleOutput, Finding  # noqa: E402
from secagent.train import data, model as modelmod, resume, run, s3sync, spot  # noqa: E402
from secagent.train.config import TrainConfig  # noqa: E402


def tiny_model():
    cfg = transformers.Qwen3MoeConfig(
        vocab_size=151936, hidden_size=32, intermediate_size=64, moe_intermediate_size=16,
        num_hidden_layers=2, num_attention_heads=4, num_key_value_heads=2, head_dim=8,
        num_experts=4, num_experts_per_tok=2, max_position_embeddings=2048,
        decoder_sparse_step=1, mlp_only_layers=[], tie_word_embeddings=False)
    torch.manual_seed(0)
    return transformers.Qwen3MoeForCausalLM(cfg)


def _example(i):
    code = f"def f{i}(c, u):\n    q = 'SELECT ' + u\n    return c.execute(q)\n"
    f = Finding(cwe="CWE-89", severity="high", function=f"f{i}", line=2, title="SQL enjeksiyonu",
                evidence="q = 'SELECT ' + u", fix="Parametreli sorgu kullan.", false_positive=False)
    return Example(input=ExampleInput(file="a.py", language="python", code=code,
                                      scanner_output="bandit: [B608] sql (a.py:2, severity: medium)"),
                   output=ExampleOutput(findings=[f] if i % 2 == 0 else [], summary="özet"))


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "train.jsonl"
    p.write_text("\n".join(_example(i).to_jsonl() for i in range(8)) + "\n")
    return TrainConfig(train_file=str(p), val_file=str(p), output_dir=str(tmp_path / "out"),
                       max_len=1024, quantization="none", bf16=False, use_cpu=True, epochs=1,
                       max_steps=4, save_steps=2, eval_steps=2, logging_steps=1,
                       per_device_batch_size=2, grad_accum=1, gradient_checkpointing=False,
                       lora={"r": 4, "alpha": 8, "dropout": 0.0}, spot={"enabled": False})


def test_collate_pads_right_and_masks_padding(tokenizer):
    ds = data.SFTDataset(tokenizer, [_example(0), _example(1)], max_len=1024)
    batch = data.collate([ds[0], ds[1]], pad_id=tokenizer.pad_token_id)
    assert batch["input_ids"].shape == batch["labels"].shape == batch["attention_mask"].shape
    short = min(range(2), key=lambda i: len(ds[i]["input_ids"]))
    n = len(ds[short]["input_ids"])
    assert (batch["labels"][short, n:] == -100).all() and (batch["attention_mask"][short, n:] == 0).all()
    assert (batch["attention_mask"][short, :n] == 1).all()
    assert ds.dropped == 0


def test_dataset_drops_overlong_and_counts_them(tokenizer):
    long_ex = _example(0).model_copy(update={"input": _example(0).input.model_copy(
        update={"code": "x = 1\n" * 4000})})
    ds = data.SFTDataset(tokenizer, [long_ex, _example(1)], max_len=512)
    assert len(ds) == 1 and ds.dropped == 1


def test_lora_touches_only_attention_projections():
    model = modelmod.apply_lora(tiny_model(), TrainConfig(train_file="x").lora, gradient_checkpointing=False)
    names = [n for n, p in model.named_parameters() if p.requires_grad]
    assert names and all("lora_" in n for n in names)
    assert all(any(t in n for t in ("q_proj", "k_proj", "v_proj", "o_proj")) for n in names)
    assert not any(("experts" in n) or ("mlp.gate" in n) or ("embed" in n) or ("lm_head" in n) for n in names)
    frozen = [n for n, p in model.named_parameters() if not p.requires_grad]
    assert len(frozen) > len(names)
    trainable, total = modelmod.count_parameters(model)
    assert 0 < trainable < total * 0.2


def test_nf4_without_cuda_fails_with_clear_message(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="nf4.*CUDA"):
        modelmod.load_base_model(TrainConfig(train_file="x", quantization="nf4"))


def test_train_saves_complete_checkpoints_then_resumes(cfg, tokenizer):
    s1 = run.train(cfg, model=tiny_model(), tokenizer=tokenizer)
    assert s1["global_step"] == 4 and s1["resumed_from"] is None and s1["interrupted"] is False
    out = cfg.output_dir
    assert resume.latest_checkpoint(out).name == "checkpoint-4"
    assert (resume.latest_checkpoint(out) / resume.MARKER).exists()
    assert s1["train_loss"] is not None and s1["train_loss"] == s1["train_loss"]        # NaN değil
    assert (resume.latest_checkpoint(out) / "adapter_model.safetensors").exists()
    # kaldığı yerden devam: hedefi 6 adıma çıkar
    s2 = run.train(cfg.model_copy(update={"max_steps": 6}), model=tiny_model(), tokenizer=tokenizer)
    assert s2["resumed_from"].endswith("checkpoint-4") and s2["global_step"] == 6
    assert (cfg_dir := resume.latest_checkpoint(out)).name == "checkpoint-6"
    assert json.loads((cfg_dir.parent / "run_summary.json").read_text())["global_step"] == 6


def test_spot_interruption_saves_and_stops_early(cfg, tokenizer):
    fired = threading.Event()
    seq = {"n": 0}

    def fetch():                                  # birkaç yoklamadan sonra kesinti bildirimi
        seq["n"] += 1
        return {"action": "terminate", "time": "t"} if seq["n"] > 2 else None

    watcher = spot.SpotWatcher(fetch=fetch, poll_seconds=0.001)
    big = cfg.model_copy(update={"max_steps": 400, "save_steps": 1000})
    summary = run.train(big, model=tiny_model(), tokenizer=tokenizer, spot_watcher=watcher)
    assert summary["interrupted"] is True and summary["global_step"] < 400
    ckpt = resume.latest_checkpoint(big.output_dir)
    assert ckpt is not None and (ckpt / resume.MARKER).exists()                     # son durum kaydedildi


def test_s3_is_pushed_after_every_save_and_pulled_first(cfg, tokenizer):
    calls = []
    s3 = s3sync.S3Sync("s3://my-bucket/run1", runner=lambda cmd, **kw: calls.append(cmd))
    run.train(cfg, model=tiny_model(), tokenizer=tokenizer, s3=s3)
    syncs = [c for c in calls if c[:3] == ["aws", "s3", "sync"]]
    assert syncs[0][3] == "s3://my-bucket/run1"                                      # önce pull (kaynak = S3)
    pushes = [c for c in syncs[1:] if c[3] != "s3://my-bucket/run1"]
    assert len(pushes) >= 2 * 2                                                      # ≥2 kayıt × (veri + işaret)


def test_dry_run_reports_tokens_steps_and_cost(cfg, tokenizer):
    rep = run.dry_run(cfg, tokenizer)
    assert rep["examples"] == 8 and rep["kept"] == 8 and rep["trained_tokens"] > 0
    assert rep["steps_per_epoch"] == 4 and rep["total_steps"] == 4                    # max_steps=4
    assert rep["estimated_hours"] is None and rep["estimated_usd"] is None            # hız bilinmiyor
    priced = run.dry_run(cfg.model_copy(update={"assumed_tokens_per_sec": 1000.0, "usd_per_hour": 10.0}),
                         tokenizer)
    assert priced["estimated_hours"] > 0 and priced["estimated_usd"] == pytest.approx(
        priced["estimated_hours"] * 10.0, rel=1e-3)


def test_hf_generation_backend_runs_on_a_tiny_saved_model(tmp_path, tokenizer):
    from secagent.eval import backends
    d = tmp_path / "tiny"
    tiny_model().save_pretrained(d)
    tokenizer.save_pretrained(d)
    gen = backends.build_generator("hf", str(d), max_tokens=6)
    text = gen(_example(0).input)
    assert isinstance(text, str)            # içerik rastgele; yol (istem -> üretim -> çözme) çalışıyor


def test_launch_script_is_safe_and_valid_bash():
    import subprocess
    from pathlib import Path
    sh = Path(__file__).resolve().parent.parent / "train" / "launch.sh"
    assert subprocess.run(["bash", "-n", str(sh)]).returncode == 0
    text = sh.read_text()
    assert "trap finish EXIT" in text and "shutdown -h now" in text          # her çıkışta kapanır
    assert "--delete" not in text                                            # uzaktakini silmez
    assert "board_asset_tag" in text and "EC2 değil" in text                 # yerelde ASLA kapatmaz
    bad = subprocess.run(["bash", str(sh)], env={"PATH": "/usr/bin:/bin", "S3_BUCKET": "x;rm",
                         "RUN_ID": "r1", "NO_SHUTDOWN": "1"}, capture_output=True, text=True)
    assert bad.returncode == 64 and "geçersiz" in bad.stderr                 # girdi doğrulanır
    missing = subprocess.run(["bash", str(sh)], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert missing.returncode != 0


def test_fraction_4bit_check_fails_fast_when_experts_stay_bf16():
    with pytest.raises(RuntimeError, match="4-bit"):
        modelmod.check_quantized_fraction(tiny_model(), min_fraction=0.5)
    assert modelmod.quantized_fraction(tiny_model()) == 0.0


def test_eval_subset_is_capped(cfg, tokenizer):
    big = cfg.model_copy(update={"eval_max_examples": 3})
    assert run.eval_examples(big)[0:1] and len(run.eval_examples(big)) == 3


def test_finished_run_is_not_marked_interrupted_by_a_late_notice(cfg, tokenizer):
    w = spot.SpotWatcher(fetch=lambda: None, poll_seconds=0.001)
    w.notice.set()                                     # eğitim bittikten sonra gelmiş gibi: ilk adımdan önce set
    w.info = {"action": "terminate"}
    s = run.train(cfg.model_copy(update={"max_steps": 1, "save_steps": 1000}), model=tiny_model(),
                  tokenizer=tokenizer, spot_watcher=w)
    assert s["global_step"] == 1 and s["interrupted"] is False        # hedef adıma ulaştı: kesinti sayılmaz
    assert (pathlib.Path(cfg.output_dir) / "final").exists() and len(s["train_file_sha256"]) == 16


def test_launch_script_cost_safety_and_input_validation():
    import subprocess
    from pathlib import Path
    sh = Path(__file__).resolve().parent.parent / "train" / "launch.sh"
    text = sh.read_text()
    assert "trap '' HUP" in text and "sudo -n shutdown" in text and "timeout -k 5m" in text
    assert text.count("timeout \"$STEP_TIMEOUT\"") >= 4                      # pip, veri, iki aşamalı son eşitleme
    assert "--exclude \"*/COMPLETE\"" in text and "--include \"*/COMPLETE\"" in text
    assert "-c train/constraints.txt" in text
    for bad in ("..", ".hidden", "a..b", "x y", "-rf"):
        r = subprocess.run(["bash", str(sh)], env={"PATH": "/usr/bin:/bin", "S3_BUCKET": "my-bucket",
                           "RUN_ID": bad, "NO_SHUTDOWN": "1"}, capture_output=True, text=True)
        assert r.returncode == 64, bad
    cons = (sh.parent / "constraints.txt").read_text()
    assert "transformers==" in cons and "peft==" in cons
