"""
Eğitim akışı: secagent-train --config train/config.yaml [--dry-run] [--set anahtar=değer]

Sıra: S3'ten çek -> son TAM checkpoint'i bul -> eğit (Spot kesintisinde kaydet+dur) ->
adaptörü kaydet -> özeti yaz -> S3'e it. Çıkış kodu 0 = bitti, 75 = Spot kesintisi (yeniden
başlatılırsa kaldığı yerden devam eder), diğer = hata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

from .config import TrainConfig, load_config, parse_overrides
from .format import length_report, load_examples
from .resume import latest_checkpoint
from .s3sync import S3Sync
from .spot import SpotWatcher

EX_TEMPFAIL = 75


def dry_run(cfg: TrainConfig, tokenizer) -> dict:
    """GPU kullanmadan: token sayısı, adım ve (hız biliniyorsa) süre/maliyet tahmini."""
    rep = length_report(tokenizer, load_examples(cfg.train_file), cfg.max_len)
    effective = cfg.per_device_batch_size * cfg.grad_accum
    steps_per_epoch = max(1, math.ceil(rep["kept"] / effective))
    total_steps = cfg.max_steps or max(1, math.ceil(steps_per_epoch * cfg.epochs))
    processed_tokens = rep["total_tokens"] * total_steps / steps_per_epoch
    hours = (processed_tokens / cfg.assumed_tokens_per_sec / 3600
             if cfg.assumed_tokens_per_sec else None)
    usd = hours * cfg.usd_per_hour if hours is not None and cfg.usd_per_hour else None
    return {**rep, "effective_batch": effective, "steps_per_epoch": steps_per_epoch,
            "total_steps": total_steps, "processed_tokens": round(processed_tokens),
            "estimated_hours": hours, "estimated_usd": usd}


def eval_examples(cfg: TrainConfig) -> list:
    """Doğrulama kümesinin ilk eval_max_examples örneği (süre sınırı; deterministik)."""
    out = []
    for ex in load_examples(cfg.val_file):
        out.append(ex)
        if len(out) >= cfg.eval_max_examples:
            break
    return out


def _sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def build_args(cfg: TrainConfig, has_val: bool):
    from transformers import TrainingArguments

    return TrainingArguments(
        output_dir=cfg.output_dir,
        per_device_train_batch_size=cfg.per_device_batch_size, per_device_eval_batch_size=1,
        gradient_accumulation_steps=cfg.grad_accum, learning_rate=cfg.learning_rate,
        num_train_epochs=cfg.epochs, max_steps=cfg.max_steps or -1,
        lr_scheduler_type=cfg.lr_scheduler, warmup_steps=cfg.warmup_ratio,   # transformers 5: [0,1) ondalığı = toplam adım oranı
        weight_decay=cfg.weight_decay, bf16=cfg.bf16 and not cfg.use_cpu,
        logging_steps=cfg.logging_steps, save_strategy="steps", save_steps=cfg.save_steps,
        save_total_limit=cfg.save_total_limit,
        eval_strategy="steps" if has_val else "no", eval_steps=cfg.eval_steps,
        seed=cfg.seed, report_to="none", remove_unused_columns=False,
        gradient_checkpointing=cfg.gradient_checkpointing,
        gradient_checkpointing_kwargs={"use_reentrant": False} if cfg.gradient_checkpointing else None,
        use_cpu=cfg.use_cpu, optim=cfg.optim, dataloader_num_workers=0)


def train(cfg: TrainConfig, model=None, tokenizer=None, spot_watcher: SpotWatcher | None = None,
          s3: S3Sync | None = None) -> dict:
    from transformers import AutoTokenizer, Trainer

    from .callbacks import MarkerCallback, S3Callback, SpotCallback
    from .data import SFTDataset, collate
    from .model import apply_lora, count_parameters, load_base_model

    tokenizer = tokenizer or AutoTokenizer.from_pretrained(cfg.model_id)
    s3 = s3 or S3Sync(cfg.s3.uri)
    out = Path(cfg.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    s3.pull(out, retries=3)                             # ÖNCE çek: itme uzaktakini ezmesin
    ckpt = latest_checkpoint(out)

    train_ds = SFTDataset(tokenizer, load_examples(cfg.train_file), cfg.max_len)
    val_ds = SFTDataset(tokenizer, eval_examples(cfg), cfg.max_len) if cfg.val_file else None
    if len(train_ds) == 0:
        raise ValueError("eğitim kümesi boş (hepsi max_len'den uzun ya da dosya boş)")

    if model is None:
        model = load_base_model(cfg)
    model = apply_lora(model, cfg.lora, cfg.gradient_checkpointing, quantized=cfg.quantization == "nf4")
    trainable, total = count_parameters(model)

    watcher = spot_watcher or (SpotWatcher(poll_seconds=cfg.spot.poll_seconds) if cfg.spot.enabled else None)
    if watcher is not None and not watcher.is_alive():
        watcher.start()
    callbacks = [MarkerCallback(), S3Callback(s3)] + ([SpotCallback(watcher)] if watcher else [])

    pad = tokenizer.pad_token_id
    trainer = Trainer(model=model, args=build_args(cfg, val_ds is not None), train_dataset=train_ds,
                      eval_dataset=val_ds, data_collator=lambda b: collate(b, pad), callbacks=callbacks)
    result = trainer.train(resume_from_checkpoint=str(ckpt) if ckpt else None)

    # Eğitim hedef adıma ulaştıysa geç gelen bildirim "kesinti" değildir (final kaydedilir, çıkış 0)
    interrupted = bool(watcher and watcher.notice.is_set()
                       and trainer.state.global_step < trainer.state.max_steps)
    if watcher is not None:
        watcher.stop()
    if not interrupted:
        trainer.save_model(str(out / "final"))          # yalnızca LoRA adaptörü
    summary = {"global_step": trainer.state.global_step, "train_loss": result.training_loss,
               "resumed_from": str(ckpt) if ckpt else None, "interrupted": interrupted,
               "examples": len(train_ds), "dropped_too_long": train_ds.dropped,
               "trainable_params": trainable, "total_params": total,
               "train_file_sha256": _sha256(cfg.train_file)}      # bölmeler veri sürümüne bağlı
    (out / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    s3.push(out, retries=3)                             # kesin garanti: hata fırlatır
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secagent-train")
    ap.add_argument("--config", required=True)
    ap.add_argument("--set", action="append", default=[], metavar="ANAHTAR=DEĞER")
    ap.add_argument("--dry-run", action="store_true", help="GPU kullanma; token/adım/maliyet raporu")
    args = ap.parse_args(argv)
    cfg = load_config(args.config, parse_overrides(args.set))
    if args.dry_run:
        from transformers import AutoTokenizer
        print(json.dumps(dry_run(cfg, AutoTokenizer.from_pretrained(cfg.model_id)),
                         indent=2, ensure_ascii=False))
        return 0
    summary = train(cfg)
    print(json.dumps(summary, indent=2))
    return EX_TEMPFAIL if summary["interrupted"] else 0


if __name__ == "__main__":
    sys.exit(main())
