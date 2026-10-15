"""Eğitim yapılandırması (YAML + komut satırı geçersiz kılmaları). Bilinmeyen anahtar HATA verir."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

S3_URI = re.compile(r"^s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](/[A-Za-z0-9._\-/]*)?$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoraCfg(_Strict):
    r: int = Field(16, gt=0)
    alpha: int = Field(32, gt=0)
    dropout: float = Field(0.05, ge=0, lt=1)
    # Yalnızca dikkat katmanları: MoE uzman/router katmanlarına LoRA uygulanmaz
    # (uzmanlar sürüme göre birleşik tensör olabilir, router'a dokunmak istikrarsızlaştırır).
    target_modules: list[str] = ["q_proj", "k_proj", "v_proj", "o_proj"]

    @field_validator("target_modules")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("target_modules boş olamaz")
        return v


class S3Cfg(_Strict):
    uri: str | None = None

    @field_validator("uri")
    @classmethod
    def _valid(cls, v: str | None) -> str | None:
        if v is not None and not S3_URI.match(v):
            raise ValueError(f"geçersiz S3 URI: {v!r}")
        return v


class SpotCfg(_Strict):
    enabled: bool = True
    poll_seconds: float = Field(5.0, gt=0)


class TrainConfig(_Strict):
    model_id: str = "Qwen/Qwen3-Coder-30B-A3B-Instruct"
    train_file: str
    val_file: str | None = None
    output_dir: str = "outputs/run"
    max_len: int = Field(4096, gt=0)
    # none = bf16 LoRA (varsayılan). nf4: Qwen3-MoE uzmanları birleşik 3B parametre olduğundan
    # bitsandbytes onları nicemleyemez (bellek tasarrufu yok); yüklemede hızlıca hata verir.
    quantization: Literal["none", "nf4"] = "none"
    lora: LoraCfg = LoraCfg()
    epochs: float = Field(2.0, gt=0)
    max_steps: int | None = Field(None, gt=0)
    learning_rate: float = Field(1e-4, gt=0)
    lr_scheduler: str = "cosine"
    warmup_ratio: float = Field(0.03, ge=0, lt=1)
    weight_decay: float = Field(0.0, ge=0)
    per_device_batch_size: int = Field(1, gt=0)
    grad_accum: int = Field(16, gt=0)
    gradient_checkpointing: bool = True
    bf16: bool = True
    optim: str = "adamw_torch"          # CUDA/QLoRA'da paged_adamw_8bit (bitsandbytes) denenebilir
    use_cpu: bool = False               # yalnızca yerel duman testi için
    logging_steps: int = Field(10, gt=0)
    save_steps: int = Field(100, gt=0)
    eval_steps: int = Field(100, gt=0)
    save_total_limit: int = Field(3, gt=0)
    eval_max_examples: int = Field(100, gt=0)    # değerlendirme süresi Spot uyarısından kısa kalsın
    seed: int = 42
    s3: S3Cfg = S3Cfg()
    spot: SpotCfg = SpotCfg()
    # Maliyet tahmini için (H6 keşif oturumunda ölçülür; bilinmiyorsa boş bırak)
    usd_per_hour: float | None = Field(None, gt=0)
    assumed_tokens_per_sec: float | None = Field(None, gt=0)


def _set_path(tree: dict, dotted: str, value: Any) -> None:
    node = tree
    *parents, leaf = dotted.split(".")
    for key in parents:
        node = node.setdefault(key, {})
    node[leaf] = value


def parse_overrides(pairs: list[str]) -> dict:
    """['a.b=3', 'x=foo'] -> {'a': {'b': 3}, 'x': 'foo'} (değerler YAML olarak çözülür)."""
    out: dict = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"geçersiz --set değeri (anahtar=değer olmalı): {pair!r}")
        key, raw = pair.split("=", 1)
        _set_path(out, key.strip(), yaml.safe_load(raw))
    return out


def _merge(base: dict, extra: dict) -> dict:
    merged = dict(base)
    for k, v in extra.items():
        merged[k] = _merge(merged[k], v) if isinstance(v, dict) and isinstance(merged.get(k), dict) else v
    return merged


def load_config(path: str | Path, overrides: dict | None = None) -> TrainConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return TrainConfig.model_validate(_merge(data, overrides or {}))
