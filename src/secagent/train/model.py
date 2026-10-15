"""Temel modeli yükleme (isteğe bağlı 4-bit NF4) ve LoRA uygulama."""
from __future__ import annotations

from .config import LoraCfg, TrainConfig


def load_base_model(cfg: TrainConfig):
    import torch
    from transformers import AutoModelForCausalLM

    kwargs: dict = {"dtype": torch.bfloat16 if cfg.bf16 else "auto"}
    cuda = torch.cuda.is_available()
    if cfg.quantization == "nf4":
        if not cuda:
            raise RuntimeError("quantization=nf4 (QLoRA) için CUDA gerekir; yerelde 'none' kullan "
                               "ya da GPU'lu makinede çalıştır")
        from transformers import BitsAndBytesConfig
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16)
    if cuda:
        kwargs["device_map"] = {"": torch.cuda.current_device()}       # tek GPU
    model = AutoModelForCausalLM.from_pretrained(cfg.model_id, **kwargs)
    if cfg.quantization == "nf4":
        check_quantized_fraction(model)
    return model


def quantized_fraction(model) -> float:
    """4-bit (bitsandbytes Params4bit) parametrelerin toplam içindeki payı."""
    total = q = 0
    for p in model.parameters():
        n = p.numel() * (2 if type(p).__name__ == "Params4bit" else 1)   # 4-bit paketli: 2 değer/bayt
        total += n
        if type(p).__name__ == "Params4bit":
            q += n
    return q / total if total else 0.0


def check_quantized_fraction(model, min_fraction: float = 0.5) -> None:
    """Qwen3-MoE uzmanları birleşik 3B nn.Parameter'dır; bitsandbytes yalnızca nn.Linear'ı
    nicemler, yani nf4 sessizce ~58 GB'ı bf16 bırakır. Ücretli GPU zamanını harcamadan HATA ver."""
    frac = quantized_fraction(model)
    if frac < min_fraction:
        raise RuntimeError(f"nf4 istendi ama parametrelerin yalnızca %{frac:.0%}'i 4-bit "
                           f"(beklenen >= %{min_fraction:.0%}): MoE uzmanları nicemlenmedi. "
                           "quantization: none (bf16 LoRA) kullan.")


def apply_lora(model, lora: LoraCfg, gradient_checkpointing: bool, quantized: bool = False):
    from peft import LoraConfig, get_peft_model

    # prepare_model_for_kbit_training KULLANILMAZ: nicemlenmemiş tüm bf16 parametreleri fp32'ye
    # çevirir (MoE uzmanlarında ~2x bellek). Gerekli olan tek şey giriş gradyanıdır.
    if gradient_checkpointing or quantized:
        model.enable_input_require_grads()        # dondurulmuş gömmelerle checkpointing için gerekli
    model.config.use_cache = False
    peft_cfg = LoraConfig(r=lora.r, lora_alpha=lora.alpha, lora_dropout=lora.dropout,
                          target_modules=list(lora.target_modules), bias="none", task_type="CAUSAL_LM")
    return get_peft_model(model, peft_cfg)


def count_parameters(model) -> tuple[int, int]:
    """(eğitilebilir, toplam)"""
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return trainable, sum(p.numel() for p in model.parameters())
