"""Model arka uçları: ExampleInput -> ham metin. Ağır kütüphaneler yalnızca kullanılınca içe aktarılır.

- null : her zaman 'bulgu yok' (alt sınır / sağlık kontrolü)
- mlx  : Apple Silicon, mlx-lm (taban çizgisi ve nicemlenmiş model için)
- hf   : transformers (+ isteğe bağlı PEFT adaptörü); GPU'da eğitim sonrası ölçüm için
Çıkarımda EĞİTİMLE AYNI istem kullanılır (train.format.prompt_text).
"""
from __future__ import annotations

from typing import Callable

from ..schema import ExampleInput

Generator = Callable[[ExampleInput], str]
NULL_OUTPUT = '{"findings":[],"summary":"Bulgu yok."}'


def build_generator(backend: str, model: str | None = None, adapter: str | None = None,
                    max_tokens: int = 1024) -> Generator:
    if backend == "null":
        return lambda _inp: NULL_OUTPUT
    if not model:
        raise ValueError(f"'{backend}' arka ucu için --model gerekli")
    if backend == "mlx":
        return _mlx(model, max_tokens)
    if backend == "hf":
        return _hf(model, adapter, max_tokens)
    raise ValueError(f"bilinmeyen arka uç: {backend!r}")


def _mlx(model_id: str, max_tokens: int) -> Generator:
    from mlx_lm import generate, load          # pip install mlx-lm
    from ..train.format import prompt_text

    model, tokenizer = load(model_id)

    def gen(inp: ExampleInput) -> str:
        text = prompt_text(tokenizer, inp)
        return generate(model, tokenizer, prompt=text, max_tokens=max_tokens, verbose=False)

    return gen


def _hf(model_id: str, adapter: str | None, max_tokens: int) -> Generator:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from ..train.format import prompt_text

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(model_id, dtype="auto", device_map="auto")
    if adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter)
    model.eval()

    def gen(inp: ExampleInput) -> str:
        ids = tokenizer(prompt_text(tokenizer, inp), add_special_tokens=False,
                        return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(**ids, max_new_tokens=max_tokens, do_sample=False,
                                 eos_token_id=tokenizer.eos_token_id,
                                 pad_token_id=tokenizer.pad_token_id)
        return tokenizer.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)

    return gen
