"""
SFT tokenizasyonu: (istem -> JSON) örneğini girdi/etiket dizisine çevirir.

- Kayıp YALNIZCA asistan JSON'una ve bitiş belirtecine (<|im_end|>) hesaplanır; sistem
  istemi, kod ve tarayıcı çıktısı maskelenir (-100).
- İstem ve hedef AYRI tokenlanır: çıkarımda da model istem kimlikleriyle başlar ve hedefi
  üretir, dolayısıyla eğitim ve çıkarım dizilimi aynıdır.
- Çok uzun örnek KIRPILMAZ, atılır: kodu kırpmak numaralı satırları ve bulguları bozar.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .. import prompt
from ..schema import Example, ExampleInput, iter_valid

IGNORE = -100


@dataclass(frozen=True)
class Tokenized:
    input_ids: list[int]
    labels: list[int]
    prompt_len: int


def prompt_text(tokenizer, inp: ExampleInput) -> str:
    """Çıkarımda da kullanılan istem metni (asistan başlığıyla biter)."""
    return tokenizer.apply_chat_template(prompt.build_messages(inp), tokenize=False,
                                         add_generation_prompt=True)


def tokenize_example(tokenizer, ex: Example, max_len: int) -> Tokenized | None:
    """None: dizi max_len'i aşıyor."""
    prompt_ids = tokenizer(prompt_text(tokenizer, ex.input), add_special_tokens=False)["input_ids"]
    target = prompt.render_target(ex.output) + tokenizer.eos_token
    target_ids = tokenizer(target, add_special_tokens=False)["input_ids"]
    if len(prompt_ids) + len(target_ids) > max_len:
        return None
    return Tokenized(input_ids=prompt_ids + target_ids,
                     labels=[IGNORE] * len(prompt_ids) + target_ids,
                     prompt_len=len(prompt_ids))


def load_examples(path: str | Path) -> Iterator[Example]:
    """Şema doğrulamalı JSONL; geçersiz satırda hata verir (sessiz veri kaybı yok)."""
    return iter_valid(path)


def _percentile(sorted_vals: list[int], q: float) -> int:
    return sorted_vals[min(len(sorted_vals) - 1, int(q * len(sorted_vals)))] if sorted_vals else 0


def length_report(tokenizer, examples: Iterable[Example], max_len: int) -> dict:
    """Token uzunluğu dağılımı ve atılacak örnek sayısı (eğitime girmeden önce bütçe)."""
    lengths, trained, dropped, n = [], 0, 0, 0
    for ex in examples:
        n += 1
        t = tokenize_example(tokenizer, ex, max_len=10**9)
        if len(t.input_ids) > max_len:
            dropped += 1
            continue
        lengths.append(len(t.input_ids))
        trained += len(t.input_ids) - t.prompt_len
    lengths.sort()
    return {"examples": n, "kept": len(lengths), "dropped_too_long": dropped,
            "total_tokens": sum(lengths), "trained_tokens": trained,
            "percentiles": {"p50": _percentile(lengths, .5), "p90": _percentile(lengths, .9),
                            "p99": _percentile(lengths, .99), "max": lengths[-1] if lengths else 0}}
