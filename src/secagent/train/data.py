"""PyTorch veri seti ve harmanlayıcı (sağa dolgu; dolgu etiketleri -100)."""
from __future__ import annotations

from typing import Iterable

import torch
from torch.utils.data import Dataset

from ..schema import Example
from .format import IGNORE, tokenize_example


class SFTDataset(Dataset):
    """Örnekleri bir kez tokenlar. max_len'i aşanlar ATILIR (kırpılmaz) ve `dropped`te sayılır."""

    def __init__(self, tokenizer, examples: Iterable[Example], max_len: int):
        self._items: list[dict] = []
        self.dropped = 0
        for ex in examples:
            t = tokenize_example(tokenizer, ex, max_len)
            if t is None:
                self.dropped += 1
            else:
                self._items.append({"input_ids": t.input_ids, "labels": t.labels})

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, i: int) -> dict:
        return self._items[i]


def collate(batch: list[dict], pad_id: int) -> dict[str, torch.Tensor]:
    width = max(len(b["input_ids"]) for b in batch)
    ids = torch.full((len(batch), width), pad_id, dtype=torch.long)
    labels = torch.full((len(batch), width), IGNORE, dtype=torch.long)
    mask = torch.zeros((len(batch), width), dtype=torch.long)
    for i, b in enumerate(batch):
        n = len(b["input_ids"])
        ids[i, :n] = torch.tensor(b["input_ids"])
        labels[i, :n] = torch.tensor(b["labels"])
        mask[i, :n] = 1
    return {"input_ids": ids, "labels": labels, "attention_mask": mask}
