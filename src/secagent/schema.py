"""
Eğitim örneği şeması.

Her eğitim örneği bir JSONL satırıdır: {"input": {...}, "output": {...}}.
Bu modül şemayı kodla tanımlar ve her örneği doğrular. Bozuk veya eksik
örnekler eğitime girmez. Üretilen tüm veri bu doğrulamadan geçmelidir.

Bağımlılık: pydantic>=2
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Literal, Optional

from pydantic import BaseModel, Field, field_validator


Severity = Literal["critical", "high", "medium", "low", "info"]

LANGUAGES: tuple[str, ...] = (
    "python", "java", "kotlin", "cpp", "csharp", "typescript", "javascript",
    "go", "rust", "php", "ruby", "swift", "docker", "terraform", "kubernetes",
)
Language = Literal[LANGUAGES]  # type: ignore[valid-type]  # tek kaynak: LANGUAGES

# Eğitim hedefinden çıkarılan, çıkarım sonrası deterministik eklenen alanlar.
_TRAIN_EXCLUDE = {"output": {"findings": {"__all__": {"cvss", "references"}}}}


class CVSS(BaseModel):
    """CVSS 3.1 skoru. Kaynağı yoksa tamamen boş (None) bırakılır;
    model olmayan veriden puan uydurmasın diye alan atlanır."""
    score: float = Field(ge=0.0, le=10.0)
    vector: str

    @field_validator("vector")
    @classmethod
    def _vector_shape(cls, v: str) -> str:
        if not v.startswith("CVSS:3"):
            raise ValueError("CVSS vektörü 'CVSS:3...' ile başlamalı")
        return v


class Finding(BaseModel):
    cwe: str = Field(pattern=r"^CWE-\d+$")
    severity: Severity
    cvss: Optional[CVSS] = None
    function: Optional[str] = None          # etkilenen fonksiyon; global ise None
    line: Optional[int] = Field(default=None, ge=1)
    title: str = Field(min_length=5, max_length=160)
    evidence: str                            # koddaki ilgili satır(lar)
    fix: str                                 # somut, uygulanabilir düzeltme
    references: list[str] = Field(default_factory=list)
    false_positive: bool = False

    @field_validator("references")
    @classmethod
    def _refs_are_urls(cls, v: list[str]) -> list[str]:
        for r in v:
            if not r.startswith("http"):
                raise ValueError(f"Referans URL olmalı: {r!r}")
        return v


class ExampleInput(BaseModel):
    file: str
    language: Language
    code: str
    scanner_output: str = ""                 # tarayıcı çıktısı; yoksa boş


class ExampleOutput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""                        # kısa doğal dil özeti (opsiyonel)


class Example(BaseModel):
    input: ExampleInput
    output: ExampleOutput

    def to_jsonl(self, training: bool = False) -> str:
        """training=True: cvss/references hedeften çıkarılır. Bunlar model
        tarafından üretilmez; mappings.py ile çıkarım sonrası eklenir."""
        return self.model_dump_json(
            exclude_none=True, exclude=_TRAIN_EXCLUDE if training else None
        )


def validate_file(path: str | Path) -> tuple[int, int]:
    """Bir JSONL dosyasındaki her satırı doğrular.
    (geçerli, hatalı) sayısını döndürür ve hataları stderr'e yazar."""
    import sys

    ok, bad = 0, 0
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                Example.model_validate_json(line)
                ok += 1
            except Exception as e:  # pydantic ValidationError dahil
                bad += 1
                print(f"[satır {i}] GEÇERSİZ: {e}", file=sys.stderr)
    return ok, bad


def iter_valid(path: str | Path) -> Iterator[Example]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield Example.model_validate_json(line)


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("Kullanım: secagent-validate <örnekler.jsonl>")
        return 2
    good, broken = validate_file(sys.argv[1])
    print(f"Geçerli: {good}  Hatalı: {broken}")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
