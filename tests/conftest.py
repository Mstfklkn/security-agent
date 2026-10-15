import pytest

MODEL_ID = "Qwen/Qwen3-Coder-30B-A3B-Instruct"


@pytest.fixture(scope="session")
def tokenizer():
    """Gerçek Qwen3-Coder tokenizer'ı (yalnızca tokenizer dosyaları, ~10 MB). Yüklenemezse
    (transformers yok / çevrimdışı ve önbellek boş) bağımlı testler atlanır."""
    transformers = pytest.importorskip("transformers")
    try:
        return transformers.AutoTokenizer.from_pretrained(MODEL_ID)
    except Exception as e:                                   # ağ yok
        pytest.skip(f"tokenizer yüklenemedi: {type(e).__name__}")
