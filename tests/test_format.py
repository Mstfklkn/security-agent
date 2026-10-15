import pytest

from secagent import prompt
from secagent.schema import Example, ExampleInput, ExampleOutput, Finding
from secagent.train import format as fmt

CODE = "def get(c, u):\n    q = \"SELECT %s\" % u\n    return c.execute(q)\n"


def _ex(findings=True, code=CODE):
    f = [Finding(cwe="CWE-89", severity="high", function="get", line=2, title="SQL enjeksiyonu",
                 evidence='q = "SELECT %s" % u', fix="Parametreli sorgu.", false_positive=False)]
    return Example(input=ExampleInput(file="a.py", language="python", code=code,
                                      scanner_output="bandit: [B608] sql"),
                   output=ExampleOutput(findings=f if findings else [], summary="özet"))


def test_labels_mask_the_prompt_and_train_on_json_plus_eos(tokenizer):
    ex = _ex()
    t = fmt.tokenize_example(tokenizer, ex, max_len=4096)
    assert len(t.input_ids) == len(t.labels)
    assert all(x == fmt.IGNORE for x in t.labels[:t.prompt_len])
    trained = [x for x in t.labels if x != fmt.IGNORE]
    assert tokenizer.decode(trained) == prompt.render_target(ex.output) + "<|im_end|>"
    assert t.input_ids[-1] == tokenizer.eos_token_id == t.labels[-1]
    assert t.labels[t.prompt_len:] == t.input_ids[t.prompt_len:]


def test_prompt_part_equals_inference_prompt_and_chat_template(tokenizer):
    ex = _ex()
    t = fmt.tokenize_example(tokenizer, ex, max_len=4096)
    text = fmt.prompt_text(tokenizer, ex.input)
    assert tokenizer.decode(t.input_ids[:t.prompt_len]) == text
    assert text.endswith("<|im_start|>assistant\n")
    full = tokenizer.apply_chat_template(
        prompt.build_messages(ex.input) + [{"role": "assistant", "content": prompt.render_target(ex.output)}],
        tokenize=False)
    assert full.startswith(text + prompt.render_target(ex.output) + "<|im_end|>")


def test_too_long_examples_are_dropped_not_truncated(tokenizer):
    long = _ex(code="x = 1\n" * 5000)
    assert fmt.tokenize_example(tokenizer, long, max_len=512) is None
    ok = fmt.tokenize_example(tokenizer, _ex(), max_len=4096)
    assert fmt.tokenize_example(tokenizer, _ex(), max_len=len(ok.input_ids)) is not None
    assert fmt.tokenize_example(tokenizer, _ex(), max_len=len(ok.input_ids) - 1) is None


def test_clean_example_trains_on_empty_findings(tokenizer):
    t = fmt.tokenize_example(tokenizer, _ex(findings=False), max_len=4096)
    trained = tokenizer.decode([x for x in t.labels if x != fmt.IGNORE])
    assert trained.startswith('{"findings":[],')


def test_length_report(tokenizer):
    rep = fmt.length_report(tokenizer, [_ex(), _ex(findings=False), _ex(code="x = 1\n" * 5000)],
                            max_len=1024)
    assert rep["examples"] == 3 and rep["dropped_too_long"] == 1 and rep["kept"] == 2
    assert rep["total_tokens"] > 0 and rep["trained_tokens"] > 0
    assert rep["trained_tokens"] < rep["total_tokens"]
    assert set(rep["percentiles"]) == {"p50", "p90", "p99", "max"}


def test_load_examples_streams_valid_jsonl(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text(_ex().to_jsonl() + "\n" + _ex(findings=False).to_jsonl() + "\n")
    assert len(list(fmt.load_examples(p))) == 2
    with pytest.raises(Exception):
        bad = tmp_path / "b.jsonl"
        bad.write_text('{"input":{}}\n')
        list(fmt.load_examples(bad))
