"""In-process client for a model loaded with MLX, optionally with a LoRA adapter.

MLX has no schema-constrained decoding, so the answer shape is described in the
prompt and the reply is parsed leniently. That makes results from this client
not directly comparable with the Ollama client, which enforces the schema.
"""

from __future__ import annotations

import time
from typing import Any

from .llm import ChatResult


def shape_of(schema: dict[str, Any]) -> str:
    """A compact skeleton of a JSON schema, short enough to put in a prompt."""
    kind = schema.get("type")
    if kind == "object":
        inner = ", ".join(f'"{k}": {shape_of(v)}' for k, v in schema["properties"].items())
        return "{" + inner + "}"
    if kind == "array":
        return f"[{shape_of(schema['items'])}, ...]"
    if kind == "integer":
        return "int"
    if "enum" in schema:
        return '"' + "|".join(schema["enum"]) + '"'
    return "string"


def format_note(schema: dict[str, Any]) -> str:
    return "Answer with one JSON object and nothing else, in this shape:\n" + shape_of(schema)


def extract_json(text: str) -> str:
    """The outermost JSON object in a reply that may carry fences or stray text."""
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if start != -1 and end > start else text


def with_format_note(messages: list[dict[str, Any]], schema: dict[str, Any] | None) -> list[dict[str, Any]]:
    out = [dict(m) for m in messages]
    if schema:
        out[-1]["content"] = f"{out[-1]['content']}\n\n{format_note(schema)}"
    return out


class MLXClient:
    def __init__(
        self,
        model: str,
        adapter: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ):
        from mlx_lm import load  # imported lazily: MLX is optional and Apple-only

        self.model = f"{model}+{adapter}" if adapter else model
        self._model, self._tokenizer = load(model, adapter_path=adapter)
        self.max_tokens = max_tokens
        self.temperature = temperature

    def render(self, messages: list[dict[str, Any]]) -> str:
        """The exact prompt text, with reasoning switched off where the template allows."""
        try:
            return self._tokenizer.apply_chat_template(
                messages, add_generation_prompt=True, tokenize=False, enable_thinking=False
            )
        except TypeError:
            return self._tokenizer.apply_chat_template(
                messages, add_generation_prompt=True, tokenize=False
            )

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        schema: dict[str, Any] | None = None,
    ) -> ChatResult:
        from mlx_lm import stream_generate
        from mlx_lm.sample_utils import make_sampler

        prompt = self.render(with_format_note(messages, schema))
        started = time.monotonic()
        text, last = "", None
        for last in stream_generate(
            self._model, self._tokenizer, prompt=prompt, max_tokens=self.max_tokens,
            sampler=make_sampler(temp=self.temperature),
        ):
            text += last.text
        return ChatResult(
            content=extract_json(text) if schema else text,
            prompt_tokens=getattr(last, "prompt_tokens", 0),
            completion_tokens=getattr(last, "generation_tokens", 0),
            seconds=time.monotonic() - started,
            truncated=getattr(last, "finish_reason", None) == "length",
        )
