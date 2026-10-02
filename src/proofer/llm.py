"""Thin client for a local chat model.

The agent only depends on `ChatClient.chat`. Ollama is the default runtime;
another local runtime can be added by implementing the same method.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx


class LLMError(Exception):
    pass


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResult:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    truncated: bool = False


class ChatClient(Protocol):
    model: str

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        schema: dict[str, Any] | None = None,
    ) -> ChatResult: ...


def require_loopback(url: str) -> None:
    """The product path must not send repository contents off this machine."""
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise LLMError(f"model endpoint must be on this machine, got {host!r}")


class OllamaClient:
    def __init__(
        self,
        model: str,
        host: str = "http://127.0.0.1:11434",
        num_ctx: int = 16384,
        temperature: float = 0.0,
        think: bool | None = None,
        seed: int = 7,
        max_tokens: int = 4096,
        timeout: float = 900.0,
    ):
        require_loopback(host)
        self.model = model
        self.host = host.rstrip("/")
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.think = think
        self.seed = seed
        self.max_tokens = max_tokens
        self._http = httpx.Client(timeout=timeout)

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        schema: dict[str, Any] | None = None,
    ) -> ChatResult:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            # A fixed seed and zero temperature keep evaluation runs comparable.
            "options": {
                "num_ctx": self.num_ctx,
                "temperature": self.temperature,
                "seed": self.seed,
                # Without a cap a reasoning model can think for minutes and never answer.
                "num_predict": self.max_tokens,
            },
        }
        if tools:
            body["tools"] = tools
        if schema:
            body["format"] = schema
        if self.think is not None:
            body["think"] = self.think

        started = time.monotonic()
        try:
            resp = self._http.post(f"{self.host}/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise LLMError(f"cannot reach model runtime: {exc}") from exc
        if resp.status_code != 200:
            raise LLMError(f"runtime returned {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        msg = data.get("message", {})

        calls = []
        for raw in msg.get("tool_calls") or []:
            fn = raw.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            calls.append(ToolCall(name=fn.get("name", ""), arguments=args))

        return ChatResult(
            content=msg.get("content") or "",
            tool_calls=calls,
            thinking=msg.get("thinking") or "",
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            seconds=time.monotonic() - started,
            truncated=data.get("done_reason") == "length",
        )
