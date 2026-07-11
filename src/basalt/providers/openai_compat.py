"""openai_compat (u otro gateway OpenAI-compatible) vía HTTP.

Reutiliza el gateway `/v1/chat/completions` de openai_compat. Mismo cliente sirve
para cualquier endpoint OpenAI-compat (por eso `base_url` es configurable).
"""
from __future__ import annotations
import os
from .base import ModelProvider, CompletionResult, extract_openai_text
from .registry import register


@register("openai_compat")
class OpenAICompatProvider(ModelProvider):
    def __init__(self, model: str = "qwen3:8b",
                 base_url: str = "http://localhost:8080/v1",
                 api_key_env: str = "OPENAI_COMPAT_API_KEY", **opts):
        super().__init__(model, **opts)
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env

    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw) -> CompletionResult:
        import httpx
        headers = {"Content-Type": "application/json"}
        key = os.environ.get(self.api_key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature, "max_tokens": max_tokens,
        }

        def _do():
            with httpx.Client(timeout=self.opts.get("timeout", 300)) as c:
                r = c.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
            return CompletionResult(text=extract_openai_text(data), provider="openai_compat",
                                    model=self.model, usage=data.get("usage", {}), raw=data)
        return self._retry(_do)
