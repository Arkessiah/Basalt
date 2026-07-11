"""Ollama local (offline, coste cero) vía su API OpenAI-compatible (`/v1`).

Apunta al kit local `~/MODELOS_iA` si `OLLAMA_MODELS` está configurado. Ideal
para triage barato o entornos sin conexión.
"""
from __future__ import annotations
from .base import ModelProvider, CompletionResult, extract_openai_text
from .registry import register


@register("ollama")
class OllamaProvider(ModelProvider):
    def __init__(self, model: str = "qwen3:8b",
                 base_url: str = "http://localhost:11434/v1", **opts):
        super().__init__(model, **opts)
        self.base_url = base_url.rstrip("/")

    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw) -> CompletionResult:
        import httpx
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature, "max_tokens": max_tokens, "stream": False,
        }

        def _do():
            with httpx.Client(timeout=self.opts.get("timeout", 600)) as c:
                r = c.post(f"{self.base_url}/chat/completions", json=payload)
                r.raise_for_status()
                data = r.json()
            return CompletionResult(text=extract_openai_text(data), provider="ollama",
                                    model=self.model, usage=data.get("usage", {}), raw=data)
        return self._retry(_do)
