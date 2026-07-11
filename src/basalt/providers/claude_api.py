"""Claude vía Anthropic API (calidad máxima de auditoría)."""
from __future__ import annotations
import os
from .base import ModelProvider, CompletionResult
from .registry import register


@register("claude_api")
class ClaudeAPIProvider(ModelProvider):
    def __init__(self, model: str = "claude-opus-4-8", api_key_env: str = "ANTHROPIC_API_KEY", **opts):
        super().__init__(model or "claude-opus-4-8", **opts)
        self.api_key_env = api_key_env

    def _client(self):
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("Falta 'anthropic'. `uv pip install anthropic`") from e
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(f"Falta la variable {self.api_key_env}")
        return anthropic.Anthropic(api_key=key)

    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw) -> CompletionResult:
        system = "\n\n".join(m.content for m in messages if m.role == "system") or None
        conv = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]

        def _do():
            resp = self._client().messages.create(
                model=self.model, max_tokens=max_tokens, temperature=temperature,
                system=system, messages=conv,
            )
            text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
            usage = getattr(resp, "usage", None)
            return CompletionResult(text=text, provider="claude_api", model=self.model,
                                    usage=usage.__dict__ if usage else {})
        return self._retry(_do)
