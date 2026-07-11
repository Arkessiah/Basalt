"""Claude vía la CLI de Claude Code (usa tu SUSCRIPCIÓN, sin API key).

Ejecuta `claude -p` en modo headless. Útil para no gastar API: aprovecha el
plan (Pro/Max). Requiere `claude` en el PATH y sesión iniciada.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from .base import ModelProvider, Message, CompletionResult
from .registry import register


@register("claude_cli")
class ClaudeCLIProvider(ModelProvider):
    def __init__(self, model: str = "", bin: str = "claude", timeout: int = 300, **opts):
        super().__init__(model, **opts)
        self.bin = bin
        self.timeout = timeout

    def _prompt(self, messages: list[Message]) -> str:
        parts = []
        for m in messages:
            tag = {"system": "[SYSTEM]", "user": "[USER]", "assistant": "[ASSISTANT]"}.get(m.role, "[USER]")
            parts.append(f"{tag}\n{m.content}")
        return "\n\n".join(parts)

    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw) -> CompletionResult:
        if not shutil.which(self.bin):
            raise RuntimeError(f"No se encontró '{self.bin}' en PATH (Claude Code CLI).")
        cmd = [self.bin, "-p", self._prompt(messages), "--output-format", "json"]
        if self.model:
            cmd += ["--model", self.model]
        r = self._retry(lambda: subprocess.run(cmd, capture_output=True, text=True,
                                               timeout=self.timeout))
        if r.returncode != 0:
            raise RuntimeError(f"claude CLI falló: {r.stderr.strip()[:300]}")
        out = r.stdout.strip()
        try:  # --output-format json => {"result": "...", ...}
            data = json.loads(out)
            text = data.get("result") or data.get("text") or out
            return CompletionResult(text=text, provider="claude_cli",
                                    model=self.model or data.get("model", "claude"), raw=data)
        except json.JSONDecodeError:
            return CompletionResult(text=out, provider="claude_cli", model=self.model or "claude")
