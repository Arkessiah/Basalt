"""Capa de proveedores de modelo — abstracción pluggable.

Todo agente habla con un `ModelProvider`. Añadir un backend nuevo = implementar
esta interfaz y registrarlo en `registry.py`. Diseño "super conectable": Claude
(suscripción vía CLI), Claude API, openai_compat (OpenAI-compat) y Ollama local
son intercambiables por configuración, sin tocar los agentes.
"""
from __future__ import annotations
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


def is_transient(e: Exception) -> bool:
    """¿El error justifica reintentar? (timeouts, red, 429/5xx). No reintenta errores
    de configuración (clave ausente, import) ni respuestas malformadas."""
    if isinstance(e, (TimeoutError, ConnectionError, subprocess.TimeoutExpired, OSError)):
        return True
    mod = type(e).__module__ or ""
    name = type(e).__name__
    if mod.startswith("httpx"):                 # sin importar httpx en el módulo base
        if name == "HTTPStatusError":
            code = getattr(getattr(e, "response", None), "status_code", 0)
            return code == 429 or 500 <= code < 600
        return True                              # TimeoutException/ConnectError/ReadError…
    if mod.startswith(("anthropic", "openai")):  # SDKs: rate-limit, conexión, 5xx, overloaded
        status = getattr(e, "status_code", 0) or 0
        if status == 429 or 500 <= status < 600:
            return True
        return any(k in name for k in ("RateLimit", "Connection", "Timeout",
                                       "InternalServer", "Overloaded", "ServiceUnavailable"))
    return False


def extract_openai_text(data: dict) -> str:
    """Extrae el texto de una respuesta OpenAI-compatible con validación clara."""
    try:
        choices = data["choices"]
        content = choices[0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        err = data.get("error") if isinstance(data, dict) else None
        raise RuntimeError(f"respuesta del modelo malformada: {err or data}") from e
    if content is None:
        raise RuntimeError("respuesta del modelo sin contenido")
    return content


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class CompletionResult:
    text: str
    provider: str
    model: str
    usage: dict = field(default_factory=dict)
    raw: dict | None = None


class ModelProvider(ABC):
    """Contrato mínimo que cumplen todos los backends de modelo."""

    name: str = "base"

    def __init__(self, model: str, **opts):
        self.model = model
        self.opts = opts

    @abstractmethod
    def complete(self, messages: list[Message], *, temperature: float = 0.2,
                 max_tokens: int = 4096, **kw) -> CompletionResult:
        """Genera una respuesta. Síncrono; los agentes lo llaman en su bucle."""

    def _retry(self, fn):
        """Ejecuta `fn` reintentando ante errores TRANSITORIOS con backoff exponencial.
        Config por provider: `retries` (default 2) y `retry_delay` seg (default 1.5)."""
        attempts = int(self.opts.get("retries", 2)) + 1
        delay = float(self.opts.get("retry_delay", 1.5))
        for i in range(attempts):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                if i < attempts - 1 and is_transient(e):
                    time.sleep(delay * (2 ** i))
                    continue
                raise

    def health(self) -> bool:
        """¿El backend responde? Se usa para fallback/resolución."""
        try:
            self.complete([Message("user", "ping")], max_tokens=5)
            return True
        except Exception:
            return False

    def __repr__(self):  # pragma: no cover
        return f"<{self.__class__.__name__} model={self.model!r}>"
