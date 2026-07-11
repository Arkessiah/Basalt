"""Agente base: un rol = prompt de sistema + un ModelProvider.

Los roles (recon/red/purple/blue/grader) heredan de aquí. El prompt de cada rol
vive en `prompts/<role>.md` para poder iterarlo sin tocar código.
"""
from __future__ import annotations
from pathlib import Path
from ..providers.base import ModelProvider, Message

PROMPTS_DIR = Path(__file__).resolve().parents[3] / "prompts"


def load_prompt(role: str) -> str:
    p = PROMPTS_DIR / f"{role}.md"
    return p.read_text(encoding="utf-8") if p.exists() else f"You are the {role} agent."


class Agent:
    role = "base"

    def __init__(self, provider: ModelProvider, extra_system: str = ""):
        self.provider = provider
        self.system = load_prompt(self.role)
        if extra_system:
            self.system += "\n\n" + extra_system

    def run(self, user_content: str, *, temperature: float = 0.2, max_tokens: int = 4096) -> str:
        msgs = [Message("system", self.system), Message("user", user_content)]
        return self.provider.complete(msgs, temperature=temperature, max_tokens=max_tokens).text
