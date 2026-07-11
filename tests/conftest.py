"""Fixtures y dobles de prueba (fake provider + fake sandbox).

Permiten ejercitar el orquestador sin llamar a modelos reales ni a Docker.
"""
from __future__ import annotations
import pytest

from basalt.config import Settings
from basalt.providers.base import ModelProvider, CompletionResult, Message
from basalt.sandbox.base import Sandbox, RunResult


class FakeProvider(ModelProvider):
    """Provider que devuelve una respuesta fija (scriptable) y no toca la red."""
    name = "fake"

    def __init__(self, model: str = "fake-1", reply: str = "", healthy: bool = True, **opts):
        super().__init__(model, **opts)
        self.reply = reply
        self._healthy = healthy
        self.calls: list[list[Message]] = []

    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw) -> CompletionResult:
        self.calls.append(list(messages))
        return CompletionResult(text=self.reply, provider=self.name, model=self.model)

    def health(self) -> bool:
        return self._healthy


class FakeSandbox(Sandbox):
    """Sandbox en memoria: `run` devuelve por stdout lo que se haya escrito (el PoC),
    de modo que si el PoC contiene el sentinel, la reproducción 'dispara'."""

    def __init__(self):
        self.files: dict[str, str] = {}
        self.trees: list[str] = []
        self.commands: list[list[str]] = []

    def put(self, host_path, container_path):
        self.files[container_path] = f"<copiado:{host_path}>"

    def put_tree(self, host_dir, dest=""):
        self.trees.append(host_dir)

    def write(self, content, container_path):
        self.files[container_path] = content

    def run(self, cmd, *, workdir="/work", timeout=120, network=False) -> RunResult:
        self.commands.append(cmd)
        return RunResult(0, "\n".join(self.files.values()), "")


def make_settings(reply: str = '{"real": true}', role_replies: dict | None = None,
                  **overrides) -> Settings:
    """Settings con los 5 roles apuntando a un FakeProvider.

    `reply` fija la respuesta por defecto; `role_replies` la sobrescribe por rol
    (p.ej. red_find devuelve un array JSON y purple_verify un veredicto)."""
    role_replies = role_replies or {}
    roles = {r: FakeProvider(reply=role_replies.get(r, reply))
             for r in ("recon", "red_find", "purple_verify", "blue_patch", "grader")}
    cfg = Settings(roles=roles, target_kind=overrides.pop("target_kind", "generic"))
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


@pytest.fixture
def settings_factory():
    return make_settings


@pytest.fixture
def fake_sandbox_factory():
    def factory():
        return FakeSandbox()
    return factory
