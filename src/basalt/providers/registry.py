"""Resolver de proveedores — elige backend por nombre/config, con fallback.

Patrón inspirado en el resolver multi-provider de ECC. Un rol puede pedir un
proveedor lógico (p.ej. "auditor") y el registry lo resuelve a un backend físico
según config + salud, con cadena de fallback (ej. claude_api -> openai_compat -> ollama).
"""
from __future__ import annotations
from .base import ModelProvider

_BUILDERS: dict[str, type[ModelProvider]] = {}


def register(name: str):
    def deco(cls: type[ModelProvider]):
        cls.name = name
        _BUILDERS[name] = cls
        return cls
    return deco


def available() -> list[str]:
    return sorted(_BUILDERS)


def build(spec: dict) -> ModelProvider:
    """spec = {"provider": "claude_api", "model": "...", ...opts}."""
    prov = spec.get("provider")
    if prov not in _BUILDERS:
        raise ValueError(f"proveedor desconocido: {prov!r}. Disponibles: {available()}")
    opts = {k: v for k, v in spec.items() if k not in ("provider", "model")}
    return _BUILDERS[prov](model=spec.get("model", ""), **opts)


def resolve(chain: list[dict]) -> ModelProvider:
    """Devuelve el primer proveedor sano de la cadena de fallback."""
    last_err = None
    for spec in chain:
        try:
            p = build(spec)
            if p.health():
                return p
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise RuntimeError(f"ningún proveedor de la cadena está disponible: {chain} ({last_err})")


# Importar implementaciones para que se auto-registren.
from . import claude_api, claude_cli, openai_compat, ollama  # noqa: E402,F401
