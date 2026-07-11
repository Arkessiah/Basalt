"""Carga de configuración: resuelve un ModelProvider por ROL (cadena con fallback).

Ejemplo (config/basalt.example.yaml): puedes dar Claude API al auditor (purple)
y Ollama barato al recon. Cada rol acepta una lista `providers` = cadena de fallback.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml
from .providers.registry import resolve
from .providers.base import ModelProvider
from .i18n import normalize as _i18n_normalize


DEFAULT_CONFIG_YAML = """# Basalt — config de arranque (creada por `basalt init`). Ajusta a tu entorno.
default_providers:
  - { provider: claude_cli }                 # tu suscripción de Claude Code (sin API key)
  - { provider: claude_api, model: claude-opus-4-8, api_key_env: ANTHROPIC_API_KEY }
  - { provider: ollama, model: qwen3:8b }    # último recurso local/offline

roles:
  purple_verify:
    providers: [{ provider: claude_api, model: claude-opus-4-8 }, { provider: claude_cli }]

target:
  kind: generic            # generic | python | go | typescript | rust | solidity

sandbox:
  driver: docker
  gvisor: false
  # image: si se omite, se usa la imagen con toolchain por defecto del lenguaje

audit:
  red_runs: 3
  min_votes: 2
  require_execution: true
  recon: true
  max_parallel: 4
  # checks: [sql-injection, auth-bypass]     # filtra el catálogo (vacío = todos)

identity:
  org: Arkessiah
  auditor: ""

store_path: .basalt/findings.jsonl

lang: en                   # report/document language: en | es (default en)
"""


@dataclass
class Settings:
    roles: dict[str, ModelProvider]           # rol -> provider resuelto
    target_kind: str = "generic"
    sandbox: dict = field(default_factory=dict)
    store_path: str = ".basalt/findings.jsonl"
    red_runs: int = 3                          # nº de find-agents en paralelo por partición
    min_votes: int = 2                         # votos para promover a confirmado
    require_execution: bool = True             # exigir reproducción por ejecución para "confirmado"
    recon: bool = True                         # usar el agente recon para priorizar particiones por riesgo
    auto_patch: bool = False                   # tras confirmar, lanzar blue_patch + grader
    max_parallel: int = 4                      # concurrencia máx (find-agents y sandboxes de verificación)
    identity: dict = field(default_factory=dict)  # portada del informe: org, auditor, logo, contacto
    checks: list = field(default_factory=list)    # filtra el catálogo de checks (vacío = todos)
    lang: str = "en"                              # idioma del informe/documento (en|es)
    raw: dict = field(default_factory=dict)


def _validate(data: dict) -> None:
    """Validaciones baratas con mensajes claros (falla pronto, no en mitad de una auditoría)."""
    from .targets.adapters import ADAPTERS, _ALIASES
    from .checks import all_ids
    kind = data.get("target", {}).get("kind")
    if kind and kind.lower() not in ADAPTERS and kind.lower() not in _ALIASES:
        raise ValueError(
            f"target.kind desconocido: {kind!r}. Válidos: {sorted(ADAPTERS)} "
            f"(alias: {sorted(_ALIASES)}).")
    checks_sel = data.get("audit", {}).get("checks") or []
    bad = [c for c in checks_sel if c not in all_ids()]
    if bad:
        raise ValueError(f"audit.checks desconocidos: {bad}. Válidos: {all_ids()}.")


def store_path_of(path: str | Path) -> str:
    """Lee SOLO el `store_path` del YAML, sin resolver proveedores de modelo.

    Así comandos de lectura (p.ej. `report`) no exigen backends de modelo vivos."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    return data.get("store_path", ".basalt/findings.jsonl")


def lang_of(path: str | Path) -> str:
    """Lee el idioma del informe (en|es) del YAML, sin resolver proveedores."""
    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except OSError:
        return "en"
    return _i18n_normalize(data.get("lang", "en"))


def load(path: str | Path) -> Settings:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config no encontrada: {path}. Copia config/basalt.example.yaml y ajústala "
            f"(o crea una con `basalt init`).")
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise RuntimeError(f"Config YAML inválida ({path}): {e}") from e
    if not isinstance(data, dict):
        raise RuntimeError(f"Config inválida ({path}): la raíz debe ser un mapping YAML.")
    _validate(data)
    default_chain = data.get("default_providers") or [{"provider": "claude_cli"}]
    roles_cfg = data.get("roles", {})
    roles: dict[str, ModelProvider] = {}
    for role in ("recon", "red_find", "purple_verify", "blue_patch", "grader"):
        chain = roles_cfg.get(role, {}).get("providers") or default_chain
        roles[role] = resolve(chain)
    audit = data.get("audit", {})
    return Settings(
        roles=roles,
        target_kind=data.get("target", {}).get("kind", "generic"),
        sandbox=data.get("sandbox", {}),
        store_path=data.get("store_path", ".basalt/findings.jsonl"),
        red_runs=audit.get("red_runs", 3),
        min_votes=audit.get("min_votes", 2),
        require_execution=audit.get("require_execution", True),
        recon=audit.get("recon", True),
        auto_patch=audit.get("auto_patch", False),
        max_parallel=audit.get("max_parallel", 4),
        identity=data.get("identity", {}),
        checks=audit.get("checks", []),
        lang=_i18n_normalize(data.get("lang", "en")),
        raw=data,
    )
