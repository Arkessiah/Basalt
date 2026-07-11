"""Roles del purple-team. Cada rol tiene un provider propio (config), así puedes
usar Claude API para el auditor y Ollama para el recon barato, p.ej.
"""
from __future__ import annotations
from .base import Agent


class ReconAgent(Agent):
    """Mapea la superficie de ataque y particiona el objetivo en trozos auditables."""
    role = "recon"


class RedFindAgent(Agent):
    """RED — busca vulnerabilidades y produce un PoC candidato (nunca parchea)."""
    role = "red_find"


class PurpleVerifyAgent(Agent):
    """PURPLE — juez. Decide si un hallazgo es real EXIGIENDO reproducción por
    ejecución en sandbox limpio; descarta lo no reproducible (anti-falsos-positivos)."""
    role = "purple_verify"


class BluePatchAgent(Agent):
    """BLUE — parchea SOLO hallazgos ya verificados; propone fix mínimo + test."""
    role = "blue_patch"


class GraderAgent(Agent):
    """Confirma que el parche del blue cierra el PoC sin romper build/tests."""
    role = "grader"


ROLES = {
    "recon": ReconAgent, "red_find": RedFindAgent, "purple_verify": PurpleVerifyAgent,
    "blue_patch": BluePatchAgent, "grader": GraderAgent,
}
