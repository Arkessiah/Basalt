"""Basalt — purple-team de agentes de IA para auditar la seguridad de software e infra.

Arquitectura: recon → red(find) → purple(verify por ejecución) → blue(patch) → grader.
Capa de modelos pluggable (Claude CLI/API, openai_compat, Ollama). Ver README.md.
"""
__version__ = "0.1.0"
