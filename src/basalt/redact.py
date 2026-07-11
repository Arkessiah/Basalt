"""Sanitización de secretos: reemplaza credenciales por un marcador etiquetado.

Doble objetivo:
- No filtrar secretos REALES del target al proveedor de modelo, a los logs ni al informe.
- Preservar la SEÑAL: el marcador `<BASALT_REDACTED:aws-access-key>` deja ver que hay un secreto
  hardcodeado (el red agent puede seguir reportándolo) sin exponer el valor.

Idea inspirada en el `redact.ts` de T3MP3ST, reimplementada desde cero (no se copió código).
"""
from __future__ import annotations
import re

# (nombre, patrón) — el orden importa: los más específicos primero.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b")),
    ("github-token", re.compile(r"\bgh[opusr]_[0-9A-Za-z]{36,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[0-9A-Za-z-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai-key", re.compile(r"\bsk-[0-9A-Za-z]{32,}\b")),   # tras anthropic (más específico)
    ("jwt", re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b")),
]

# URI con credenciales embebidas: conserva esquema y usuario, redacta la contraseña.
_URI_CRED = re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/\s@]+):(?P<pw>[^@/\s]+)@")

# Asignación de secreto: password/token/api_key = "valor".
_ASSIGN = re.compile(
    r"(?i)(?P<key>password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"(?P<sep>\s*[:=]\s*)(?P<q>['\"])(?P<val>[^'\"\n]{6,})(?P=q)")


def find_secrets(text: str) -> list[tuple[str, int]]:
    """Localiza secretos SIN exponer su valor: devuelve [(tipo, nº_de_línea_1based)]."""
    if not text:
        return []
    out: list[tuple[str, int]] = []

    def _add(label: str, start: int):
        out.append((label, text.count("\n", 0, start) + 1))

    for name, pat in _PATTERNS:
        for m in pat.finditer(text):
            _add(name, m.start())
    for m in _URI_CRED.finditer(text):
        _add("uri-credential", m.start())
    for m in _ASSIGN.finditer(text):
        _add(m.group("key").lower().replace("-", "_"), m.start())
    return out


def redact(text: str) -> tuple[str, int]:
    """Devuelve (texto_saneado, nº_de_secretos_redactados)."""
    if not text:
        return text, 0
    total = 0
    for name, pat in _PATTERNS:
        text, c = pat.subn(f"<BASALT_REDACTED:{name}>", text)
        total += c
    text, c = _URI_CRED.subn(
        lambda m: f"{m.group('scheme')}{m.group('user')}:<BASALT_REDACTED:uri-credential>@", text)
    total += c
    text, c = _ASSIGN.subn(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('q')}"
                  f"<BASALT_REDACTED:{m.group('key').lower().replace('-', '_')}>{m.group('q')}", text)
    total += c
    return text, total
