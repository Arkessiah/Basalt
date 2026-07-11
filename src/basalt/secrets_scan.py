"""Escaneo de secretos hardcodeados como check de primera clase (cross-language).

Recorre el repo aplicando los patrones de `redact.py` y produce `Finding`s de categoría
`hardcoded-secrets` con provenance `pattern-match`. NUNCA guarda el valor del secreto, solo
su TIPO y ubicación (fichero:línea), para no filtrarlo al informe. No usa LLM ni sandbox.
"""
from __future__ import annotations
import glob
import os
from dataclasses import dataclass

from .findings import Finding
from .redact import find_secrets

# Extensiones donde suelen aparecer secretos (código + config + entorno).
_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".php", ".java", ".cs",
         ".c", ".cpp", ".sh", ".bash", ".zsh", ".env", ".yaml", ".yml", ".json", ".toml",
         ".ini", ".cfg", ".conf", ".tf", ".tfvars", ".properties", ".xml", ".txt", ".md")
_EXCLUDE = ("/node_modules/", "/vendor/", "/.git/", "/target/", "/dist/", "/build/",
            "/.venv/", "/venv/", "/__pycache__/", "/.basalt/")


@dataclass
class SecretScanResult:
    files_scanned: int
    findings: list[Finding]


def scan(root: str, *, max_files: int = 5000) -> SecretScanResult:
    files = [f for f in glob.glob(os.path.join(root, "**", "*"), recursive=True)
             if f.endswith(_EXTS) and os.path.isfile(f)
             and not any(e in f for e in _EXCLUDE)]
    findings: list[Finding] = []
    scanned = 0
    for path in files[:max_files]:
        scanned += 1
        try:
            text = open(path, errors="ignore").read()
        except OSError:
            continue
        rel = os.path.relpath(path, root)
        for label, line in find_secrets(text):
            f = Finding(
                title=f"Hardcoded secret ({label}) in {rel}",
                severity="high",
                category="hardcoded-secrets",
                target=rel,
                location=f"{rel}:{line}",
                description=(f"Possible {label} hardcoded in the code. Rotate the credential and "
                            f"move it to a secrets manager / environment variable."),
                poc="",   # no se incluye el valor real (no filtrar el secreto)
                status="confirmed",
                finder="secret-scan",
            )
            f.votes = 1
            f.meta = {
                "provenance": "pattern-match",
                "secret_type": label,
                "verify": {"stage": "secret-scan", "reproduced": None, "provenance": "pattern-match"},
            }
            findings.append(f)
    return SecretScanResult(scanned, findings)
