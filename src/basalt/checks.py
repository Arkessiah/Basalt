"""Catálogo pluggable de checks (categorías de vulnerabilidad).

Sustituye los `hint` hardcodeados por un registro declarativo: cada check tiene id
(vocabulario canónico de `Finding.category`), lenguajes aplicables, severidad orientativa,
referencia CWE y un fragmento de guía para el red agent. Filtrable por config
(`audit.checks`) para acotar una auditoría a ciertas categorías.

Añadir una categoría = una entrada en `CATALOG` (no se toca `adapters.py` ni el orchestrator).
"""
from __future__ import annotations
from dataclasses import dataclass

ALL = "*"   # aplica a todos los lenguajes


@dataclass(frozen=True)
class Check:
    id: str                 # == Finding.category canónico
    title: str
    languages: tuple[str, ...]   # kinds a los que aplica, o (ALL,)
    severity: str           # severidad orientativa
    cwe: str
    hint: str               # guía breve para el red agent

    def applies(self, kind: str) -> bool:
        return ALL in self.languages or kind in self.languages


CATALOG: tuple[Check, ...] = (
    Check("sql-injection", "Inyección SQL", (ALL,), "high", "CWE-89",
          "consultas construidas por concatenación de input no confiable"),
    Check("command-injection", "Inyección de comandos", (ALL,), "critical", "CWE-78",
          "input no confiable pasado a shell/exec/system"),
    Check("path-traversal", "Path traversal", (ALL,), "high", "CWE-22",
          "rutas de fichero derivadas de input sin normalizar/confinar"),
    Check("ssrf", "SSRF", (ALL,), "high", "CWE-918",
          "peticiones salientes a URLs controladas por el input"),
    Check("auth-bypass", "Bypass de autenticación", (ALL,), "critical", "CWE-287",
          "comprobaciones de identidad eludibles (comparación insegura, defaults, prefijos)"),
    Check("access-control", "Control de acceso roto", (ALL,), "high", "CWE-862",
          "falta de autorización por objeto/acción (IDOR, privilege escalation)"),
    Check("insecure-deserialization", "Deserialización insegura", (ALL,), "high", "CWE-502",
          "deserializar input no confiable (pickle/yaml.load/Marshal/serde arbitrario)"),
    Check("hardcoded-secrets", "Secretos hardcodeados", (ALL,), "high", "CWE-798",
          "credenciales/API keys/tokens embebidos en el código (ver marcadores <BASALT_REDACTED:...>)"),
    Check("weak-crypto", "Criptografía débil", (ALL,), "medium", "CWE-327",
          "MD5/SHA1 para seguridad, ECB, IV/nonce reutilizado, comparación no constante"),
    Check("trust-control-bypass", "Bypass de controles de confianza", (ALL,), "high", "CWE-295",
          "validación TLS/firma desactivada (InsecureSkipVerify, verify=False, NODE_TLS_REJECT)"),
    Check("xss", "Cross-site scripting", ("typescript", "generic"), "high", "CWE-79",
          "HTML/DOM construido con input sin escapar (innerHTML, dangerouslySetInnerHTML)"),
    Check("prototype-pollution", "Prototype pollution", ("typescript", "generic"), "high", "CWE-1321",
          "merge/asignación recursiva que permite escribir __proto__/constructor"),
    Check("redos", "ReDoS", ("typescript", "python", "generic"), "medium", "CWE-1333",
          "regex con backtracking catastrófico sobre input no confiable"),
    Check("reentrancy", "Reentrancy", ("solidity",), "critical", "CWE-841",
          "llamada externa antes de actualizar estado (patrón checks-effects-interactions roto)"),
    Check("integer-overflow", "Overflow aritmético", ("solidity", "rust", "generic"), "high", "CWE-190",
          "aritmética sin comprobación de límites que envuelve/desborda"),
    Check("memory-safety", "Seguridad de memoria", ("rust", "generic"), "high", "CWE-119",
          "bloques unsafe: punteros colgantes, out-of-bounds, use-after-free, data races"),
    Check("unchecked-error", "Errores no comprobados", ("go", "generic"), "medium", "CWE-252",
          "valores de error ignorados que dejan estado inseguro"),
)

_BY_ID = {c.id: c for c in CATALOG}


def all_ids() -> list[str]:
    return [c.id for c in CATALOG]


def selected(kind: str, only: list[str] | None = None) -> list[Check]:
    """Checks aplicables al lenguaje `kind`, opcionalmente filtrados por lista de ids."""
    chosen = [c for c in CATALOG if c.applies(kind)]
    if only:
        want = set(only)
        chosen = [c for c in chosen if c.id in want]
    return chosen


def prompt_block(kind: str, only: list[str] | None = None) -> str:
    """Bloque de guía para el red agent: categorías canónicas a buscar en este lenguaje."""
    checks = selected(kind, only)
    if not checks:
        return ""
    lines = ["CATEGORÍAS A BUSCAR (usa el `id` EXACTO como `category` del hallazgo):"]
    lines += [f"- {c.id} ({c.cwe}, sev~{c.severity}): {c.hint}" for c in checks]
    return "\n".join(lines)
