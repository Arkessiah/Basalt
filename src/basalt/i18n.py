"""i18n ligero: inglés por defecto (fuente), overrides por idioma. Extensible.

El texto EN es la clave: `t("Findings", lang)` devuelve la traducción si existe para
`lang`, o el propio texto EN (default sin tocar nada). Para líneas con formato, se usa la
plantilla EN como clave y `.format(**kw)` después. Añadir un idioma = otra entrada en `_TR`.
"""
from __future__ import annotations

DEFAULT_LANG = "en"
LANGUAGES = ("en", "es")

# Overrides por idioma. La clave es SIEMPRE el texto/plantilla en inglés.
_TR: dict[str, dict[str, str]] = {
    "es": {
        # report.py
        "Security Audit Report — Basalt": "Informe de Auditoría de Seguridad — Basalt",
        "**Findings:** {total} ({status})": "**Hallazgos:** {total} ({status})",
        "no findings": "sin hallazgos",
        "**Verification funnel:** {cand} candidates → {rj} rejected by the judge → "
        "{re} not reproduced in sandbox → **{conf} confirmed**.":
            "**Embudo de verificación:** {cand} candidatos → {rj} rechazados por el juez → "
            "{re} no reproducidos en sandbox → **{conf} confirmados**.",
        "Severity": "Severidad",
        "Total": "Total",
        "_No findings to report._": "_No hay hallazgos que reportar._",
        "**Location:** `{loc}`": "**Ubicación:** `{loc}`",
        "**Votes:** {n}": "**Votos:** {n}",
        "**PoC:**": "**PoC:**",
        "**Patch:** {rationale}": "**Parche:** {rationale}",
        "- Files: `{files}`": "- Ficheros: `{files}`",
        "- Provenance: **OSV match** ({cves}) · {dep_kind} dependency":
            "- Procedencia: **OSV match** ({cves}) · dependencia {dep_kind}",
        " · fixed in `{fixed}`": " · corregido en `{fixed}`",
        "direct": "directa",
        "transitive (indirect)": "transitiva (indirect)",
        "- Reachability (govulncheck): {label}": "- Reachability (govulncheck): {label}",
        "**reachable** (vulnerable symbol is called)":
            "**alcanzable** (el símbolo vulnerable se llama)",
        "not reachable (present but not called)": "no alcanzable (presente pero no llamado)",
        "reachability undetermined": "reachability no determinada",
        "- Detection: pattern match (the secret value is NOT included in the report).":
            "- Detección: por patrón (el valor del secreto NO se incluye en el informe).",
        "- Verification: {label} · reproduced={rep}": "- Verificación: {label} · reproducido={rep}",
        "proven by execution (tool-proven)": "probado por ejecución (tool-proven)",
        "asserted by the model (model-asserted)": "aseverado por el modelo (model-asserted)",
        # audit_doc.py
        "Security Audit Report": "Informe de Auditoría de Seguridad",
        "Executive summary": "Resumen ejecutivo",
        "Total confirmed findings: {n}.": "Total de hallazgos confirmados: {n}.",
        "Audit metadata": "Metadatos de la auditoría",
        "Methodology": "Metodología",
        "Findings": "Hallazgos",
        "No findings were confirmed.": "No se confirmaron hallazgos.",
        "Target": "Objetivo",
        "Scope": "Alcance",
        "Date": "Fecha",
        "Audited commit": "Commit auditado",
        "Tool": "Herramienta",
        "Isolation": "Aislamiento",
        "Auditor": "Auditor",
        "Evidence hash (SHA-256)": "Hash de evidencia (SHA-256)",
        "Proof of concept (PoC):": "Prueba de concepto (PoC):",
        "Reproduction evidence: ": "Evidencia de reproducción: ",
        "REPRODUCED by execution": "REPRODUCIDO por ejecución",
        "not reproduced": "no reproducido",
        "Evidence: ": "Evidencia: ",
        "Remediation: ": "Remediación: ",
        "Audit performed with a purple-team of AI agents and execution-based verification:":
            "Auditoría con un purple-team de agentes de IA y verificación por ejecución:",
        "CONFIDENTIAL — internal / authorized client use":
            "CONFIDENCIAL — uso interno / cliente autorizado",
        "NO FINDINGS": "SIN HALLAZGOS",
        "votes": "votos",
        "Match on OSV.dev": "Match en OSV.dev",
        " · fixed in ": " · corregido en ",
        "Known vulnerability (N-day), confirmed by version, not by PoC.":
            "Vulnerabilidad conocida (N-day), confirmada por versión, no por PoC.",
        " (stage={stage}).": " (stage={stage}).",
        "Files: ": "Ficheros: ",
        "**Verification funnel:** {line}. Confirmed findings were verified by executing the PoC "
        "in an isolated sandbox or by matching against the OSV vulnerability database "
        "(dependency N-day).":
            "**Embudo de verificación:** {line}. Los hallazgos confirmados se verificaron por "
            "ejecución del PoC en sandbox aislado o por match contra la base de vulnerabilidades "
            "OSV (N-day por dependencia).",
        "Basalt — audit report": "Basalt — informe de auditoría",
        "Reproduction evidence:": "Evidencia de reproducción:",
        # bundle.py
        "Basalt — audit evidence bundle": "Basalt — bundle de evidencia de auditoría",
        "Tool: {tool}": "Herramienta: {tool}",
        "Target: {target}": "Objetivo: {target}",
        "Audited commit: {commit}": "Commit auditado: {commit}",
        "Date: {date}": "Fecha: {date}",
        "Findings: {n}": "Hallazgos: {n}",
        "Funnel: {line}": "Embudo: {line}",
        "Integrity hash (SHA-256 of report.json): {h}":
            "Hash de integridad (SHA-256 de report.json): {h}",
        "Verification funnel: ": "Embudo de verificación: ",
        ". Confirmed findings were verified by executing the PoC in an isolated sandbox or by "
        "matching against the OSV vulnerability database (dependency N-day).":
            ". Los hallazgos confirmados se verificaron por ejecución del PoC en sandbox aislado o "
            "por match contra la base de vulnerabilidades OSV (N-day por dependencia).",
        "Known vulnerability (N-day), confirmed by version.":
            "Vulnerabilidad conocida (N-day), confirmada por versión.",
        " · fixed in {fixed}": " · corregido en {fixed}",
    },
}


def t(text: str, lang: str = DEFAULT_LANG, **fmt) -> str:
    """Traduce `text` (clave EN) a `lang`; si no hay override, usa el propio EN. Aplica format."""
    s = _TR.get(lang, {}).get(text, text)
    return s.format(**fmt) if fmt else s


def normalize(lang: str | None) -> str:
    lang = (lang or DEFAULT_LANG).lower()
    return lang if lang in LANGUAGES else DEFAULT_LANG
