"""Bundle de evidencia: empaqueta un artefacto reproducible/verificable de la auditoría.

Un .zip con el informe (md+json), el PoC de cada hallazgo, el log de stdout de su
reproducción en sandbox, y un MANIFEST con metadatos + hash de integridad. Sirve para
que un auditor humano revise la evidencia sin depender de la herramienta.
"""
from __future__ import annotations
import hashlib
import re
import zipfile

from .findings import Finding
from .report import render, funnel_from_findings, _sorted
from .i18n import t


def _slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return (s[:n] or "finding")


def build_bundle(findings: list[Finding], *, target: str, out_path: str,
                 funnel: dict | None = None, commit: str = "", date: str = "",
                 tool: str = "Basalt", lang: str = "en") -> dict:
    """Escribe el zip de evidencia. Devuelve un resumen (ruta, nº ficheros, hash)."""
    fn = funnel if funnel is not None else funnel_from_findings(findings)
    ordered = _sorted(findings)
    report_json = render(findings, fmt="json", target=target, funnel=fn)
    report_md = render(findings, fmt="markdown", target=target, funnel=fn, lang=lang)
    ehash = hashlib.sha256(report_json.encode("utf-8")).hexdigest()

    n_poc = n_log = 0
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.md", report_md)
        z.writestr("report.json", report_json)
        for i, f in enumerate(ordered):
            slug = f"{i:02d}_{_slug(f.title)}"
            if f.poc:
                z.writestr(f"pocs/{slug}.txt", f.poc)
                n_poc += 1
            vr = f.meta.get("verify") if isinstance(f.meta, dict) else None
            tail = (vr or {}).get("tail")
            if tail:
                z.writestr(f"verify/{slug}.log", tail)
                n_log += 1
        funnel_line = (f"{fn.get('candidates', 0)} candidates → {fn.get('rejected_judge', 0)} "
                       f"judge-rejected → {fn.get('rejected_exec', 0)} not reproduced → "
                       f"{fn.get('confirmed', 0)} confirmed")
        manifest = (
            t("Basalt — audit evidence bundle", lang) + "\n"
            + t("Tool: {tool}", lang, tool=tool) + "\n"
            + t("Target: {target}", lang, target=target) + "\n"
            + t("Audited commit: {commit}", lang, commit=commit or "—") + "\n"
            + t("Date: {date}", lang, date=date or "—") + "\n"
            + t("Findings: {n}", lang, n=len(findings)) + "\n"
            + t("Funnel: {line}", lang, line=funnel_line) + "\n"
            + t("Integrity hash (SHA-256 of report.json): {h}", lang, h=ehash) + "\n"
        )
        z.writestr("MANIFEST.txt", manifest)
    return {"path": out_path, "findings": len(findings), "pocs": n_poc,
            "logs": n_log, "hash": ehash}
