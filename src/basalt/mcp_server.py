"""Servidor MCP de Basalt: expone la auditoría como herramientas para clientes MCP.

Así Claude Code (u otro cliente MCP) puede disparar auditorías y consultar hallazgos como
tools, no solo por CLI. La LÓGICA vive en funciones planas y testables (`tool_*`); la capa
FastMCP (`build_server`) es un wrapper fino que solo se importa al arrancar el servidor,
para no exigir el SDK `mcp` en el resto del proyecto.
"""
from __future__ import annotations
import os
from dataclasses import asdict

DEFAULT_CONFIG = os.environ.get("BASALT_CONFIG", "config/basalt.yaml")


def _store(config: str):
    from .config import store_path_of
    from .findings import FindingsStore
    return FindingsStore(store_path_of(config))


def tool_list_findings(config: str = DEFAULT_CONFIG, status: str = "") -> list[dict]:
    """Lista hallazgos del store, opcionalmente filtrados por status."""
    findings = _store(config).all()
    if status:
        findings = [f for f in findings if f.status == status]
    return [{"fingerprint": f.fingerprint(), "title": f.title, "severity": f.severity,
             "category": f.category, "status": f.status, "votes": f.votes,
             "location": f.location, "provenance": (f.meta or {}).get("provenance")}
            for f in findings]


def tool_get_finding(fingerprint: str, config: str = DEFAULT_CONFIG) -> dict:
    """Detalle completo de un hallazgo por fingerprint."""
    for f in _store(config).all():
        if f.fingerprint() == fingerprint:
            return asdict(f)
    return {"error": f"fingerprint no encontrado: {fingerprint}"}


def tool_get_report(config: str = DEFAULT_CONFIG, fmt: str = "markdown",
                    all_findings: bool = False) -> str:
    """Renderiza el informe (markdown|json) desde el store."""
    from . import report as report_mod
    store = _store(config)
    all_f = store.all()
    findings = all_f if all_findings else [f for f in all_f if f.status in ("confirmed", "patched")]
    return report_mod.render(findings, fmt=fmt, funnel=report_mod.funnel_from_findings(all_f))


def tool_scan_dependencies(path: str, config: str = DEFAULT_CONFIG, kind: str = "") -> dict:
    """Escanea dependencias (lockfiles) vs OSV.dev (N-day). No usa proveedores de modelo."""
    import yaml
    from pathlib import Path
    from .findings import FindingsStore
    from .targets.adapters import make_target
    from . import deps
    from .config import store_path_of
    data = yaml.safe_load(Path(config).read_text()) if Path(config).exists() else {}
    tkind = kind or (data or {}).get("target", {}).get("kind", "generic")
    min_votes = (data or {}).get("audit", {}).get("min_votes", 2)
    target = make_target(tkind, path)
    res = deps.scan(target.dependency_manifests(), min_votes=min_votes)
    store = FindingsStore(store_path_of(config))
    for f in res.findings:
        store.update(f)
    return {"packages_checked": res.packages_checked, "n_day": len(res.findings),
            "error": res.error,
            "findings": [{"package": f.meta.get("package"), "version": f.meta.get("version"),
                          "severity": f.severity, "cves": f.meta.get("cves"),
                          "fixed": f.meta.get("fixed")} for f in res.findings]}


def tool_scan_secrets(path: str, config: str = DEFAULT_CONFIG) -> dict:
    """Escanea secretos hardcodeados en el repo (cross-language). No devuelve los valores."""
    from .findings import FindingsStore
    from .config import store_path_of
    from . import secrets_scan
    res = secrets_scan.scan(path)
    store = FindingsStore(store_path_of(config))
    for f in res.findings:
        store.update(f)
    return {"files_scanned": res.files_scanned, "secrets": len(res.findings),
            "findings": [{"type": f.meta.get("secret_type"), "location": f.location}
                         for f in res.findings]}


_SEV_ORDER = ("info", "low", "medium", "high", "critical")


def tool_gate(config: str = DEFAULT_CONFIG, fail_on: str = "high") -> dict:
    """Evalúa el gate de CI: ¿hay hallazgos confirmados >= severidad?"""
    if fail_on not in _SEV_ORDER:
        return {"error": f"fail_on inválido: {fail_on}"}
    thr = _SEV_ORDER.index(fail_on)
    gated = [f for f in _store(config).all() if f.status in ("confirmed", "patched")]
    over = [f for f in gated if f.severity in _SEV_ORDER and _SEV_ORDER.index(f.severity) >= thr]
    return {"fail_on": fail_on, "passes": len(over) == 0, "over_threshold": len(over)}


def tool_run_audit(path: str, config: str = DEFAULT_CONFIG, max_partitions: int = 0) -> dict:
    """Ejecuta una auditoría (recon→red→purple→verificación por ejecución). Requiere proveedores."""
    from .config import load
    from .orchestrator import Orchestrator
    cfg = load(config)
    orch = Orchestrator(cfg, path)
    rep = orch.audit(max_partitions=max_partitions or None)
    return {"target": rep.target, "funnel": rep.funnel,
            "confirmed": [{"title": f.title, "severity": f.severity, "category": f.category,
                           "location": f.location, "votes": f.votes} for f in rep.confirmed]}


def build_server(config: str = DEFAULT_CONFIG):
    """Construye el servidor FastMCP con las herramientas registradas."""
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("basalt")

    @mcp.tool()
    def list_findings(status: str = "") -> list[dict]:
        """Lista los hallazgos del store (opcional: filtra por status confirmed|patched|rejected)."""
        return tool_list_findings(config, status)

    @mcp.tool()
    def get_finding(fingerprint: str) -> dict:
        """Devuelve el detalle completo de un hallazgo por su fingerprint."""
        return tool_get_finding(fingerprint, config)

    @mcp.tool()
    def get_report(fmt: str = "markdown", all_findings: bool = False) -> str:
        """Renderiza el informe de auditoría (fmt: markdown|json) desde el store."""
        return tool_get_report(config, fmt, all_findings)

    @mcp.tool()
    def scan_dependencies(path: str, kind: str = "") -> dict:
        """Escanea dependencias del repo en `path` contra CVEs conocidos (OSV.dev)."""
        return tool_scan_dependencies(path, config, kind)

    @mcp.tool()
    def run_audit(path: str, max_partitions: int = 0) -> dict:
        """Lanza una auditoría de seguridad del repo en `path` (verificación por ejecución)."""
        return tool_run_audit(path, config, max_partitions)

    @mcp.tool()
    def scan_secrets(path: str) -> dict:
        """Escanea secretos hardcodeados en el repo en `path` (no devuelve los valores)."""
        return tool_scan_secrets(path, config)

    @mcp.tool()
    def gate(fail_on: str = "high") -> dict:
        """Evalúa el gate de CI: ¿hay hallazgos confirmados con severidad >= `fail_on`?"""
        return tool_gate(config, fail_on)

    return mcp
