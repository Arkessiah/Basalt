"""Reachability de N-day para Go vía `govulncheck` (análisis de call-graph).

Tener una versión vulnerable (match OSV) no implica que el símbolo vulnerable se USE.
`govulncheck` resuelve eso para Go: analiza el grafo de llamadas y marca qué vulns son
realmente alcanzables. Enriquecemos los findings de N-day con `reachability`:
`reachable` (se llama el código vulnerable), `not-reachable` (presente pero no llamado),
`unknown` (govulncheck no lo cubre / no disponible).

No ejecuta el código del target: govulncheck hace análisis estático (aunque compila/typechecks).
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from .findings import Finding


@dataclass
class ReachResult:
    available: bool
    reachable_ids: set = field(default_factory=set)   # ids (GO/CVE/GHSA) con símbolo llamado
    present_ids: set = field(default_factory=set)     # ids que govulncheck conoce para el módulo
    error: str = ""


def parse_govulncheck_json(text: str) -> tuple[set, set]:
    """Parsea el stream JSON de `govulncheck -json`. Devuelve (alcanzables, presentes)
    expandidos a todos los alias (GO-id + CVE + GHSA)."""
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    aliases: dict[str, set] = {}   # GO-id -> {GO-id, CVE..., GHSA...}
    called: set = set()
    reported: set = set()
    while idx < n:
        while idx < n and text[idx] in " \n\r\t":
            idx += 1
        if idx >= n:
            break
        try:
            obj, idx = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        if isinstance(obj.get("osv"), dict):
            o = obj["osv"]
            gid = o.get("id")
            al = set(o.get("aliases") or [])
            if gid:
                al.add(gid)
                aliases[gid] = al
        elif isinstance(obj.get("finding"), dict):
            fnd = obj["finding"]
            gid = fnd.get("osv")
            if not gid:
                continue
            reported.add(gid)
            trace = fnd.get("trace") or []
            if trace and isinstance(trace[0], dict) and trace[0].get("function"):
                called.add(gid)   # el frame más específico es una función -> se llama

    def expand(ids: set) -> set:
        out: set = set()
        for gid in ids:
            out |= aliases.get(gid, {gid})
        return out

    return expand(called), expand(reported)


def govulncheck_scan(module_dir: str, *, timeout: int = 300) -> ReachResult:
    """Ejecuta govulncheck en un módulo Go. Requiere `govulncheck` en PATH o ~/go/bin y red."""
    exe = shutil.which("govulncheck") or os.path.expanduser("~/go/bin/govulncheck")
    if not (exe and os.path.exists(exe)):
        return ReachResult(False, error="govulncheck no instalado (go install golang.org/x/vuln/cmd/govulncheck@latest)")
    try:
        r = subprocess.run([exe, "-json", "./..."], cwd=module_dir,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ReachResult(False, error="govulncheck: timeout")
    except OSError as e:
        return ReachResult(False, error=f"govulncheck: {e}")
    if not r.stdout:
        return ReachResult(False, error=f"govulncheck sin salida: {r.stderr[-300:]}")
    reachable, present = parse_govulncheck_json(r.stdout)
    return ReachResult(True, reachable, present)


def annotate(findings: list[Finding], reach: ReachResult) -> None:
    """Escribe `meta['reachability']` en cada finding según el resultado de govulncheck."""
    for f in findings:
        ids = set(f.meta.get("cves") or [])
        if f.meta.get("osv_id"):
            ids.add(f.meta["osv_id"])
        if not reach.available:
            r = "unknown"
        elif ids & reach.reachable_ids:
            r = "reachable"
        elif ids & reach.present_ids:
            r = "not-reachable"
        else:
            r = "unknown"
        f.meta["reachability"] = r
