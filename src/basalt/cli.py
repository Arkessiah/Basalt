"""CLI de Basalt.  `basalt providers` · `basalt audit <path>` · `basalt report`."""
from __future__ import annotations
from pathlib import Path
import typer
from rich import print as rprint
from .providers import registry

app = typer.Typer(help="Basalt — purple-team de agentes para auditar seguridad.")

_SEV_ORDER = ("info", "low", "medium", "high", "critical")


def _fails_gate(findings, fail_on: str) -> bool:
    """True si algún hallazgo alcanza o supera el umbral de severidad (para romper CI)."""
    if not fail_on:
        return False
    if fail_on not in _SEV_ORDER:
        raise typer.BadParameter(f"--fail-on debe ser uno de {list(_SEV_ORDER)}")
    thr = _SEV_ORDER.index(fail_on)
    return any(f.severity in _SEV_ORDER and _SEV_ORDER.index(f.severity) >= thr for f in findings)


@app.command()
def providers():
    """Lista los backends de modelo registrados (capa conectable)."""
    rprint("[bold]Proveedores registrados:[/bold]", ", ".join(registry.available()))


@app.command()
def doctor(config: str = typer.Option("config/basalt.yaml", "-c", "--config")):
    """Diagnóstico: config, proveedores por rol, y herramientas externas (Docker, govulncheck)."""
    import shutil
    import os
    from .config import load
    cfg = load(config)
    rprint("[bold]Proveedores por rol:[/bold]")
    for role, prov in cfg.roles.items():
        rprint(f"  {role:14s} -> {prov.name}:{prov.model or '(default)'}  "
                f"[{'green]OK' if prov.health() else 'red]NO RESPONDE'}[/]")
    rprint("[bold]Herramientas externas:[/bold]")
    docker = shutil.which("docker")
    rprint(f"  docker          [{'green]OK' if docker else 'yellow]ausente (verificación por ejecución no funcionará)'}[/]")
    gv = shutil.which("govulncheck") or (os.path.expanduser("~/go/bin/govulncheck")
                                         if os.path.exists(os.path.expanduser("~/go/bin/govulncheck")) else None)
    rprint(f"  govulncheck     [{'green]OK' if gv else 'yellow]ausente (reachability Go no disponible)'}[/]")
    rprint(f"[bold]Objetivo:[/bold] kind={cfg.target_kind} · store={cfg.store_path} · "
           f"require_execution={cfg.require_execution} · recon={cfg.recon}")


@app.command()
def audit(
    path: str = typer.Argument(..., help="Ruta del repo/objetivo a auditar."),
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    max_partitions: int = typer.Option(0, "--max", help="Limitar nº de particiones (0=todas)."),
    patch: bool = typer.Option(False, "--patch/--no-patch",
                               help="Tras confirmar, lanzar blue_patch + grader por ejecución."),
    report_path: str = typer.Option("", "--report", help="Volcar informe a FICHERO al terminar."),
    fmt: str = typer.Option("markdown", "--format", help="Formato del informe: markdown | json."),
    doc_out: str = typer.Option("", "--doc", help="Generar documento de auditoría (Word+PDF) con este basename."),
    bundle_out: str = typer.Option("", "--bundle", help="Generar bundle de evidencia (.zip) en esta ruta."),
    scan_deps: bool = typer.Option(False, "--deps/--no-deps", help="Además, escanear dependencias vs OSV (N-day)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Estimar coste (nº de llamadas) sin auditar."),
    fail_on: str = typer.Option("", "--fail-on", help="Salir con código≠0 si hay hallazgos >= severidad (info|low|medium|high|critical). Para CI."),
    changed: bool = typer.Option(False, "--changed", help="Auditar solo los ficheros cambiados vs --base (para PRs)."),
    base: str = typer.Option("main", "--base", help="Rama/ref base para --changed."),
):
    """Lanza el purple-team contra un objetivo."""
    from .config import load
    from .orchestrator import Orchestrator
    cfg = load(config)
    orch = Orchestrator(cfg, path)

    if dry_run:
        plan = orch.plan(max_partitions=max_partitions or None)
        rprint("[bold]== Plan (dry-run, sin llamar a modelos) ==[/bold]")
        rprint(f"  Objetivo: {plan['target']}  ·  lenguaje: {plan['kind']}")
        rprint(f"  Particiones: {plan['partitions_audited']} de {plan['partitions_total']} "
               f"· red_runs: {plan['red_runs']}")
        rprint(f"  Llamadas de find estimadas: [bold]{plan['find_calls']}[/bold] "
               f"(+{plan['recon_calls']} recon)")
        rprint(f"  [dim]{plan['note']}[/dim]")
        return

    if scan_deps:
        res = orch.scan_dependencies()
        if res.error:
            rprint(f"[yellow]Scan de dependencias degradado:[/yellow] {res.error}")
        else:
            rprint(f"[bold]Dependencias:[/bold] {res.packages_checked} revisadas · "
                   f"[red]{len(res.findings)} N-day[/red]")
    only_paths = None
    if changed:
        only_paths = _changed_files(path, base)
        rprint(f"[bold]Modo --changed:[/bold] {len(only_paths)} fichero(s) cambiados vs {base}")
        if not only_paths:
            rprint("[yellow]Sin cambios detectados (o git falló): no hay nada que auditar.[/yellow]")

    def _progress(i, n, name):
        rprint(f"  [dim]audit[/dim] [{i}/{n}] {name}")
    rep = orch.audit(max_partitions=max_partitions or None, on_partition=_progress,
                     only_paths=only_paths)
    rprint("\n[bold]== Informe ==[/bold]")
    rprint(rep.summary())
    for f in rep.confirmed:
        rprint(f"  [red]•[/red] [{f.severity.upper()}] {f.title} ({f.category}) @ {f.location} "
               f"· votos={f.votes}")

    if report_path:
        from . import report as report_mod
        show = [f for f in orch.store.all() if f.status in ("confirmed", "patched")]
        content = report_mod.render(show, fmt=fmt, target=orch.target.root, funnel=rep.funnel,
                                    lang=cfg.lang)
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(content, encoding="utf-8")
        rprint(f"\n[green]Informe escrito:[/green] {report_path}")

    if doc_out:
        from . import audit_doc
        conf_findings = [f for f in orch.store.all() if f.status in ("confirmed", "patched")]
        scope = ", ".join(sorted({f.category for f in conf_findings})) or "—"
        meta = audit_doc.build_meta(cfg.identity, target=orch.target.root, findings=conf_findings,
                                    date=_today(), commit=_target_commit(orch.target.root),
                                    scope=scope, funnel=rep.funnel, lang=cfg.lang)
        written = audit_doc.generate(conf_findings, meta, doc_out)
        for k, v in written.items():
            rprint(f"[green]{k.upper()} de auditoría:[/green] {v}")

    if bundle_out:
        from . import bundle as bundle_mod
        conf_findings = [f for f in orch.store.all() if f.status in ("confirmed", "patched")]
        res = bundle_mod.build_bundle(conf_findings, target=orch.target.root, out_path=bundle_out,
                                      funnel=rep.funnel, commit=_target_commit(orch.target.root),
                                      date=_today(), lang=cfg.lang)
        rprint(f"[green]Bundle de evidencia:[/green] {res['path']} ({res['pocs']} PoCs, hash {res['hash'][:12]}…)")

    if patch or cfg.auto_patch:
        rprint("\n[bold]== Blue patch + grader ==[/bold]")
        outcomes = orch.patch(rep.confirmed)
        if not outcomes:
            rprint("  (sin hallazgos confirmados que parchear)")
        for o in outcomes:
            mark = "[green]✔ patched[/green]" if o.accepted else "[yellow]✗ rechazado[/yellow]"
            checks = " ".join(f"{k}={'✔' if v else '✗'}" for k, v in o.checks.items())
            rprint(f"  {mark} {o.finding.title} — {checks}"
                   + (f" · {', '.join(o.files)}" if o.files else "")
                   + (f"  [dim]{o.notes}[/dim]" if o.notes else ""))

    if fail_on:
        gated = [f for f in orch.store.all() if f.status in ("confirmed", "patched")]
        if _fails_gate(gated, fail_on):
            rprint(f"\n[red]GATE: hallazgos de severidad >= {fail_on}. Saliendo con código 2.[/red]")
            raise typer.Exit(code=2)
        rprint(f"\n[green]GATE OK: sin hallazgos >= {fail_on}.[/green]")


@app.command()
def gate(
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    fail_on: str = typer.Option("high", "--fail-on", help="Umbral: info|low|medium|high|critical."),
):
    """Sale con código 2 si el store tiene hallazgos confirmados >= severidad. Para pipelines CI."""
    from .config import store_path_of
    from .findings import FindingsStore
    store = FindingsStore(store_path_of(config))
    gated = [f for f in store.all() if f.status in ("confirmed", "patched")]
    if _fails_gate(gated, fail_on):
        n = sum(1 for f in gated if _SEV_ORDER.index(f.severity) >= _SEV_ORDER.index(fail_on))
        rprint(f"[red]GATE FALLA:[/red] {n} hallazgo(s) >= {fail_on}.")
        raise typer.Exit(code=2)
    rprint(f"[green]GATE OK:[/green] sin hallazgos >= {fail_on}.")


@app.command()
def init(
    output: str = typer.Option("config/basalt.yaml", "-o", "--output", help="Ruta del config a crear."),
    force: bool = typer.Option(False, "--force", help="Sobrescribir si ya existe."),
):
    """Crea un config/basalt.yaml de arranque."""
    from .config import DEFAULT_CONFIG_YAML
    p = Path(output)
    if p.exists() and not force:
        rprint(f"[yellow]Ya existe {output}[/yellow] (usa --force para sobrescribir).")
        raise typer.Exit(code=1)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    rprint(f"[green]Config creada:[/green] {output}. Ajusta providers/target y lanza `basalt doctor -c {output}`.")


@app.command()
def secrets(
    path: str = typer.Argument(..., help="Ruta del repo a escanear."),
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
):
    """Escanea secretos hardcodeados (cross-language). Sin LLM ni sandbox; no guarda valores."""
    import yaml
    from .findings import FindingsStore
    from . import secrets_scan
    data = yaml.safe_load(Path(config).read_text()) if Path(config).exists() else {}
    store_path = (data or {}).get("store_path", ".basalt/findings.jsonl")
    store = FindingsStore(store_path)
    res = secrets_scan.scan(path)
    for f in res.findings:
        store.update(f)
    rprint(f"[bold]Ficheros escaneados:[/bold] {res.files_scanned} · "
           f"[red]secretos potenciales:[/red] {len(res.findings)}")
    for f in res.findings:
        rprint(f"  [red]•[/red] {f.meta.get('secret_type')} @ {f.location}")


@app.command()
def deps(
    path: str = typer.Argument(..., help="Ruta del repo/objetivo a escanear."),
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    kind: str = typer.Option("", "--kind", help="Forzar lenguaje (por defecto: el de la config)."),
    reachability: bool = typer.Option(
        False, "--reachability", help="Go: confirmar reachability con govulncheck (requiere go+red)."),
):
    """Escanea dependencias (lockfiles) contra CVEs conocidos (OSV.dev). N-day, sin sandbox."""
    # No requiere proveedores de modelo: lee solo el YAML crudo (como `report`).
    import os
    import yaml
    from .findings import FindingsStore
    from .targets.adapters import make_target
    from . import deps as deps_mod
    data = yaml.safe_load(Path(config).read_text()) if Path(config).exists() else {}
    tkind = kind or (data or {}).get("target", {}).get("kind", "generic")
    store_path = (data or {}).get("store_path", ".basalt/findings.jsonl")
    min_votes = (data or {}).get("audit", {}).get("min_votes", 2)
    target = make_target(tkind, path)
    store = FindingsStore(store_path)
    manifests = target.dependency_manifests()
    rprint(f"[bold]Manifiestos encontrados:[/bold] {len(manifests)}  "
           + (" · ".join(f"{e}:{rel}" for e, _, rel in manifests) or "(ninguno)"))
    res = deps_mod.scan(manifests, min_votes=min_votes)

    if reachability and any(e == "Go" for e, _, _ in manifests):
        from . import reachability as rmod
        merged = rmod.ReachResult(False)
        for d in {os.path.dirname(ab) for e, ab, _ in manifests if e == "Go"}:
            rr = rmod.govulncheck_scan(d)
            if rr.available:
                merged.available = True
                merged.reachable_ids |= rr.reachable_ids
                merged.present_ids |= rr.present_ids
            elif not merged.available:
                merged.error = rr.error
        rmod.annotate(res.findings, merged)
        if not merged.available:
            rprint(f"[yellow]Reachability no disponible:[/yellow] {merged.error}")

    for f in res.findings:
        store.update(f)
    if res.error:
        rprint(f"[yellow]Scan degradado:[/yellow] {res.error}")
    rprint(f"[bold]Paquetes revisados:[/bold] {res.packages_checked} · "
           f"[red]N-day encontrados:[/red] {len(res.findings)}")
    _rmark = {"reachable": "[red]REACHABLE[/red]", "not-reachable": "[green]no alcanzable[/green]",
              "unknown": "[dim]reach?[/dim]"}
    for f in sorted(res.findings, key=lambda x: x.severity, reverse=True):
        cves = ", ".join(f.meta.get("cves", [])) or f.meta.get("osv_id", "")
        reach = f.meta.get("reachability")
        rprint(f"  [red]•[/red] [{f.severity.upper()}] {f.meta.get('package')}@{f.meta.get('version')}"
               + ("" if f.meta.get("direct", True) else " (indirect)")
               + f" — {cves}" + (f" · fixed: {', '.join(f.meta['fixed'])}" if f.meta.get("fixed") else "")
               + (f" · {_rmark.get(reach, '')}" if reach else ""))


def _changed_files(path: str, base: str) -> set[str]:
    """Ficheros cambiados vs `base` (rutas absolutas). Vacío si git falla."""
    import os
    import subprocess
    try:
        r = subprocess.run(["git", "-C", path, "diff", "--name-only", f"{base}...HEAD"],
                           capture_output=True, text=True, timeout=15)
        rels = r.stdout.split() if r.returncode == 0 else []
        if not rels:   # fallback: cambios sin commitear vs base
            r2 = subprocess.run(["git", "-C", path, "diff", "--name-only", base],
                                capture_output=True, text=True, timeout=15)
            rels = r2.stdout.split() if r2.returncode == 0 else []
    except Exception:
        return set()
    # git devuelve rutas relativas a la raíz del repo, no necesariamente a `path`
    try:
        top = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        top = path
    return {os.path.join(top, rel) for rel in rels}


def _target_commit(path: str) -> str:
    import subprocess
    try:
        r = subprocess.run(["git", "-C", path, "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _today() -> str:
    from datetime import date
    return date.today().isoformat()


@app.command()
def doc(
    target: str = typer.Argument("", help="Ruta del objetivo auditado (para portada/commit)."),
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    output: str = typer.Option("auditoria", "-o", "--output", help="Basename de salida (sin extensión)."),
    fmt: str = typer.Option("both", "--format", help="both | docx | pdf."),
    all_findings: bool = typer.Option(False, "--all", help="Incluir candidatos/rechazados."),
):
    """Genera el DOCUMENTO de auditoría profesional (Word + PDF) como prueba. Language-agnostic."""
    from .config import store_path_of, load
    from .findings import FindingsStore
    from . import audit_doc, report as report_mod
    # Identidad: intenta config completa; si falla (sin proveedores), lee solo el YAML crudo.
    identity = {}
    try:
        identity = load(config).identity
    except Exception:
        import yaml
        from pathlib import Path as _P
        identity = (yaml.safe_load(_P(config).read_text()) or {}).get("identity", {})
    store = FindingsStore(store_path_of(config))
    all_f = store.all()
    findings = all_f if all_findings else [f for f in all_f if f.status in ("confirmed", "patched")]
    scope = ", ".join(sorted({f.category for f in findings})) or "—"
    from .config import lang_of
    meta = audit_doc.build_meta(identity, target=target, findings=findings,
                                date=_today(), commit=_target_commit(target) if target else "",
                                scope=scope, funnel=report_mod.funnel_from_findings(all_f),
                                lang=lang_of(config))
    if fmt == "docx":
        audit_doc.render_docx(findings, meta, f"{output}.docx")
        written = {"docx": f"{output}.docx"}
    elif fmt == "pdf":
        audit_doc.to_pdf(audit_doc.render_html(findings, meta), f"{output}.pdf")
        written = {"pdf": f"{output}.pdf"}
    else:
        written = audit_doc.generate(findings, meta, output)
    for k, v in written.items():
        rprint(f"[green]{k.upper()} escrito:[/green] {v}  ({len(findings)} hallazgos)")


@app.command()
def bundle(
    target: str = typer.Argument("", help="Ruta del objetivo (para el manifiesto/commit)."),
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    output: str = typer.Option("evidence.zip", "-o", "--output", help="Ruta del zip de evidencia."),
    all_findings: bool = typer.Option(False, "--all", help="Incluir candidatos/rechazados."),
):
    """Empaqueta un BUNDLE de evidencia (.zip): informe + PoCs + logs + manifiesto con hash."""
    from .config import store_path_of
    from .findings import FindingsStore
    from . import bundle as bundle_mod, report as report_mod
    store = FindingsStore(store_path_of(config))
    all_f = store.all()
    findings = all_f if all_findings else [f for f in all_f if f.status in ("confirmed", "patched")]
    from .config import lang_of
    res = bundle_mod.build_bundle(findings, target=target, out_path=output,
                                  funnel=report_mod.funnel_from_findings(all_f),
                                  commit=_target_commit(target) if target else "", date=_today(),
                                  lang=lang_of(config))
    rprint(f"[green]Bundle escrito:[/green] {res['path']}  "
           f"({res['findings']} hallazgos · {res['pocs']} PoCs · {res['logs']} logs)")
    rprint(f"  [dim]hash SHA-256:[/dim] {res['hash']}")


@app.command()
def report(
    config: str = typer.Option("config/basalt.yaml", "-c", "--config"),
    fmt: str = typer.Option("markdown", "--format", help="markdown | json."),
    output: str = typer.Option("", "-o", "--output", help="Fichero de salida (vacío = stdout)."),
    all_findings: bool = typer.Option(
        False, "--all", help="Incluir candidatos/rechazados (por defecto solo confirmed/patched)."),
):
    """Genera un informe (markdown/JSON) desde el store de hallazgos. Language-agnostic."""
    from .config import store_path_of, lang_of
    from .findings import FindingsStore
    from . import report as report_mod
    store = FindingsStore(store_path_of(config))
    all_f = store.all()
    findings = all_f if all_findings else [f for f in all_f if f.status in ("confirmed", "patched")]
    # El embudo se calcula SIEMPRE del store completo (incluye rechazados), aunque no se listen.
    content = report_mod.render(findings, fmt=fmt, target="",
                                funnel=report_mod.funnel_from_findings(all_f), lang=lang_of(config))
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(content, encoding="utf-8")
        rprint(f"[green]Informe escrito:[/green] {output} ({len(findings)} hallazgos)")
    else:
        print(content)


@app.command(name="mcp-serve")
def mcp_serve(config: str = typer.Option("config/basalt.yaml", "-c", "--config")):
    """Arranca el servidor MCP (stdio): expone list_findings/get_report/scan_dependencies/run_audit."""
    from .mcp_server import build_server
    rprint("[bold]Basalt MCP server[/bold] (stdio) — herramientas: "
           "list_findings, get_finding, get_report, scan_dependencies, run_audit")
    build_server(config).run()


if __name__ == "__main__":
    app()
