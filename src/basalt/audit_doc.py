"""Documento de auditoría profesional (Word + PDF) — sirve como PRUEBA de la auditoría.

Fuente canónica: un HTML con estilo profesional (portada, metadatos, resumen ejecutivo,
metodología, fichas de hallazgo con PoC y evidencia de reproducción, anexo). El PDF se
genera de ese HTML con WeasyPrint; el Word con python-docx. Ambos comparten el mismo
modelo de contenido (`_prepare`), así no divergen.

`identity` (org/auditor/logo/contacto) es configurable en el YAML (default Arkessiah).
"""
from __future__ import annotations
import hashlib
import html
import json
from dataclasses import dataclass, field, asdict

from .findings import Finding, SEVERITIES
from .report import counts, _sorted
from .i18n import t

_SEV_COLOR = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
              "low": "#1976d2", "info": "#607d8b"}


def _tool_version() -> str:
    try:
        from importlib.metadata import version
        return version("basalt")
    except Exception:
        return "0.x"


@dataclass
class AuditMeta:
    org: str = "Arkessiah"
    auditor: str = ""
    contact: str = ""
    logo: str = ""                 # ruta a imagen (opcional)
    target: str = ""
    scope: str = ""                # lenguajes / particiones auditadas
    date: str = ""                 # YYYY-MM-DD (lo inyecta el llamante; el módulo no usa reloj)
    commit: str = ""               # hash del commit del objetivo (evidencia)
    tool: str = field(default_factory=lambda: f"Basalt v{_tool_version()}")
    sandbox: str = "Docker, network disabled (--network none), execution-based verification"
    confidentiality: str = "CONFIDENTIAL — internal / authorized client use"
    evidence_hash: str = ""        # SHA-256 de los hallazgos (integridad de la prueba)
    funnel: dict = field(default_factory=dict)  # embudo de verificación (credibilidad)
    lang: str = "en"


def build_meta(identity: dict | None, *, target: str, findings: list[Finding],
               date: str, commit: str = "", scope: str = "", funnel: dict | None = None,
               lang: str = "en") -> AuditMeta:
    identity = identity or {}
    payload = json.dumps([asdict(f) for f in _sorted(findings)], ensure_ascii=False, sort_keys=True)
    ehash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return AuditMeta(
        org=identity.get("org", "Arkessiah"),
        auditor=identity.get("auditor", ""),
        contact=identity.get("contact", ""),
        logo=identity.get("logo", ""),
        target=target,
        scope=scope,
        date=date,
        commit=commit,
        evidence_hash=ehash,
        funnel=funnel or {},
        lang=lang,
    )


def _funnel_line(fn: dict, lang: str = "en") -> str:
    return t("{cand} candidates → {rj} rejected by the judge → {re} not reproduced in sandbox "
             "→ {conf} confirmed", lang, cand=fn.get("candidates", 0), rj=fn.get("rejected_judge", 0),
             re=fn.get("rejected_exec", 0), conf=fn.get("confirmed", 0))


# Metodología y disclaimer: EN por defecto (fuente), ES override. Bloques largos → aquí.
_METHODOLOGY_EN = [
    ("Recon", "Maps the attack surface and splits the target into auditable units."),
    ("Red (find × N)", "Several independent agents look for vulnerabilities and produce a "
                       "reproducible PoC; consensus voting filters out hallucinations."),
    ("Purple (verify)", "Adversarial judge (skeptical pre-filter) that demands a credible PoC."),
    ("Execution-based verification", "The PoC is reproduced in a clean, isolated sandbox; a finding "
                                     "is only CONFIRMED if the exploit actually fires (sentinel marker). "
                                     "This is the anti-false-positive core: another model's opinion is "
                                     "not enough."),
    ("Blue (patch) + Grader", "A minimal fix is proposed and GRADED by execution: green build, closed "
                              "PoC, and no test regressions."),
]
_METHODOLOGY_ES = [
    ("Recon", "Mapea la superficie de ataque y particiona el objetivo en unidades auditables."),
    ("Red (find × N)", "Varios agentes independientes buscan vulnerabilidades y producen un PoC "
                       "reproducible; el consenso por votos filtra alucinaciones."),
    ("Purple (verify)", "Juez adversarial (pre-filtro escéptico) que exige un PoC creíble."),
    ("Verificación por ejecución", "El PoC se reproduce en un sandbox limpio y aislado; un hallazgo "
                                   "solo se CONFIRMA si el exploit se dispara realmente (marca de "
                                   "sentinel). Es el núcleo anti-falsos-positivos: no basta la opinión "
                                   "de otro modelo."),
    ("Blue (patch) + Grader", "Se propone un fix mínimo y se GRADÚA por ejecución: build verde, PoC "
                              "cerrado y tests sin regresión."),
]
_DISCLAIMER_EN = ("This report is an automated security screening (purple-team of AI agents with "
                  "execution-based verification). It does NOT replace a manual professional audit for "
                  "code with real funds or compliance requirements. Confirmed findings were reproduced "
                  "by execution in an isolated environment on the stated date.")
_DISCLAIMER_ES = ("Este informe es un screening de seguridad automatizado (purple-team de agentes de IA "
                  "con verificación por ejecución). NO sustituye una auditoría profesional manual para "
                  "código con fondos reales o requisitos de cumplimiento. Los hallazgos confirmados "
                  "fueron reproducidos por ejecución en un entorno aislado en la fecha indicada.")


def _methodology(lang: str):
    return _METHODOLOGY_ES if lang == "es" else _METHODOLOGY_EN


def _disclaimer(lang: str) -> str:
    return _DISCLAIMER_ES if lang == "es" else _DISCLAIMER_EN


def _prepare(findings: list[Finding]) -> dict:
    ordered = _sorted(findings)
    return {"ordered": ordered, "counts": counts(findings)}


# --------------------------------------------------------------------------- HTML/PDF
def _css() -> str:
    return """
@page { size: A4; margin: 2.2cm 2cm 2.4cm 2cm;
  @bottom-center { content: "__FOOTER__ · " counter(page) " / " counter(pages);
                   font-size: 8pt; color: #888; } }
* { box-sizing: border-box; }
body { font-family: "Helvetica Neue", Arial, sans-serif; color: #1a1a1a; font-size: 10.5pt; line-height: 1.5; }
h1 { font-size: 20pt; margin: 0 0 4px; } h2 { font-size: 14pt; border-bottom: 2px solid #222; padding-bottom: 4px; margin-top: 26px; }
h3 { font-size: 11.5pt; margin: 18px 0 4px; }
.cover { height: 24cm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
.cover .org { font-size: 26pt; font-weight: 700; letter-spacing: 2px; }
.cover .title { font-size: 30pt; font-weight: 800; margin: 18px 0 6px; }
.cover .sub { font-size: 13pt; color: #444; }
.cover .meta { margin-top: 40px; font-size: 11pt; color: #333; }
.cover .conf { margin-top: 30px; font-size: 9pt; color: #b00020; font-weight: 700; letter-spacing: 1px; }
table.meta { border-collapse: collapse; width: 100%; margin: 8px 0 4px; }
table.meta td { border: 1px solid #ddd; padding: 6px 9px; font-size: 9.5pt; vertical-align: top; }
table.meta td.k { background: #f5f5f5; font-weight: 600; width: 28%; }
.chips { margin: 10px 0; } .chip { display: inline-block; color: #fff; padding: 3px 10px; border-radius: 12px;
  font-size: 9pt; font-weight: 700; margin-right: 6px; }
.badge { display: inline-block; color: #fff; padding: 1px 8px; border-radius: 4px; font-size: 8.5pt; font-weight: 700; }
.finding { border: 1px solid #e0e0e0; border-left: 5px solid #999; border-radius: 4px; padding: 12px 14px;
  margin: 12px 0; page-break-inside: avoid; }
.finding .loc { color: #555; font-size: 9pt; margin: 2px 0 8px; }
pre { background: #0f1117; color: #e6e6e6; padding: 10px 12px; border-radius: 4px; font-size: 8.5pt;
  white-space: pre-wrap; word-break: break-word; overflow-x: auto; }
.ok { color: #2e7d32; font-weight: 700; } .no { color: #b00020; font-weight: 700; }
.disc { font-size: 8.5pt; color: #666; border-top: 1px solid #ddd; padding-top: 8px; margin-top: 24px; }
"""


def render_html(findings: list[Finding], meta: AuditMeta) -> str:
    d = _prepare(findings)
    c = d["counts"]
    esc = html.escape
    lang = meta.lang

    def sev_chip(s):
        return (f'<span class="chip" style="background:{_SEV_COLOR.get(s,"#777")}">'
                f'{s.upper()}: {c["by_severity"].get(s,0)}</span>')

    present = [s for s in reversed(SEVERITIES) if c["by_severity"].get(s)]
    chips = ("".join(sev_chip(s) for s in present)
             or f'<span class="chip" style="background:#2e7d32">{t("NO FINDINGS", lang)}</span>')

    meta_rows = [
        (t("Target", lang), esc(meta.target)),
        (t("Scope", lang), esc(meta.scope or "—")),
        (t("Date", lang), esc(meta.date)),
        (t("Audited commit", lang), esc(meta.commit or "—")),
        (t("Tool", lang), esc(meta.tool)),
        (t("Isolation", lang), esc(meta.sandbox)),
        (t("Auditor", lang), esc(meta.auditor or meta.org)),
        (t("Evidence hash (SHA-256)", lang), esc(meta.evidence_hash)),
    ]
    meta_tbl = "".join(f'<tr><td class="k">{k}</td><td>{v}</td></tr>' for k, v in meta_rows)

    method = "".join(f"<li><b>{esc(name)}.</b> {esc(desc)}</li>" for name, desc in _methodology(lang))

    fparts = []
    for f in d["ordered"]:
        color = _SEV_COLOR.get(f.severity, "#999")
        badge = f'<span class="badge" style="background:{color}">{esc(f.severity.upper())}</span>'
        block = [f'<div class="finding" style="border-left-color:{color}">',
                 f'<h3>{badge} {esc(f.title)} <span style="color:#888;font-weight:400">'
                 f'· {esc(f.category)} · {esc(f.status)} · {t("votes", lang)} {f.votes}</span></h3>']
        if f.location or f.finder:
            block.append(f'<div class="loc">{esc(f.location)}'
                         + (f' · finder: {esc(f.finder)}' if f.finder else "") + "</div>")
        if f.description:
            block.append(f"<p>{esc(f.description)}</p>")
        if f.poc:
            block.append(f'<p><b>{t("Proof of concept (PoC):", lang)}</b></p><pre>{esc(f.poc)}</pre>')
        prov = f.meta.get("provenance") if isinstance(f.meta, dict) else None
        if prov == "osv-match":
            cves = ", ".join(f.meta.get("cves", [])) or f.meta.get("osv_id", "")
            fixed = ", ".join(f.meta.get("fixed", []))
            block.append(f'<p><b>{t("Evidence: ", lang)}</b><span class="ok">{t("Match on OSV.dev", lang)}</span> '
                         f'({esc(cves)})'
                         + (f'{t(" · fixed in ", lang)}<code>{esc(fixed)}</code>' if fixed else '')
                         + f'. {t("Known vulnerability (N-day), confirmed by version, not by PoC.", lang)}</p>')
        else:
            vr = f.meta.get("verify") if isinstance(f.meta, dict) else None
            if vr:
                rep = vr.get("reproduced")
                cls = "ok" if rep else "no"
                verdict = t("REPRODUCED by execution", lang) if rep else t("not reproduced", lang)
                block.append(f'<p><b>{t("Reproduction evidence:", lang)}</b> '
                             f'<span class="{cls}">{verdict}</span>'
                             f'{t(" (stage={stage}).", lang, stage=esc(str(vr.get("stage"))))}</p>')
        patch = f.meta.get("patch") if isinstance(f.meta, dict) else None
        if patch:
            checks = " · ".join(f'{k}: {"✔" if v else "✗"}' for k, v in patch.get("checks", {}).items())
            files = ", ".join(patch.get("files", [])) or "—"
            block.append(f'<p><b>{t("Remediation: ", lang)}</b>{esc(patch.get("rationale",""))}<br>'
                         f'{t("Files: ", lang)}<code>{esc(files)}</code> · Grader: {esc(checks)}</p>')
        block.append("</div>")
        fparts.append("\n".join(block))
    findings_html = ("\n".join(fparts) if fparts
                     else f"<p><i>{t('No findings were confirmed.', lang)}</i></p>")

    logo = f'<img src="{esc(meta.logo)}" style="max-height:90px;margin-bottom:20px">' if meta.logo else ""
    footer = t("Basalt — audit report", lang)
    css = _css().replace("__FOOTER__", footer)
    funnel_html = ""
    if meta.funnel:
        tail = t(". Confirmed findings were verified by executing the PoC in an isolated sandbox "
                 "or by matching against the OSV vulnerability database (dependency N-day).", lang)
        funnel_html = (f'<p><b>{esc(t("Verification funnel: ", lang))}</b>'
                       f'{esc(_funnel_line(meta.funnel, lang))}{esc(tail)}</p>')

    return f"""<!doctype html><html lang="{esc(lang)}"><head><meta charset="utf-8"><style>{css}</style></head><body>
<section class="cover">
  {logo}
  <div class="org">{esc(meta.org)}</div>
  <div class="title">{t("Security Audit Report", lang)}</div>
  <div class="sub">{esc(meta.target) or "—"}</div>
  <div class="meta">{t("Date", lang)}: {esc(meta.date)}<br>{t("Auditor", lang)}: {esc(meta.auditor or meta.org)}<br>
    {t("Tool", lang)}: {esc(meta.tool)}</div>
  <div class="conf">{esc(t(meta.confidentiality, lang))}</div>
</section>

<h1>{t("Executive summary", lang)}</h1>
<p>{t("Total confirmed findings: {n}.", lang, n=c['total'])}</p>
<div class="chips">{chips}</div>
{funnel_html}

<h2>{t("Audit metadata", lang)}</h2>
<table class="meta">{meta_tbl}</table>

<h2>{t("Methodology", lang)}</h2>
<p>{t("Audit performed with a purple-team of AI agents and execution-based verification:", lang)}</p>
<ol>{method}</ol>

<h2>{t("Findings", lang)}</h2>
{findings_html}

<p class="disc">{esc(_disclaimer(lang))}</p>
</body></html>"""


def to_pdf(html_str: str, path: str) -> None:
    from weasyprint import HTML
    HTML(string=html_str).write_pdf(path)


# --------------------------------------------------------------------------- Word
def render_docx(findings: list[Finding], meta: AuditMeta, path: str) -> None:
    from docx import Document
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    d = _prepare(findings)
    c = d["counts"]
    lang = meta.lang
    doc = Document()
    doc.core_properties.title = t("Security Audit Report", lang)
    doc.core_properties.author = meta.auditor or meta.org

    def _centered(text: str, *, size: int, bold: bool = False, rgb: RGBColor | None = None):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(text)
        run.bold = bold
        run.font.size = Pt(size)
        if rgb is not None:
            run.font.color.rgb = rgb
        return p

    # Cover
    _centered(meta.org, size=24, bold=True)
    _centered(t("Security Audit Report", lang), size=20, bold=True)
    _centered(meta.target or "—", size=13)
    _centered(t(meta.confidentiality, lang), size=9, bold=True, rgb=RGBColor(0xB0, 0x00, 0x20))
    doc.add_page_break()

    # Executive summary
    doc.add_heading(t("Executive summary", lang), level=1)
    doc.add_paragraph(t("Total confirmed findings: {n}.", lang, n=c["total"]))
    if meta.funnel:
        fp = doc.add_paragraph()
        fp.add_run(t("Verification funnel: ", lang)).bold = True
        fp.add_run(_funnel_line(meta.funnel, lang)
                   + t(". Confirmed findings were verified by executing the PoC in an isolated "
                       "sandbox or by matching against the OSV vulnerability database "
                       "(dependency N-day).", lang))
    present = [s for s in reversed(SEVERITIES) if c["by_severity"].get(s)]
    if present:
        tbl = doc.add_table(rows=1, cols=2)
        tbl.style = "Light Grid Accent 1"
        tbl.rows[0].cells[0].text = t("Severity", lang)
        tbl.rows[0].cells[1].text = t("Total", lang)
        for s in present:
            row = tbl.add_row().cells
            row[0].text = s.upper()
            row[1].text = str(c["by_severity"][s])

    # Metadata
    doc.add_heading(t("Audit metadata", lang), level=1)
    meta_rows = [(t("Target", lang), meta.target), (t("Scope", lang), meta.scope or "—"),
                 (t("Date", lang), meta.date), (t("Audited commit", lang), meta.commit or "—"),
                 (t("Tool", lang), meta.tool), (t("Isolation", lang), meta.sandbox),
                 (t("Auditor", lang), meta.auditor or meta.org),
                 (t("Evidence hash (SHA-256)", lang), meta.evidence_hash)]
    mt = doc.add_table(rows=0, cols=2)
    mt.style = "Light List Accent 1"
    for k, v in meta_rows:
        cells = mt.add_row().cells
        cells[0].text = k
        cells[1].text = str(v)

    # Methodology
    doc.add_heading(t("Methodology", lang), level=1)
    for name, desc in _methodology(lang):
        p = doc.add_paragraph(style="List Number")
        p.add_run(f"{name}. ").bold = True
        p.add_run(desc)

    # Findings
    doc.add_heading(t("Findings", lang), level=1)
    if not d["ordered"]:
        doc.add_paragraph(t("No findings were confirmed.", lang))
    for f in d["ordered"]:
        h = doc.add_heading(level=2)
        rb = h.add_run(f"[{f.severity.upper()}] {f.title}")
        col = _SEV_COLOR.get(f.severity, "#999").lstrip("#")
        rb.font.color.rgb = RGBColor(int(col[0:2], 16), int(col[2:4], 16), int(col[4:6], 16))
        subp = doc.add_paragraph()
        subp.add_run(f"{f.category} · {f.status} · {t('votes', lang)} {f.votes}"
                     + (f" · {f.location}" if f.location else "")).italic = True
        if f.description:
            doc.add_paragraph(f.description)
        if f.poc:
            doc.add_paragraph().add_run(t("Proof of concept (PoC):", lang)).bold = True
            pre = doc.add_paragraph(f.poc)
            pre.style = "No Spacing"
            for run in pre.runs:
                run.font.name = "Courier New"
                run.font.size = Pt(8)
        prov = f.meta.get("provenance") if isinstance(f.meta, dict) else None
        if prov == "osv-match":
            cves = ", ".join(f.meta.get("cves", [])) or f.meta.get("osv_id", "")
            fixed = ", ".join(f.meta.get("fixed", []))
            pv = doc.add_paragraph()
            pv.add_run(t("Evidence: ", lang)).bold = True
            rr = pv.add_run(f'{t("Match on OSV.dev", lang)} ({cves})'
                            + (t(" · fixed in {fixed}", lang, fixed=fixed) if fixed else "")
                            + ". " + t("Known vulnerability (N-day), confirmed by version.", lang))
            rr.font.color.rgb = RGBColor(0x2E, 0x7D, 0x32)
        else:
            vr = f.meta.get("verify") if isinstance(f.meta, dict) else None
            if vr:
                rep = vr.get("reproduced")
                pv = doc.add_paragraph()
                pv.add_run(t("Reproduction evidence:", lang) + " ").bold = True
                rr = pv.add_run(t("REPRODUCED by execution", lang) if rep else t("not reproduced", lang))
                rr.font.color.rgb = RGBColor(0x2E, 0x7D, 0x32) if rep else RGBColor(0xB0, 0x00, 0x20)
        patch = f.meta.get("patch") if isinstance(f.meta, dict) else None
        if patch:
            checks = " · ".join(f'{k}: {"OK" if v else "X"}' for k, v in patch.get("checks", {}).items())
            pp = doc.add_paragraph()
            pp.add_run(t("Remediation: ", lang)).bold = True
            pp.add_run(f"{patch.get('rationale','')}  [Grader: {checks}]")

    doc.add_paragraph()
    disc = doc.add_paragraph(_disclaimer(lang))
    for run in disc.runs:
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)
    doc.save(path)


def generate(findings: list[Finding], meta: AuditMeta, basename: str) -> dict:
    """Genera <basename>.docx y <basename>.pdf. Devuelve las rutas escritas."""
    html_str = render_html(findings, meta)
    out = {}
    docx_path = f"{basename}.docx"
    render_docx(findings, meta, docx_path)
    out["docx"] = docx_path
    pdf_path = f"{basename}.pdf"
    to_pdf(html_str, pdf_path)
    out["pdf"] = pdf_path
    return out
