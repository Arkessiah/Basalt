"""Informe de auditoría — LANGUAGE-AGNOSTIC (markdown + JSON).

Funciona igual para cualquier proyecto (Go, TS, Rust, Solidity, infra): consume los
`Finding` del store y los renderiza ordenados por severidad. No sabe nada del lenguaje
del objetivo — esa especificidad vive en los adaptadores de `targets/`.
"""
from __future__ import annotations
import json
from dataclasses import asdict

from .findings import Finding, SEVERITIES
from .i18n import t

_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}   # info < ... < critical
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _sorted(findings: list[Finding]) -> list[Finding]:
    # severidad desc, luego más votos primero, luego título
    return sorted(findings, key=lambda f: (-_SEV_ORDER.get(f.severity, -1), -f.votes, f.title))


def counts(findings: list[Finding]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_status: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_status[f.status] = by_status.get(f.status, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_status": by_status}


def funnel_from_findings(findings: list[Finding]) -> dict:
    """Embudo de verificación calculado desde el store (hallazgos únicos por fingerprint)."""
    rejected = [f for f in findings if f.status == "rejected"]
    rj = sum(1 for f in rejected
             if isinstance(f.meta, dict) and (f.meta.get("verify") or {}).get("stage") == "judge")
    return {
        "candidates": len(findings),
        "rejected_judge": rj,
        "rejected_exec": len(rejected) - rj,
        "confirmed": sum(1 for f in findings if f.status in ("confirmed", "patched")),
    }


def to_json(findings: list[Finding], *, target: str = "", funnel: dict | None = None) -> str:
    # JSON es estructurado (claves en inglés, estables para máquinas): no se traduce.
    data = {
        "target": target,
        "funnel": funnel if funnel is not None else funnel_from_findings(findings),
        "summary": counts(findings),
        "findings": [asdict(f) for f in _sorted(findings)],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


def _fence(text: str) -> str:
    """Bloque de código markdown robusto (evita romper si el PoC contiene ```)."""
    ticks = "```"
    while ticks in text:
        ticks += "`"
    return f"{ticks}\n{text.rstrip()}\n{ticks}"


def to_markdown(findings: list[Finding], *, target: str = "", funnel: dict | None = None,
                lang: str = "en") -> str:
    c = counts(findings)
    st = c["by_status"]
    fn = funnel if funnel is not None else funnel_from_findings(findings)
    lines: list[str] = ["# " + t("Security Audit Report — Basalt", lang), ""]
    if target:
        lines.append(f"**Target:** `{target}`")
    status_bits = " · ".join(f"{k}: {v}" for k, v in sorted(st.items())) or t("no findings", lang)
    lines += [t("**Findings:** {total} ({status})", lang, total=c["total"], status=status_bits), ""]

    # Verification funnel (credibility: shows the anti-false-positive filtering).
    lines += [t("**Verification funnel:** {cand} candidates → {rj} rejected by the judge → "
                "{re} not reproduced in sandbox → **{conf} confirmed**.", lang,
                cand=fn.get("candidates", 0), rj=fn.get("rejected_judge", 0),
                re=fn.get("rejected_exec", 0), conf=fn.get("confirmed", 0)), ""]

    # Severity summary table (only non-empty rows).
    present = [s for s in reversed(SEVERITIES) if c["by_severity"].get(s)]
    if present:
        lines += [f"| {t('Severity', lang)} | {t('Total', lang)} |", "|---|---|"]
        lines += [f"| {_SEV_EMOJI.get(s,'')} {s.upper()} | {c['by_severity'][s]} |" for s in present]
        lines.append("")

    if not findings:
        lines.append(t("_No findings to report._", lang))
        return "\n".join(lines)

    # Detalle agrupado por severidad (desc)
    ordered = _sorted(findings)
    current = None
    for f in ordered:
        if f.severity != current:
            current = f.severity
            lines += ["", f"## {_SEV_EMOJI.get(f.severity,'')} {f.severity.upper()}", ""]
        lines.append(f"### {f.title}  ·  `{f.category}`  ·  _{f.status}_")
        meta_bits = []
        if f.location:
            meta_bits.append(t("**Location:** `{loc}`", lang, loc=f.location))
        meta_bits.append(t("**Votes:** {n}", lang, n=f.votes))
        if f.finder:
            meta_bits.append(f"**Finder:** {f.finder}")
        lines.append(" · ".join(meta_bits))
        if f.description:
            lines += ["", f.description]
        if f.poc:
            lines += ["", t("**PoC:**", lang), _fence(f.poc)]
        patch = f.meta.get("patch") if isinstance(f.meta, dict) else None
        if patch:
            checks = patch.get("checks", {})
            chk = " ".join(f"{k}={'✔' if v else '✗'}" for k, v in checks.items())
            files = ", ".join(patch.get("files", [])) or "—"
            lines += ["", t("**Patch:** {rationale}", lang, rationale=patch.get("rationale", "")),
                      t("- Files: `{files}`", lang, files=files), f"- Grader: {chk}"]
        prov = f.meta.get("provenance") if isinstance(f.meta, dict) else None
        if prov == "osv-match":
            cves = ", ".join(f.meta.get("cves", [])) or f.meta.get("osv_id", "")
            fixed = ", ".join(f.meta.get("fixed", []))
            dep_kind = t("direct", lang) if f.meta.get("direct", True) else t("transitive (indirect)", lang)
            line = t("- Provenance: **OSV match** ({cves}) · {dep_kind} dependency",
                     lang, cves=cves, dep_kind=dep_kind)
            if fixed:
                line += t(" · fixed in `{fixed}`", lang, fixed=fixed)
            lines.append(line)
            reach = f.meta.get("reachability")
            if reach:
                rlabel = {"reachable": t("**reachable** (vulnerable symbol is called)", lang),
                          "not-reachable": t("not reachable (present but not called)", lang),
                          "unknown": t("reachability undetermined", lang)}.get(reach, reach)
                lines.append(t("- Reachability (govulncheck): {label}", lang, label=rlabel))
            refs = f.meta.get("references", [])
            if refs:
                lines.append("- Refs: " + " · ".join(refs[:3]))
        elif prov == "pattern-match":
            lines.append(t("- Detection: pattern match (the secret value is NOT included in the report).", lang))
        else:
            vr = f.meta.get("verify") if isinstance(f.meta, dict) else None
            if vr and not patch:
                label = {"tool-proven": t("proven by execution (tool-proven)", lang),
                         "model-asserted": t("asserted by the model (model-asserted)", lang)
                         }.get(prov, "")
                lines.append(t("- Verification: {label} · reproduced={rep}", lang,
                               label=label or ("stage=" + str(vr.get("stage"))),
                               rep=vr.get("reproduced")))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render(findings: list[Finding], *, fmt: str = "markdown", target: str = "",
           funnel: dict | None = None, lang: str = "en") -> str:
    if fmt == "json":
        return to_json(findings, target=target, funnel=funnel)
    if fmt in ("markdown", "md"):
        return to_markdown(findings, target=target, funnel=funnel, lang=lang)
    if fmt == "html":
        from . import audit_doc          # import perezoso: audit_doc importa de report
        meta = audit_doc.build_meta(None, target=target, findings=findings, date="",
                                    funnel=funnel, lang=lang)
        return audit_doc.render_html(findings, meta)
    raise ValueError(f"unknown format: {fmt!r} (use 'markdown', 'json' or 'html')")
