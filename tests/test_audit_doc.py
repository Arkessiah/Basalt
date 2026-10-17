"""Documento de auditoría (Word + PDF): metadatos, HTML, y generación de ficheros."""
from __future__ import annotations

from pathlib import Path

from basalt import audit_doc
from basalt.findings import Finding


def _f(title="vuln", sev="critical", **kw) -> Finding:
    base = dict(title=title, severity=sev, category="auth", target="repo",
                location="auth.py:3", status="confirmed", votes=2,
                poc="import x\nprint('BASALT-POC-TRIGGERED')")
    base.update(kw)
    f = Finding(**base)
    f.meta["verify"] = {"stage": "exec", "reproduced": True}
    return f


def test_build_meta_defaults_y_hash():
    m = audit_doc.build_meta(None, target="/repo", findings=[_f()], date="2026-07-10")
    assert m.org == "Arkessiah"
    assert m.date == "2026-07-10"
    assert len(m.evidence_hash) == 64          # SHA-256 hex
    assert m.tool.startswith("Basalt v")


def test_build_meta_hash_estable_e_independiente_del_orden():
    a = [_f("a"), _f("b", sev="high")]
    b = [_f("b", sev="high"), _f("a")]
    ha = audit_doc.build_meta(None, target="r", findings=a, date="d").evidence_hash
    hb = audit_doc.build_meta(None, target="r", findings=b, date="d").evidence_hash
    assert ha == hb                            # ordenado antes de hashear


def test_build_meta_respeta_identidad_config():
    m = audit_doc.build_meta({"org": "Acme", "auditor": "Jane Doe"}, target="r",
                             findings=[], date="d")
    assert m.org == "Acme" and m.auditor == "Jane Doe"


def test_render_html_incluye_portada_poc_y_evidencia():
    m = audit_doc.build_meta(None, target="/repo/app", findings=[_f()], date="2026-07-10")
    h = audit_doc.render_html([_f()], m)
    assert "Security Audit Report" in h
    assert "/repo/app" in h
    assert "BASALT-POC-TRIGGERED" in h
    assert "REPRODUCED by execution" in h
    assert m.evidence_hash in h
    assert "&lt;" not in "<b>"                  # sanity


def test_render_html_escapa_contenido_hostil():
    f = _f(title="<script>alert(1)</script>", description="a & b <img>")
    h = audit_doc.render_html([f], audit_doc.build_meta(None, target="r", findings=[f], date="d"))
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


def test_render_html_incluye_embudo_si_hay_funnel():
    m = audit_doc.build_meta(None, target="/repo", findings=[_f()], date="2026-07-10",
                             funnel={"candidates": 9, "rejected_judge": 4,
                                     "rejected_exec": 3, "confirmed": 2})
    h = audit_doc.render_html([_f()], m)
    assert "Verification funnel" in h
    assert "9 candidates" in h and "2 confirmed" in h


def test_render_html_sin_hallazgos_no_rompe():
    h = audit_doc.render_html([], audit_doc.build_meta(None, target="r", findings=[], date="d"))
    assert "No findings were confirmed" in h
    assert "NO FINDINGS" in h


def test_render_docx_genera_fichero(tmp_path):
    p = tmp_path / "a.docx"
    audit_doc.render_docx([_f()], audit_doc.build_meta(None, target="r", findings=[_f()], date="d"), str(p))
    assert p.exists() and p.stat().st_size > 0
    # es un .docx válido (zip) legible por python-docx
    from docx import Document
    doc = Document(str(p))
    text = "\n".join(par.text for par in doc.paragraphs)
    assert "Security Audit Report" in text


def test_generate_escribe_docx_y_pdf(tmp_path):
    base = str(tmp_path / "auditoria")
    out = audit_doc.generate([_f()], audit_doc.build_meta(None, target="r", findings=[_f()], date="d"), base)
    assert Path(out["docx"]).exists()
    assert Path(out["pdf"]).exists()
    assert Path(out["pdf"]).read_bytes()[:5] == b"%PDF-"   # cabecera PDF válida
