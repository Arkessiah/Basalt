"""i18n: inglés por defecto, español por configuración, fallback al EN."""
from __future__ import annotations

from basalt import i18n, report as report_mod
from basalt.findings import Finding


def _f() -> Finding:
    f = Finding(title="SQLi", severity="critical", category="sql-injection", target="app.py",
                location="app.py:10", status="confirmed", votes=2, poc="payload")
    f.meta["verify"] = {"stage": "exec", "reproduced": True}
    f.meta["provenance"] = "tool-proven"
    return f


def test_t_default_en_y_override_es():
    assert i18n.t("Findings", "en") == "Findings"
    assert i18n.t("Findings", "es") == "Hallazgos"
    # clave sin override -> devuelve el propio EN (default sin tocar nada)
    assert i18n.t("Some untranslated label", "es") == "Some untranslated label"


def test_t_formato():
    assert i18n.t("**Votes:** {n}", "es", n=3) == "**Votos:** 3"


def test_normalize():
    assert i18n.normalize(None) == "en"
    assert i18n.normalize("ES") == "es"
    assert i18n.normalize("fr") == "en"          # idioma no soportado -> default


def test_report_en_por_defecto():
    md = report_mod.to_markdown([_f()], funnel={"candidates": 2, "confirmed": 1})
    assert "Security Audit Report" in md
    assert "Verification funnel" in md
    assert "Location" in md and "Votes" in md
    assert "Embudo" not in md


def test_report_es_por_config():
    md = report_mod.to_markdown([_f()], funnel={"candidates": 2, "confirmed": 1}, lang="es")
    assert "Informe de Auditoría de Seguridad" in md
    assert "Embudo de verificación" in md
    assert "Ubicación" in md and "Votos" in md
    assert "proven by execution" not in md         # el label también se traduce
    assert "probado por ejecución" in md


def test_html_respeta_lang():
    from basalt import audit_doc
    meta_en = audit_doc.build_meta(None, target="r", findings=[_f()], date="d", lang="en")
    meta_es = audit_doc.build_meta(None, target="r", findings=[_f()], date="d", lang="es")
    assert 'lang="en"' in audit_doc.render_html([_f()], meta_en)
    assert "Executive summary" in audit_doc.render_html([_f()], meta_en)
    assert "Resumen ejecutivo" in audit_doc.render_html([_f()], meta_es)
