"""Informe language-agnostic: markdown + JSON, orden por severidad, PoC y parche."""
from __future__ import annotations

import json

from basalt import report
from basalt.findings import Finding


def _f(title, sev, **kw) -> Finding:
    base = dict(title=title, severity=sev, category="cat", target="repo",
                location="f.go:10", status="confirmed", votes=2, poc="echo BASALT-POC-TRIGGERED")
    base.update(kw)
    return Finding(**base)


def test_counts_agrega_por_severidad_y_status():
    fs = [_f("a", "high"), _f("b", "high"), _f("c", "low", status="patched")]
    c = report.counts(fs)
    assert c["total"] == 3
    assert c["by_severity"]["high"] == 2
    assert c["by_status"] == {"confirmed": 2, "patched": 1}


def test_markdown_ordena_por_severidad_desc():
    md = report.to_markdown([_f("baja", "low"), _f("critica", "critical")], target="repo")
    assert md.index("CRITICAL") < md.index("LOW")
    assert "critica" in md and "baja" in md


def test_markdown_incluye_poc_y_target():
    md = report.to_markdown([_f("x", "high", poc="run exploit")], target="/repo/x")
    assert "/repo/x" in md
    assert "run exploit" in md
    assert "**PoC:**" in md


def test_markdown_muestra_parche_si_patched():
    f = _f("v", "high", status="patched")
    f.meta["patch"] = {"files": ["auth.go"], "rationale": "valida token",
                       "checks": {"build": True, "poc_closed": True, "tests_pass": True}}
    md = report.to_markdown([f])
    assert "valida token" in md
    assert "auth.go" in md
    assert "poc_closed=✔" in md


def test_markdown_vacio_no_rompe():
    md = report.to_markdown([], target="repo")
    assert "No findings" in md


def test_fence_escapa_backticks_en_poc():
    poc = "```py\nexploit\n```"
    md = report.to_markdown([_f("x", "high", poc=poc)])
    # el bloque exterior debe usar más backticks que el interior
    assert "````" in md


def test_json_valido_y_ordenado():
    out = report.to_json([_f("baja", "low"), _f("alta", "critical")], target="repo")
    data = json.loads(out)
    assert data["target"] == "repo"
    assert data["summary"]["total"] == 2
    assert data["findings"][0]["title"] == "alta"    # critical primero


def test_funnel_from_findings_clasifica_por_stage():
    conf = _f("a", "high")
    rej_judge = _f("b", "low", status="rejected")
    rej_judge.meta["verify"] = {"stage": "judge", "reproduced": False}
    rej_exec = _f("c", "low", status="rejected")
    rej_exec.meta["verify"] = {"stage": "exec", "reproduced": False}
    fn = report.funnel_from_findings([conf, rej_judge, rej_exec])
    assert fn == {"candidates": 3, "rejected_judge": 1, "rejected_exec": 1, "confirmed": 1}


def test_markdown_incluye_linea_de_embudo():
    md = report.to_markdown([_f("a", "high")],
                            funnel={"candidates": 5, "rejected_judge": 2,
                                    "rejected_exec": 1, "confirmed": 2})
    assert "Verification funnel" in md
    assert "5 candidates" in md and "2 confirmed" in md


def test_json_incluye_funnel():
    out = report.to_json([_f("a", "critical")], target="r")
    data = json.loads(out)
    assert "funnel" in data and data["funnel"]["confirmed"] == 1


def test_render_dispatch_y_formato_invalido():
    assert report.render([], fmt="json") .startswith("{")
    assert report.render([], fmt="md").startswith("#")
    try:
        report.render([], fmt="xml")
        assert False, "debería lanzar"
    except ValueError:
        pass
