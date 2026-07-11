"""Modo CI-gate + DX: umbral de severidad, init, informe HTML."""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from basalt.cli import app, _fails_gate
from basalt.findings import Finding, FindingsStore
from basalt import report as report_mod

runner = CliRunner()


def _f(sev: str) -> Finding:
    return Finding(title="x", severity=sev, category="c", target="t", location="t:1",
                   status="confirmed", votes=2)


def test_fails_gate_umbral():
    fs = [_f("low"), _f("medium")]
    assert _fails_gate(fs, "high") is False
    assert _fails_gate(fs + [_f("critical")], "high") is True
    assert _fails_gate(fs, "low") is True
    assert _fails_gate(fs, "") is False


def test_fails_gate_umbral_invalido():
    with pytest.raises(Exception):
        _fails_gate([_f("high")], "urgente")


def _cfg_con_store(tmp_path, sevs):
    store_path = tmp_path / ".hk" / "f.jsonl"
    s = FindingsStore(store_path)
    for i, sev in enumerate(sevs):
        s.add(Finding(title=f"f{i}", severity=sev, category="c", target="t",
                      location=f"t:{i}", status="confirmed"))
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"store_path: {store_path}\n")
    return str(cfg)


def test_gate_command_falla_con_critico(tmp_path):
    cfg = _cfg_con_store(tmp_path, ["low", "critical"])
    res = runner.invoke(app, ["gate", "-c", cfg, "--fail-on", "high"])
    assert res.exit_code == 2
    assert "FALLA" in res.stdout


def test_gate_command_ok_sin_altos(tmp_path):
    cfg = _cfg_con_store(tmp_path, ["low", "medium"])
    res = runner.invoke(app, ["gate", "-c", cfg, "--fail-on", "high"])
    assert res.exit_code == 0
    assert "OK" in res.stdout


def test_init_crea_config(tmp_path):
    out = tmp_path / "hk.yaml"
    res = runner.invoke(app, ["init", "-o", str(out)])
    assert res.exit_code == 0 and out.exists()
    assert "default_providers" in out.read_text()
    # no sobrescribe sin --force
    res2 = runner.invoke(app, ["init", "-o", str(out)])
    assert res2.exit_code == 1
    res3 = runner.invoke(app, ["init", "-o", str(out), "--force"])
    assert res3.exit_code == 0


def test_report_html():
    html = report_mod.render([_f("high")], fmt="html", target="/repo")
    assert "<!doctype html>" in html.lower()
    assert "Security Audit Report" in html


def test_report_formato_invalido():
    with pytest.raises(ValueError):
        report_mod.render([], fmt="xml")
