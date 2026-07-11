"""Escaneo de secretos: encuentra por tipo+ubicación sin filtrar el valor."""
from __future__ import annotations

from basalt import secrets_scan
from basalt.redact import find_secrets


def test_find_secrets_devuelve_tipo_y_linea():
    text = "line1\nAKIAIOSFODNN7EXAMPLE\npassword = \"hunter2superlong\"\n"
    got = dict((label, line) for label, line in find_secrets(text))
    assert got["aws-access-key"] == 2
    assert got["password"] == 3


def test_scan_produce_findings_sin_valor(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "clean.py").write_text("x = 1\n")
    res = secrets_scan.scan(str(tmp_path))
    assert res.files_scanned >= 2
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.category == "hardcoded-secrets"
    assert f.meta["provenance"] == "pattern-match"
    assert f.meta["secret_type"] == "aws-access-key"
    assert f.location.endswith("app.py:1")
    assert f.status == "confirmed"
    # el valor real NO aparece en ningún campo del finding
    blob = f"{f.title} {f.description} {f.poc} {f.meta}"
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_scan_excluye_directorios_ruido(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text('t="ghp_' + "a" * 36 + '"\n')
    (tmp_path / "src.js").write_text('t="ghp_' + "b" * 36 + '"\n')
    res = secrets_scan.scan(str(tmp_path))
    locs = {f.location for f in res.findings}
    assert any("src.js" in x for x in locs)
    assert not any("node_modules" in x for x in locs)


def test_scan_sin_secretos(tmp_path):
    (tmp_path / "a.py").write_text("def f():\n    return 42\n")
    res = secrets_scan.scan(str(tmp_path))
    assert res.findings == []
