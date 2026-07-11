"""Bundle de evidencia: zip con informe, PoCs, logs y manifiesto con hash."""
from __future__ import annotations

import zipfile

from basalt import bundle
from basalt.findings import Finding


def _f(title="vuln", **kw) -> Finding:
    base = dict(title=title, severity="high", category="auth", target="repo",
                location="a.py:1", status="confirmed", votes=2, poc="print('BASALT-POC-TRIGGERED')")
    base.update(kw)
    f = Finding(**base)
    f.meta["verify"] = {"stage": "exec", "reproduced": True, "tail": "BASALT-POC-TRIGGERED\n"}
    return f


def test_bundle_contiene_informe_poc_log_y_manifiesto(tmp_path):
    out = tmp_path / "ev.zip"
    res = bundle.build_bundle([_f()], target="/repo", out_path=str(out),
                              commit="abc123", date="2026-07-10")
    assert out.exists()
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert "report.md" in names and "report.json" in names and "MANIFEST.txt" in names
        assert any(n.startswith("pocs/") for n in names)
        assert any(n.startswith("verify/") for n in names)
        manifest = z.read("MANIFEST.txt").decode()
        assert "abc123" in manifest and res["hash"] in manifest
        poc = z.read([n for n in names if n.startswith("pocs/")][0]).decode()
        assert "BASALT-POC-TRIGGERED" in poc
    assert res["findings"] == 1 and res["pocs"] == 1 and res["logs"] == 1
    assert len(res["hash"]) == 64


def test_bundle_sin_hallazgos_valido(tmp_path):
    out = tmp_path / "ev.zip"
    res = bundle.build_bundle([], target="/repo", out_path=str(out))
    with zipfile.ZipFile(out) as z:
        assert "report.md" in z.namelist()
    assert res["findings"] == 0 and res["pocs"] == 0


def test_hash_integridad_cambia_con_los_hallazgos(tmp_path):
    a = bundle.build_bundle([_f("a")], target="r", out_path=str(tmp_path / "a.zip"))
    b = bundle.build_bundle([_f("b")], target="r", out_path=str(tmp_path / "b.zip"))
    assert a["hash"] != b["hash"]
