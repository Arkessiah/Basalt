"""Reachability (govulncheck): parseo del JSON y anotación de findings."""
from __future__ import annotations

from basalt import reachability as R
from basalt.findings import Finding

# Stream JSON de govulncheck: GO-2026-1 se LLAMA (trace con function); GO-2026-2 solo módulo.
_SAMPLE = (
    '{"osv":{"id":"GO-2026-1","aliases":["CVE-2026-39832","GHSA-xxxx"]}}\n'
    '{"osv":{"id":"GO-2026-2","aliases":["CVE-2026-0002"]}}\n'
    '{"finding":{"osv":"GO-2026-1","trace":[{"module":"golang.org/x/crypto","package":"ssh","function":"Foo"}]}}\n'
    '{"finding":{"osv":"GO-2026-2","trace":[{"module":"golang.org/x/crypto"}]}}\n'
)


def test_parse_distingue_llamado_de_solo_presente():
    reachable, present = R.parse_govulncheck_json(_SAMPLE)
    assert "CVE-2026-39832" in reachable and "GO-2026-1" in reachable and "GHSA-xxxx" in reachable
    assert "CVE-2026-0002" not in reachable            # presente pero no llamado
    assert "CVE-2026-0002" in present and "CVE-2026-39832" in present


def test_parse_stream_sin_saltos_de_linea():
    # govulncheck concatena objetos; el parser usa raw_decode, no depende de \n
    txt = _SAMPLE.replace("\n", "")
    reachable, present = R.parse_govulncheck_json(txt)
    assert "CVE-2026-39832" in reachable


def _f(cve: str) -> Finding:
    f = Finding(title="x", severity="high", category="known-vulnerable-dependency",
                target="go.mod", location="go.mod")
    f.meta = {"cves": [cve], "osv_id": "GHSA-y"}
    return f


def test_annotate_reachable_notreachable_unknown():
    reach = R.ReachResult(True,
                          reachable_ids={"CVE-2026-39832"},
                          present_ids={"CVE-2026-39832", "CVE-2026-0002"})
    fr, fnr, funk = _f("CVE-2026-39832"), _f("CVE-2026-0002"), _f("CVE-9999-0")
    R.annotate([fr, fnr, funk], reach)
    assert fr.meta["reachability"] == "reachable"
    assert fnr.meta["reachability"] == "not-reachable"
    assert funk.meta["reachability"] == "unknown"


def test_annotate_unknown_si_govulncheck_no_disponible():
    f = _f("CVE-2026-39832")
    R.annotate([f], R.ReachResult(False, error="no instalado"))
    assert f.meta["reachability"] == "unknown"


def test_scan_sin_govulncheck_devuelve_no_disponible(tmp_path, monkeypatch):
    monkeypatch.setattr(R.shutil, "which", lambda _: None)
    monkeypatch.setattr(R.os.path, "exists", lambda _: False)
    res = R.govulncheck_scan(str(tmp_path))
    assert res.available is False and "govulncheck" in res.error
