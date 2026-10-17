"""N-day por dependencia: parsers de lockfiles + scan contra un OSV falso."""
from __future__ import annotations

import json

import pytest

from basalt import deps


def test_parse_requirements_solo_pinned():
    txt = "requests==2.19.0\nflask>=1.0\n# comentario\n-r otro.txt\nurllib3==1.24.1  # x\n"
    assert deps.parse_requirements(txt) == [("requests", "2.19.0"), ("urllib3", "1.24.1")]


def test_parse_package_lock_v3():
    data = {"packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.11"},
        "node_modules/minimist": {"name": "minimist", "version": "1.2.0"},
    }}
    got = set(deps.parse_package_lock(json.dumps(data)))
    assert ("lodash", "4.17.11") in got
    assert ("minimist", "1.2.0") in got
    assert not any(n == "app" for n, _ in got)          # el proyecto raíz no cuenta


def test_parse_go_mod_bloque_suelto_y_indirect():
    txt = ("module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n"
           "\tgolang.org/x/text v0.3.0 // indirect\n)\n\nrequire github.com/baz/qux v0.1.0\n")
    got = {(n, v): d for n, v, d in deps.parse_go_mod(txt)}
    assert got[("github.com/foo/bar", "1.2.3")] is True
    assert got[("golang.org/x/text", "0.3.0")] is False    # marcada indirect
    assert got[("github.com/baz/qux", "0.1.0")] is True


def test_scan_deduplica_por_cve(tmp_path):
    lock = tmp_path / "go.mod"
    lock.write_text("require golang.org/x/crypto v0.51.0\n")

    class MultiRecordOSV:
        # dos avisos OSV distintos que comparten el MISMO CVE
        def query_batch(self, packages):
            return [["GHSA-aaaa", "GO-2026-0001"]]

        def get_vuln(self, vid):
            sev = "critical" if vid == "GHSA-aaaa" else "high"
            return {"id": vid, "aliases": ["CVE-2026-99999"],
                    "database_specific": {"severity": sev}, "summary": "x"}

    res = deps.scan([("Go", str(lock), "go.mod")], osv=MultiRecordOSV())
    assert len(res.findings) == 1                    # colapsado por CVE
    assert res.findings[0].severity == "critical"    # conserva la mayor severidad
    assert res.findings[0].meta["direct"] is True


def test_scan_marca_indirect(tmp_path):
    lock = tmp_path / "go.mod"
    lock.write_text("require golang.org/x/crypto v0.51.0 // indirect\n")

    class OneOSV:
        def query_batch(self, packages):
            return [["GHSA-x"]]

        def get_vuln(self, vid):
            return {"id": vid, "aliases": ["CVE-2026-1"], "summary": "y",
                    "database_specific": {"severity": "high"}}

    res = deps.scan([("Go", str(lock), "go.mod")], osv=OneOSV())
    assert res.findings[0].meta["direct"] is False
    assert "Transitive" in res.findings[0].description


def test_parse_cargo_lock():
    txt = '[[package]]\nname = "time"\nversion = "0.1.42"\n\n[[package]]\nname = "libc"\nversion = "0.2.66"\n'
    got = deps.parse_cargo_lock(txt)
    assert ("time", "0.1.42") in got and ("libc", "0.2.66") in got


def test_parse_manifest_dedup_y_ecosistema():
    pkgs = deps.parse_manifest("a==1.0\na==1.0\nb==2.0\n", "PyPI")
    assert [(p.name, p.version) for p in pkgs] == [("a", "1.0"), ("b", "2.0")]
    assert all(p.ecosystem == "PyPI" for p in pkgs)


def test_parse_poetry_lock():
    txt = '[[package]]\nname = "requests"\nversion = "2.25.1"\n\n[[package]]\nname = "urllib3"\nversion = "1.26.5"\n'
    assert deps.parse_poetry_lock(txt) == [("requests", "2.25.1"), ("urllib3", "1.26.5")]


def test_parse_pnpm_lock_v9_y_scoped():
    txt = ("packages:\n\n"
           "  /lodash@4.17.11:\n    resolution: {integrity: sha512-x}\n"
           "  '/@babel/core@7.0.0':\n    resolution: {integrity: sha512-y}\n")
    got = set(deps.parse_pnpm_lock(txt))
    assert ("lodash", "4.17.11") in got
    assert ("@babel/core", "7.0.0") in got


def test_parse_yarn_lock_v1_y_scoped():
    txt = ('lodash@^4.17.4, lodash@~4.17.0:\n  version "4.17.11"\n  resolved "x"\n\n'
           '"@babel/core@^7.0.0":\n  version "7.0.1"\n')
    got = set(deps.parse_yarn_lock(txt))
    assert ("lodash", "4.17.11") in got
    assert ("@babel/core", "7.0.1") in got


def test_parse_gemfile_lock():
    txt = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
           "    actionpack (6.0.3)\n      actionview (= 6.0.3)\n    nokogiri (1.10.4)\n")
    got = set(deps.parse_gemfile_lock(txt))
    assert ("actionpack", "6.0.3") in got and ("nokogiri", "1.10.4") in got
    assert ("actionview", "6.0.3") not in got          # es dependencia (6 espacios), no spec


def test_parse_composer_lock():
    data = '{"packages":[{"name":"monolog/monolog","version":"v2.1.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.0.0"}]}'
    got = set(deps.parse_composer_lock(data))
    assert ("monolog/monolog", "2.1.0") in got          # quita la 'v'
    assert ("phpunit/phpunit", "9.0.0") in got


def test_parse_nuget_lock():
    data = '{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.3"}}}}'
    assert deps.parse_nuget_lock(data) == [("Newtonsoft.Json", "12.0.3")]


def test_parse_manifest_despacha_por_fichero():
    # mismo ecosistema npm, distinto fichero -> distinto parser
    pnpm = deps.parse_manifest("  /lodash@4.17.11:\n", "npm", filename="/x/pnpm-lock.yaml")
    assert (pnpm[0].name, pnpm[0].version) == ("lodash", "4.17.11")


class FakeOSV:
    """OSV falso: 'lodash' 4.17.11 es vulnerable (CVE-2019-10744)."""
    def query_batch(self, packages):
        return [["GHSA-jf85-cpcp-j695"] if p.name == "lodash" else [] for p in packages]

    def get_vuln(self, vuln_id):
        return {"id": vuln_id, "aliases": ["CVE-2019-10744"],
                "summary": "Prototype pollution in lodash",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}],
                "references": [{"url": "https://example/advisory"}]}


def test_scan_detecta_nday(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"packages": {
        "node_modules/lodash": {"version": "4.17.11"},
        "node_modules/safe": {"version": "1.0.0"},
    }}))
    res = deps.scan([("npm", str(lock), "package-lock.json")], osv=FakeOSV(), min_votes=2)
    assert res.packages_checked == 2
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.category == "known-vulnerable-dependency"
    assert f.severity == "critical"
    assert f.status == "confirmed" and f.votes == 2
    assert f.meta["provenance"] == "osv-match"
    assert f.meta["cves"] == ["CVE-2019-10744"]
    assert f.meta["fixed"] == ["4.17.12"]


def test_scan_sin_paquetes_no_llama_osv(tmp_path):
    res = deps.scan([("npm", str(tmp_path / "nope.json"), "nope.json")], osv=FakeOSV())
    assert res.findings == [] and res.packages_checked == 0


def test_scan_degrada_si_osv_falla(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("lodash==1.0\n")

    class Broken:
        def query_batch(self, packages):
            raise RuntimeError("sin red")

    res = deps.scan([("PyPI", str(lock), "requirements.txt")], osv=Broken())
    assert res.findings == []
    assert "OSV" in res.error


def test_severity_desde_cvss_score():
    assert deps._severity_of({"severity": [{"score": "9.8"}]}) == "critical"
    assert deps._severity_of({"severity": [{"score": "5.0"}]}) == "medium"
    assert deps._severity_of({}) == "high"          # conservador por defecto


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_query_batch_trocea_en_tandas_de_1000(monkeypatch):
    import httpx
    sizes = []

    def fake_post(url, json, timeout):
        qs = json["queries"]
        sizes.append(len(qs))
        # cada paquete "vulnerable" lleva su nombre como ID para comprobar el orden
        return _Resp({"results": [{"vulns": [{"id": q["package"]["name"]}]} for q in qs]})

    monkeypatch.setattr(httpx, "post", fake_post)
    pkgs = [deps.Package(f"p{i}", "1.0.0", "npm") for i in range(2001)]
    ids = deps.OSVClient().query_batch(pkgs)
    assert sizes == [1000, 1000, 1]
    assert ids == [[f"p{i}"] for i in range(2001)]


def test_query_batch_falla_si_osv_desalinea(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: _Resp({"results": []}))
    with pytest.raises(ValueError):
        deps.OSVClient().query_batch([deps.Package("a", "1.0.0", "npm")])
