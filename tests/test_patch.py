"""Fase blue_patch + grader: aceptación por EJECUCIÓN (build + PoC cerrado + tests).

El grader es autoritativo por ejecución. Se simula con un GradeSandbox cuyo
`reproduce` deja de emitir el sentinel SOLO si el fix aplicado contiene el marcador
`PATCH_CLOSES_POC` (así distinguimos un patch bueno de uno inútil sin Docker real).
"""
from __future__ import annotations

import json

from basalt.findings import Finding, FindingsStore
from basalt.orchestrator import Orchestrator
from basalt.sandbox.base import POC_SENTINEL, RunResult, SandboxUnavailable
from conftest import FakeSandbox, make_settings


class GradeSandbox(FakeSandbox):
    """`reproduce` emite el sentinel salvo que un fichero aplicado lo neutralice."""

    def run(self, cmd, *, workdir="/work", timeout=120, network=False) -> RunResult:
        self.commands.append(cmd)
        fixed = any("PATCH_CLOSES_POC" in c for c in self.files.values())
        return RunResult(0, "" if fixed else POC_SENTINEL, "")


def _confirmed() -> Finding:
    return Finding(title="vuln", severity="high", category="c", target="x",
                   location="x:1", poc=f"echo {POC_SENTINEL}", status="confirmed", votes=2)


def _blue_reply(*, closes: bool) -> str:
    content = "codigo corregido " + ("PATCH_CLOSES_POC" if closes else "sin arreglar")
    return json.dumps({"files": [{"path": "x", "content": content}],
                       "rationale": "fix mínimo"})


def _orch(tmp_path, reply, sandbox_factory):
    cfg = make_settings(reply=reply)
    return Orchestrator(cfg, str(tmp_path), sandbox_factory=sandbox_factory)


def test_patch_bueno_cierra_poc_y_marca_patched(tmp_path):
    orch = _orch(tmp_path, _blue_reply(closes=True), lambda: GradeSandbox())
    f = _confirmed()
    outcomes = orch.patch([f])
    assert len(outcomes) == 1
    o = outcomes[0]
    assert o.accepted is True
    assert o.checks == {"build": True, "poc_closed": True, "tests_pass": True}
    assert f.status == "patched"
    assert o.files == ["x"]


def test_patch_inutil_deja_poc_abierto_no_acepta(tmp_path):
    orch = _orch(tmp_path, _blue_reply(closes=False), lambda: GradeSandbox())
    f = _confirmed()
    o = orch.patch([f])[0]
    assert o.accepted is False
    assert o.checks["poc_closed"] is False
    assert f.status == "confirmed"          # no se promueve


def test_patch_sin_ficheros_se_rechaza(tmp_path):
    reply = json.dumps({"files": [], "rationale": "nada"})
    orch = _orch(tmp_path, reply, lambda: GradeSandbox())
    o = orch.patch([_confirmed()])[0]
    assert o.accepted is False
    assert "aplicable" in o.notes or "ficheros" in o.notes


def test_patch_blue_json_invalido_se_rechaza(tmp_path):
    orch = _orch(tmp_path, "no soy json", lambda: GradeSandbox())
    o = orch.patch([_confirmed()])[0]
    assert o.accepted is False


def test_grade_sandbox_no_disponible_no_acepta(tmp_path):
    def factory():
        raise SandboxUnavailable("docker off")
    orch = _orch(tmp_path, _blue_reply(closes=True), factory)
    o = orch.patch([_confirmed()])[0]
    assert o.accepted is False
    assert "sandbox no disponible" in o.notes


def test_build_roto_rechaza_patch(tmp_path, monkeypatch):
    class BadBuild(GradeSandbox):
        def run(self, cmd, *, workdir="/work", timeout=120, network=False):
            self.commands.append(cmd)
            if cmd == ["build"]:
                return RunResult(1, "", "boom")
            return RunResult(0, "", "")     # reproduce: sin sentinel (cerrado)
    orch = _orch(tmp_path, _blue_reply(closes=True), lambda: BadBuild())
    monkeypatch.setattr(orch.target, "build_cmd", lambda: ["build"])
    o = orch.patch([_confirmed()])[0]
    assert o.accepted is False
    assert o.checks["build"] is False


def test_patched_persiste_en_store(tmp_path):
    store_path = tmp_path / "f.jsonl"
    cfg = make_settings(reply=_blue_reply(closes=True))
    cfg.store_path = str(store_path)
    orch = Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: GradeSandbox())
    f = _confirmed()
    orch.store.add(f)                        # confirmado en el store (voto=1->1)
    orch.patch([f])
    reloaded = FindingsStore(store_path)
    assert reloaded.patched()                # status patched persistido
    assert reloaded.patched()[0].meta["patch"]["files"] == ["x"]
