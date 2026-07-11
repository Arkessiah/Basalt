"""Verificación en dos etapas (juez LLM + reproducción por ejecución).

Usa FakeProvider (juez) y FakeSandbox (ejecución) para no depender de modelos ni Docker.
La FakeSandbox devuelve por stdout el contenido escrito, así que un PoC que contiene
el sentinel 'dispara' la reproducción.
"""
from __future__ import annotations


from basalt.findings import Finding
from basalt.orchestrator import Orchestrator
from basalt.targets.base import Partition
from basalt.sandbox.base import POC_SENTINEL, SandboxUnavailable
from conftest import make_settings


def _finding(poc: str) -> Finding:
    return Finding(title="t", severity="high", category="c", target="x",
                   location="x:1", poc=poc)


def _part() -> Partition:
    return Partition(name="x", paths=[])


def _orch(tmp_path, reply='{"real": true}', sandbox_factory=None, **cfg_over):
    cfg = make_settings(reply=reply, **cfg_over)
    return Orchestrator(cfg, str(tmp_path), sandbox_factory=sandbox_factory)


def test_juez_ok_y_poc_dispara_sentinel_confirma(tmp_path, fake_sandbox_factory):
    orch = _orch(tmp_path, sandbox_factory=fake_sandbox_factory)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._verify(f, _part(), "ctx") is True
    assert f.meta["verify"]["reproduced"] is True


def test_juez_ok_pero_poc_sin_sentinel_no_confirma(tmp_path, fake_sandbox_factory):
    orch = _orch(tmp_path, sandbox_factory=fake_sandbox_factory)
    f = _finding(poc="echo nada")
    assert orch._verify(f, _part(), "ctx") is False
    assert f.meta["verify"]["reproduced"] is False


def test_juez_rechaza_no_toca_sandbox(tmp_path):
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        raise AssertionError("no debería crear sandbox si el juez rechaza")

    orch = _orch(tmp_path, reply='{"real": false}', sandbox_factory=factory)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._verify(f, _part(), "ctx") is False
    assert calls["n"] == 0


def test_provenance_tool_proven_al_reproducir(tmp_path, fake_sandbox_factory):
    orch = _orch(tmp_path, sandbox_factory=fake_sandbox_factory)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._verify(f, _part(), "ctx") is True
    assert f.meta["provenance"] == "tool-proven"


def test_provenance_model_asserted_si_no_hay_ejecucion(tmp_path):
    def factory():
        raise AssertionError("no debería tocar sandbox")
    orch = _orch(tmp_path, sandbox_factory=factory, require_execution=False)
    f = _finding(poc="x")
    assert orch._verify(f, _part(), "ctx") is True
    assert f.meta["provenance"] == "model-asserted"


def test_require_execution_false_confia_en_juez(tmp_path):
    def factory():
        raise AssertionError("no debería tocar sandbox con require_execution=False")

    orch = _orch(tmp_path, sandbox_factory=factory, require_execution=False)
    f = _finding(poc="lo que sea")
    assert orch._verify(f, _part(), "ctx") is True
    assert f.meta["verify"]["stage"] == "judge-only"


def test_sandbox_no_disponible_no_confirma(tmp_path):
    def factory():
        raise SandboxUnavailable("docker off")

    orch = _orch(tmp_path, sandbox_factory=factory)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._verify(f, _part(), "ctx") is False
    assert "sandbox no disponible" in f.meta["verify"]["reason"]


def test_reproduce_falla_si_target_sin_reproduce_cmd(tmp_path, fake_sandbox_factory, monkeypatch):
    orch = _orch(tmp_path, sandbox_factory=fake_sandbox_factory)
    monkeypatch.setattr(orch.target, "reproduce_cmd", lambda: None)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._reproduce(f, _part()) is False
    assert f.meta["verify"]["reason"] == "target sin reproduce_cmd"


def test_reintenta_cold_start_y_luego_reproduce(tmp_path):
    from conftest import FakeSandbox
    from basalt.sandbox.base import RunResult

    class ColdStartOnce(FakeSandbox):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def run(self, cmd, *, workdir="/work", timeout=120, network=False):
            self.attempts += 1
            if self.attempts == 1:                       # 1er run: cold-start (vacío, exit 1)
                return RunResult(1, "", "")
            return RunResult(0, POC_SENTINEL, "")        # reintento: reproduce

    sb = ColdStartOnce()
    orch = _orch(tmp_path, sandbox_factory=lambda: sb)
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._verify(f, _part(), "ctx") is True
    assert sb.attempts == 2                              # reintentó exactamente una vez


def test_no_reintenta_si_hay_salida_real(tmp_path):
    from conftest import FakeSandbox
    from basalt.sandbox.base import RunResult

    class RealFailure(FakeSandbox):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def run(self, cmd, *, workdir="/work", timeout=120, network=False):
            self.attempts += 1
            return RunResult(1, "", "Traceback: boom")   # fallo real (hay stderr) -> no reintenta

    sb = RealFailure()
    orch = _orch(tmp_path, sandbox_factory=lambda: sb)
    f = _finding(poc="x")
    assert orch._verify(f, _part(), "ctx") is False
    assert sb.attempts == 1


def test_build_falla_no_confirma(tmp_path, monkeypatch):
    from conftest import FakeSandbox
    from basalt.sandbox.base import RunResult

    class FailingBuildSandbox(FakeSandbox):
        def run(self, cmd, *, workdir="/work", timeout=120, network=False):
            self.commands.append(cmd)
            if cmd == ["build"]:
                return RunResult(1, "", "boom")          # build roto
            return RunResult(0, "\n".join(self.files.values()), "")

    orch = _orch(tmp_path, sandbox_factory=lambda: FailingBuildSandbox())
    monkeypatch.setattr(orch.target, "build_cmd", lambda: ["build"])
    f = _finding(poc=f"echo {POC_SENTINEL}")
    assert orch._reproduce(f, _part()) is False
    assert f.meta["verify"]["stage"] == "build"
