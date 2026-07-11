"""Integración end-to-end del flujo completo con dobles (sin modelos reales ni Docker):
recon → red → verificación por ejecución → embudo → blue patch + grader → informe → gate.

Un solo sandbox falso sirve para verificar (el PoC dispara el sentinel) y para gradar el
patch (el fix contiene el marcador PATCH_CLOSES → el PoC deja de disparar)."""
from __future__ import annotations

import json

from basalt.orchestrator import Orchestrator
from basalt.sandbox.base import POC_SENTINEL, RunResult
from basalt.findings import FindingsStore
from basalt import report as report_mod
from conftest import FakeSandbox, make_settings


class IntegrationSandbox(FakeSandbox):
    """`reproduce` emite el sentinel salvo que un fichero aplicado lo neutralice (fix)."""
    def run(self, cmd, *, workdir="/work", timeout=120, network=False) -> RunResult:
        self.commands.append(cmd)
        fixed = any("PATCH_CLOSES" in c for c in self.files.values())
        return RunResult(0, "" if fixed else POC_SENTINEL, "")


RED = json.dumps([{
    "title": "auth bypass en login", "severity": "critical", "category": "auth-bypass",
    "location": "auth.py:2", "description": "login() acepta prefijo vacío -> bypass total.",
    "poc": f"import auth\nif auth.login(''):\n    print('{POC_SENTINEL}')",
}])
RECON = json.dumps([{"name": "auth.py", "risk": "high", "hint": "auth-bypass en login()"}])
BLUE = json.dumps({"files": [{"path": "auth.py", "content": "def login(t):\n    # PATCH_CLOSES\n    return bool(t) and t == SECRET\n"}],
                   "rationale": "exige token no vacío e igualdad estricta"})


def _orchestrator(tmp_path):
    (tmp_path / "auth.py").write_text("def login(t):\n    return SECRET.startswith(t)\n")
    cfg = make_settings(role_replies={
        "recon": RECON, "red_find": RED, "purple_verify": '{"real": true}', "blue_patch": BLUE,
    })
    cfg.target_kind = "python"
    cfg.red_runs = 3
    cfg.min_votes = 2
    cfg.store_path = str(tmp_path / ".hk" / "findings.jsonl")
    return Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: IntegrationSandbox())


def test_flujo_completo_audit_patch_report_gate(tmp_path):
    orch = _orchestrator(tmp_path)

    # 1) AUDIT: recon prioriza, red encuentra, verificación por ejecución confirma con votos
    seen = []
    rep = orch.audit(on_partition=lambda i, n, name: seen.append(name))
    assert seen == ["auth.py"]                          # recon dejó la partición de riesgo
    assert rep.total_candidates == 3                    # 3 red_runs
    assert len(rep.confirmed) == 1
    conf = rep.confirmed[0]
    assert conf.category == "auth-bypass" and conf.votes == 3
    assert conf.meta["provenance"] == "tool-proven"     # reproducido por ejecución
    assert rep.funnel == {"rejected_judge": 0, "rejected_exec": 0,
                          "confirmed_reproductions": 3, "candidates": 3, "confirmed": 1}

    # 2) PATCH + GRADER: el fix cierra el PoC (sentinel desaparece) → patched
    outcomes = orch.patch(rep.confirmed)
    assert len(outcomes) == 1 and outcomes[0].accepted is True
    assert outcomes[0].checks["poc_closed"] is True
    assert conf.status == "patched"

    # 3) INFORME: persistido y renderizable, refleja el hallazgo y el embudo
    reloaded = FindingsStore(orch.cfg.store_path)
    assert reloaded.patched() and reloaded.patched()[0].meta["patch"]["files"] == ["auth.py"]
    md = report_mod.render(reloaded.all(), fmt="markdown", target=str(tmp_path), funnel=rep.funnel)
    assert "auth bypass en login" in md
    assert "Verification funnel" in md
    html = report_mod.render(reloaded.all(), fmt="html", target=str(tmp_path))
    assert "<!doctype html>" in html.lower()

    # 4) GATE: hay un crítico → debe fallar el umbral 'high'
    from basalt.cli import _fails_gate
    assert _fails_gate(reloaded.all(), "high") is True
    assert _fails_gate(reloaded.all(), "critical") is True


def test_flujo_sin_hallazgos_gate_ok(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    cfg = make_settings(role_replies={"recon": "[]", "red_find": "[]"})
    cfg.target_kind = "python"
    cfg.store_path = str(tmp_path / ".hk" / "f.jsonl")
    orch = Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: IntegrationSandbox())
    rep = orch.audit()
    assert rep.total_candidates == 0 and rep.confirmed == []
    from basalt.cli import _fails_gate
    assert _fails_gate(orch.store.all(), "low") is False
