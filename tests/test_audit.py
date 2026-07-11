"""Flujo audit() con find + verify EN PARALELO y consenso por votos.

Con fakes: red_find devuelve el mismo hallazgo en cada run -> mismo fingerprint ->
los N runs se acumulan como votos al reproducirse -> confirmado si votos >= min_votes.
"""
from __future__ import annotations

import json

from basalt.orchestrator import Orchestrator
from conftest import FakeSandbox, make_settings

RED_REPLY = json.dumps([{
    "title": "overdraft", "severity": "high", "category": "logic",
    "location": "wallet.py:2", "description": "sin validar fondos",
    "poc": "echo BASALT-POC-TRIGGERED",
}])


def _orch(tmp_path, *, red_runs=3, min_votes=2, max_parallel=4, require_execution=True):
    (tmp_path / "wallet.py").write_text("def transfer(b, a):\n    return b - a\n")
    cfg = make_settings(role_replies={"red_find": RED_REPLY, "purple_verify": '{"real": true}'})
    cfg.red_runs = red_runs
    cfg.min_votes = min_votes
    cfg.max_parallel = max_parallel
    cfg.require_execution = require_execution
    cfg.store_path = str(tmp_path / ".hk/findings.jsonl")
    return Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: FakeSandbox())


def test_audit_paralelo_acumula_votos_y_confirma(tmp_path):
    orch = _orch(tmp_path, red_runs=3, min_votes=2)
    rep = orch.audit(max_partitions=1)
    assert rep.total_candidates == 3          # 3 runs x 1 hallazgo
    assert len(rep.confirmed) == 1            # dedupe por fingerprint
    assert rep.confirmed[0].votes == 3        # 3 reproducciones independientes
    assert rep.confirmed[0].status == "confirmed"


def test_audit_no_confirma_si_faltan_votos(tmp_path):
    orch = _orch(tmp_path, red_runs=1, min_votes=2)
    rep = orch.audit(max_partitions=1)
    assert rep.total_candidates == 1
    assert rep.confirmed == []                # 1 voto < min_votes=2


def test_workers_acotado_por_max_parallel(tmp_path):
    orch = _orch(tmp_path, red_runs=10, max_parallel=3)
    assert orch._workers(10) == 3
    assert orch._workers(2) == 2
    assert orch._workers(0) == 1              # nunca menos de 1


def test_audit_serializado_max_parallel_1_mismos_resultados(tmp_path):
    orch = _orch(tmp_path, red_runs=4, min_votes=2, max_parallel=1)
    rep = orch.audit(max_partitions=1)
    assert rep.total_candidates == 4
    assert rep.confirmed[0].votes == 4


def test_embudo_cuenta_confirmados_y_rechazados_por_juez(tmp_path):
    # red_find devuelve 1 hallazgo por run; el juez lo RECHAZA (real: false) -> rejected_judge
    from conftest import FakeProvider
    orch = _orch(tmp_path, red_runs=2, min_votes=2)
    orch.agents["purple_verify"].provider = FakeProvider(reply='{"real": false}')
    rep = orch.audit(max_partitions=1)
    assert rep.total_candidates == 2
    assert rep.confirmed == []
    assert rep.funnel["rejected_judge"] == 2
    assert rep.funnel["rejected_exec"] == 0
    assert rep.funnel["confirmed"] == 0
    # los rechazados quedan persistidos para el informe
    assert len(orch.store.rejected()) == 1          # deduplicado por fingerprint


def test_embudo_confirmados_ok(tmp_path):
    orch = _orch(tmp_path, red_runs=3, min_votes=2)
    rep = orch.audit(max_partitions=1)
    assert rep.funnel["candidates"] == 3
    assert rep.funnel["confirmed"] == 1
    assert rep.funnel["rejected_judge"] == 0
    assert rep.summary().count("→") == 3            # línea de embudo bien formada


def test_prompt_del_red_envuelve_contenido_no_confiable(tmp_path):
    """Spotlighting anti-injection: el código del target va entre delimitadores."""
    from basalt.targets.base import Partition
    orch = _orch(tmp_path, red_runs=1)
    captured = {}
    orig = orch.agents["red_find"].run

    def spy(prompt, **kw):
        captured["prompt"] = prompt
        return orig(prompt, **kw)

    orch.agents["red_find"].run = spy
    orch._find_parallel(Partition(name="x", hint="h", paths=[]), "CODIGO_DEL_TARGET")
    assert "<<<UNTRUSTED_TARGET_CONTENT>>>" in captured["prompt"]
    assert "<<<END_UNTRUSTED_TARGET_CONTENT>>>" in captured["prompt"]
    assert "CODIGO_DEL_TARGET" in captured["prompt"]
