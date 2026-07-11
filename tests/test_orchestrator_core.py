"""Núcleo del flujo LLM: parseo robusto, recon (prioriza), dry-run/plan, progreso."""
from __future__ import annotations

import json

from basalt.orchestrator import _extract_json_array, Orchestrator
from basalt.targets.base import Partition
from conftest import make_settings


def test_extract_array_directo():
    assert _extract_json_array('[{"a":1}]') == [{"a": 1}]


def test_extract_array_con_fence_json():
    txt = 'aquí tienes:\n```json\n[{"title":"x"}]\n```\ngracias'
    assert _extract_json_array(txt) == [{"title": "x"}]


def test_extract_array_objeto_envoltorio():
    assert _extract_json_array('{"findings": [{"title":"x"}]}') == [{"title": "x"}]
    assert _extract_json_array('{"results": [1,2]}') == [1, 2]


def test_extract_array_con_prosa_alrededor():
    assert _extract_json_array('bla bla [1, 2, 3] fin') == [1, 2, 3]


def test_extract_array_none_si_no_hay():
    assert _extract_json_array("no hay json aquí") is None
    assert _extract_json_array("") is None


def _orch(tmp_path, recon_reply):
    cfg = make_settings(role_replies={"recon": recon_reply})
    cfg.store_path = str(tmp_path / ".hk/f.jsonl")
    return Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: None)


def _parts():
    return [Partition("a.py", paths=[], hint="h1"), Partition("b.py", paths=[], hint="h2"),
            Partition("c.py", paths=[], hint="h3")]


def test_recon_reordena_por_riesgo(tmp_path):
    reply = json.dumps([{"name": "c.py", "risk": "high"},
                        {"name": "a.py", "risk": "medium"},
                        {"name": "b.py", "risk": "low"}])
    orch = _orch(tmp_path, reply)
    ordered = [p.name for p in orch._recon(_parts())]
    assert ordered == ["c.py", "a.py", "b.py"]


def test_recon_no_mencionadas_al_final(tmp_path):
    reply = json.dumps([{"name": "b.py", "risk": "high"}])
    orch = _orch(tmp_path, reply)
    ordered = [p.name for p in orch._recon(_parts())]
    assert ordered[0] == "b.py"
    assert set(ordered) == {"a.py", "b.py", "c.py"}       # no pierde ninguna


def test_recon_fallback_si_respuesta_basura(tmp_path):
    orch = _orch(tmp_path, "no soy json")
    ordered = [p.name for p in orch._recon(_parts())]
    assert ordered == ["a.py", "b.py", "c.py"]            # mantiene orden original


def test_recon_refina_hint(tmp_path):
    reply = json.dumps([{"name": "a.py", "risk": "high", "hint": "SQLi en la query"}])
    orch = _orch(tmp_path, reply)
    parts = orch._recon(_parts())
    assert parts[0].name == "a.py" and parts[0].hint == "SQLi en la query"


def test_audit_only_paths_filtra_particiones(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    (tmp_path / "b.py").write_text("y=2")
    (tmp_path / "c.py").write_text("z=3")
    cfg = make_settings(role_replies={"red_find": "[]"})
    cfg.target_kind = "python"
    cfg.recon = False
    cfg.store_path = str(tmp_path / ".hk/f.jsonl")
    orch = Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: None)
    seen = []
    orch.audit(only_paths={str(tmp_path / "b.py")},
               on_partition=lambda i, n, name: seen.append(name))
    assert seen == ["b.py"]                              # solo la partición del fichero cambiado


def test_audit_only_paths_vacio_no_audita_nada(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    cfg = make_settings(role_replies={"red_find": "[]"})
    cfg.target_kind = "python"
    cfg.recon = False
    cfg.store_path = str(tmp_path / ".hk/f.jsonl")
    orch = Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: None)
    seen = []
    orch.audit(only_paths=set(), on_partition=lambda i, n, name: seen.append(name))
    assert seen == []


def test_plan_dry_run_cuenta_llamadas(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    (tmp_path / "b.py").write_text("y=2")
    cfg = make_settings()
    cfg.red_runs = 3
    cfg.recon = True
    cfg.store_path = str(tmp_path / ".hk/f.jsonl")
    orch = Orchestrator(cfg, str(tmp_path), sandbox_factory=lambda: None)
    plan = orch.plan()
    assert plan["partitions_total"] == 2
    assert plan["find_calls"] == 2 * 3
    assert plan["recon_calls"] == 1
    plan2 = orch.plan(max_partitions=1)
    assert plan2["partitions_audited"] == 1 and plan2["find_calls"] == 3
