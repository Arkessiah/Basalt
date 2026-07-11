"""MCP server: funciones-herramienta planas (sin depender del SDK mcp)."""
from __future__ import annotations

import yaml

from basalt import mcp_server
from basalt.findings import Finding, FindingsStore


def _cfg(tmp_path) -> str:
    store = tmp_path / ".hk" / "f.jsonl"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml.safe_dump({"store_path": str(store), "target": {"kind": "python"}}))
    s = FindingsStore(store)
    # dos reproducciones independientes del mismo hallazgo -> votos=2
    s.add(Finding(title="A", severity="critical", category="auth", target="x",
                  location="x:1", status="confirmed"))
    s.add(Finding(title="A", severity="critical", category="auth", target="x",
                  location="x:1", status="confirmed"))
    s.record_rejected(Finding(title="B", severity="low", category="style", target="y",
                              location="y:2"))
    return str(cfg)


def test_list_findings_y_filtro_por_status(tmp_path):
    cfg = _cfg(tmp_path)
    todos = mcp_server.tool_list_findings(cfg)
    assert len(todos) == 2
    conf = mcp_server.tool_list_findings(cfg, status="confirmed")
    assert len(conf) == 1 and conf[0]["title"] == "A" and conf[0]["votes"] == 2
    rej = mcp_server.tool_list_findings(cfg, status="rejected")
    assert len(rej) == 1 and rej[0]["title"] == "B"


def test_get_finding_por_fingerprint(tmp_path):
    cfg = _cfg(tmp_path)
    fp = mcp_server.tool_list_findings(cfg, status="confirmed")[0]["fingerprint"]
    det = mcp_server.tool_get_finding(fp, cfg)
    assert det["title"] == "A" and det["severity"] == "critical"
    assert "error" in mcp_server.tool_get_finding("noexiste", cfg)


def test_get_report_markdown_y_json(tmp_path):
    cfg = _cfg(tmp_path)
    md = mcp_server.tool_get_report(cfg, "markdown")
    assert "Verification funnel" in md and "A" in md
    js = mcp_server.tool_get_report(cfg, "json")
    assert js.strip().startswith("{")


def test_tool_gate(tmp_path):
    cfg = _cfg(tmp_path)                               # A = critical confirmado
    assert mcp_server.tool_gate(cfg, "high")["passes"] is False
    assert mcp_server.tool_gate(cfg, "high")["over_threshold"] == 1
    assert "error" in mcp_server.tool_gate(cfg, "urgente")


def test_tool_scan_secrets(tmp_path):
    (tmp_path / "app.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n')
    cfg = tmp_path / "c2.yaml"
    cfg.write_text(f"store_path: {tmp_path/'.hk2'/'f.jsonl'}\n")
    res = mcp_server.tool_scan_secrets(str(tmp_path), str(cfg))
    assert res["secrets"] == 1
    assert res["findings"][0]["type"] == "aws-access-key"
    assert "AKIAIOSFODNN7EXAMPLE" not in str(res)      # no filtra el valor
