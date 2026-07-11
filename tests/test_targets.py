"""Adaptadores por lenguaje: make_target/alias, imagen por defecto, harness de PoC."""
from __future__ import annotations

from basalt.findings import Finding
from basalt.targets.adapters import (
    make_target, SolidityTarget, RustTarget, PythonTarget, GoTarget,
    TypeScriptTarget, GenericTarget,
)


def _f() -> Finding:
    return Finding(title="t", severity="high", category="c", target="x", poc="CONTENIDO_POC")


def test_make_target_resuelve_kinds_y_alias():
    assert isinstance(make_target("python", "/x"), PythonTarget)
    assert isinstance(make_target("go", "/x"), GoTarget)
    assert isinstance(make_target("typescript", "/x"), TypeScriptTarget)
    assert isinstance(make_target("rust", "/x"), RustTarget)
    assert isinstance(make_target("solidity", "/x"), SolidityTarget)
    # alias
    assert isinstance(make_target("py", "/x"), PythonTarget)
    assert isinstance(make_target("golang", "/x"), GoTarget)
    assert isinstance(make_target("TS", "/x"), TypeScriptTarget)
    assert isinstance(make_target("react", "/x"), TypeScriptTarget)
    assert isinstance(make_target("sol", "/x"), SolidityTarget)
    # desconocido -> generic
    assert isinstance(make_target("cobol", "/x"), GenericTarget)
    assert isinstance(make_target("", "/x"), GenericTarget)


def test_imagen_por_defecto_por_lenguaje():
    assert make_target("python", "/x").default_image == "python:3.12-slim"
    assert make_target("go", "/x").default_image == "golang:1.22"
    assert make_target("typescript", "/x").default_image == "node:20-slim"
    assert "rust" in make_target("rust", "/x").default_image
    assert "foundry" in make_target("solidity", "/x").default_image
    assert make_target("generic", "/x").default_image == "ubuntu:24.04"


def test_poc_artifact_y_reproduce_por_lenguaje():
    cases = {
        "python": ("hk_poc.py", "python3 hk_poc.py"),
        "go": ("hkpoc/main.go", "go run ./hkpoc"),
        "typescript": ("hk_poc.mjs", "node hk_poc.mjs"),
        "rust": ("hk_poc.rs", "rustc hk_poc.rs"),
        "solidity": ("test/HK_PoC.t.sol", "forge test"),
        "generic": ("hk_poc.sh", "bash hk_poc.sh"),
    }
    for kind, (path, cmd_substr) in cases.items():
        t = make_target(kind, "/x")
        p, content = t.poc_artifact(_f())
        assert p == path
        assert content == "CONTENIDO_POC"
        assert cmd_substr in " ".join(t.reproduce_cmd())


def test_poc_instructions_mencionan_el_sentinel():
    for kind in ("python", "go", "typescript", "rust", "solidity", "generic"):
        assert "BASALT-POC-TRIGGERED" in make_target(kind, "/x").poc_instructions()


def test_partitions_filtra_dependencias(tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text("y=2")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("z=3")
    parts = make_target("python", str(tmp_path)).partitions()
    names = {p.name for p in parts}
    assert names == {"app.py"}            # excluye node_modules y .venv


def test_typescript_recoge_varias_extensiones(tmp_path):
    for name in ("a.ts", "b.tsx", "c.js", "d.jsx", "e.mjs"):
        (tmp_path / name).write_text("//x")
    (tmp_path / "styles.css").write_text("x{}")
    parts = make_target("ts", str(tmp_path)).partitions()
    names = {p.name for p in parts}
    assert names == {"a.ts", "b.tsx", "c.js", "d.jsx", "e.mjs"}   # no .css


def test_orchestrator_usa_imagen_del_lenguaje_si_no_hay_en_config(tmp_path, monkeypatch):
    from basalt.orchestrator import Orchestrator
    from conftest import make_settings
    import basalt.orchestrator as orch_mod

    captured = {}

    class FakeDocker:
        def __init__(self, image, **kw):
            captured["image"] = image
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(orch_mod, "DockerSandbox", FakeDocker)
    cfg = make_settings()
    cfg.target_kind = "go"
    cfg.sandbox = {"driver": "docker"}                 # sin image
    orch = Orchestrator(cfg, str(tmp_path))
    orch._default_sandbox()
    assert captured["image"] == "golang:1.22"          # imagen del toolchain Go

    cfg.sandbox = {"driver": "docker", "image": "custom:1"}
    Orchestrator(cfg, str(tmp_path))._default_sandbox()
    assert captured["image"] == "custom:1"             # la de config manda
