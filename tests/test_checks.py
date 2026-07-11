"""Catálogo de checks pluggable: filtrado por lenguaje y por selección."""
from __future__ import annotations

from basalt import checks


def test_selected_por_lenguaje():
    sol = {c.id for c in checks.selected("solidity")}
    assert "reentrancy" in sol
    assert "xss" not in sol                    # xss no aplica a solidity
    ts = {c.id for c in checks.selected("typescript")}
    assert "xss" in ts and "prototype-pollution" in ts
    assert "reentrancy" not in ts


def test_checks_universales_en_todos():
    for kind in ("python", "go", "typescript", "rust", "solidity", "generic"):
        ids = {c.id for c in checks.selected(kind)}
        assert {"sql-injection", "command-injection", "auth-bypass"} <= ids


def test_filtro_por_only():
    sel = checks.selected("python", only=["sql-injection", "ssrf", "reentrancy"])
    ids = {c.id for c in sel}
    assert ids == {"sql-injection", "ssrf"}     # reentrancy no aplica a python


def test_prompt_block_usa_ids_canonicos():
    block = checks.prompt_block("go")
    assert "unchecked-error" in block
    assert "CWE-" in block
    assert "usa el `id` EXACTO" in block


def test_prompt_block_vacio_si_only_no_aplica():
    assert checks.prompt_block("solidity", only=["xss"]) == ""


def test_all_ids_sin_duplicados():
    ids = checks.all_ids()
    assert len(ids) == len(set(ids))
