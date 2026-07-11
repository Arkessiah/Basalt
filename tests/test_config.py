"""Validación de config: errores claros ante fichero ausente / YAML roto / valores inválidos."""
from __future__ import annotations

import pytest

from basalt import config


def test_config_ausente_error_claro(tmp_path):
    with pytest.raises(FileNotFoundError) as ei:
        config.load(tmp_path / "no_existe.yaml")
    assert "example" in str(ei.value)


def test_yaml_invalido(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("target: [unclosed\n")
    with pytest.raises(RuntimeError):
        config.load(p)


def test_target_kind_desconocido(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("target: { kind: cobol }\ndefault_providers: [{provider: ollama}]\n")
    with pytest.raises(ValueError) as ei:
        config.load(p)
    assert "cobol" in str(ei.value)


def test_checks_desconocidos(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("audit: { checks: [sql-injection, no-existe] }\n"
                 "default_providers: [{provider: ollama}]\ntarget: {kind: python}\n")
    with pytest.raises(ValueError) as ei:
        config.load(p)
    assert "no-existe" in str(ei.value)


def test_store_path_of_no_valida_providers(tmp_path):
    # store_path_of debe funcionar aunque no haya providers sanos (lectura pura)
    p = tmp_path / "c.yaml"
    p.write_text("store_path: /x/y.jsonl\n")
    assert config.store_path_of(p) == "/x/y.jsonl"
