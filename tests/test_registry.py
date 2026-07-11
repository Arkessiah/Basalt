"""Registry de providers: registro, build y cadena de fallback (resolve)."""
from __future__ import annotations

import pytest

from basalt.providers import registry
from basalt.providers.base import ModelProvider, CompletionResult


def _make(name: str, healthy: bool):
    @registry.register(name)
    class _P(ModelProvider):
        def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw):
            return CompletionResult(text="ok", provider=name, model=self.model)

        def health(self):
            return healthy
    return _P


@pytest.fixture
def temp_providers():
    """Registra providers de prueba y limpia el registry al terminar."""
    saved = dict(registry._BUILDERS)
    _make("t_ok", healthy=True)
    _make("t_down", healthy=False)
    yield
    registry._BUILDERS.clear()
    registry._BUILDERS.update(saved)


def test_available_incluye_registrados(temp_providers):
    assert "t_ok" in registry.available()
    assert "t_down" in registry.available()


def test_build_desconocido_lanza(temp_providers):
    with pytest.raises(ValueError):
        registry.build({"provider": "no_existe"})


def test_resolve_devuelve_primer_sano(temp_providers):
    prov = registry.resolve([{"provider": "t_down"}, {"provider": "t_ok"}])
    assert prov.name == "t_ok"


def test_resolve_salta_no_registrado_y_sigue(temp_providers):
    prov = registry.resolve([{"provider": "no_existe"}, {"provider": "t_ok"}])
    assert prov.name == "t_ok"


def test_resolve_sin_ninguno_sano_lanza(temp_providers):
    with pytest.raises(RuntimeError):
        registry.resolve([{"provider": "t_down"}])


def test_build_pasa_opts_menos_provider_y_model(temp_providers):
    prov = registry.build({"provider": "t_ok", "model": "m1", "base_url": "http://x"})
    assert prov.model == "m1"
    assert prov.opts.get("base_url") == "http://x"
