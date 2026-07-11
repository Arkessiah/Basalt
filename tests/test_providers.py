"""Robustez de providers: retry ante transitorios, no-retry ante errores de config,
parseo OpenAI defensivo."""
from __future__ import annotations

import pytest

from basalt.providers.base import (
    ModelProvider, CompletionResult, is_transient, extract_openai_text, Message,
)


class _P(ModelProvider):
    def complete(self, messages, *, temperature=0.2, max_tokens=4096, **kw):
        return CompletionResult("ok", "p", self.model)


def test_is_transient_stdlib_y_no_config():
    assert is_transient(TimeoutError()) is True
    assert is_transient(ConnectionError()) is True
    assert is_transient(ValueError("clave ausente")) is False
    assert is_transient(RuntimeError("falta API key")) is False


def test_is_transient_httpx_por_modulo():
    class _Resp:
        status_code = 503

    class HTTPStatusError(Exception):
        __module__ = "httpx"
        response = _Resp()
    assert is_transient(HTTPStatusError()) is True

    class ConnectError(Exception):
        __module__ = "httpx"
    assert is_transient(ConnectError()) is True


def test_is_transient_httpx_4xx_no_reintenta():
    class _Resp:
        status_code = 400

    class HTTPStatusError(Exception):
        __module__ = "httpx"
        response = _Resp()
    assert is_transient(HTTPStatusError()) is False


def test_is_transient_anthropic_ratelimit():
    class RateLimitError(Exception):
        __module__ = "anthropic"
    assert is_transient(RateLimitError()) is True

    class BadRequestError(Exception):
        __module__ = "anthropic"
        status_code = 400
    assert is_transient(BadRequestError()) is False


def test_retry_reintenta_transitorio_y_acaba_ok():
    p = _P("m", retries=3, retry_delay=0)
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("hipo de red")
        return "ok"
    assert p._retry(fn) == "ok"
    assert calls["n"] == 3


def test_retry_no_reintenta_error_de_config():
    p = _P("m", retries=5, retry_delay=0)
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise RuntimeError("falta ANTHROPIC_API_KEY")
    with pytest.raises(RuntimeError):
        p._retry(fn)
    assert calls["n"] == 1                       # no reintentó


def test_retry_agota_intentos_y_relanza():
    p = _P("m", retries=2, retry_delay=0)
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise TimeoutError("siempre falla")
    with pytest.raises(TimeoutError):
        p._retry(fn)
    assert calls["n"] == 3                        # 1 + 2 reintentos


def test_extract_openai_ok_y_malformado():
    assert extract_openai_text({"choices": [{"message": {"content": "hola"}}]}) == "hola"
    with pytest.raises(RuntimeError):
        extract_openai_text({"error": {"message": "modelo no existe"}})
    with pytest.raises(RuntimeError):
        extract_openai_text({"choices": [{"message": {"content": None}}]})


def test_message_dataclass():
    m = Message("user", "x")
    assert m.role == "user" and m.content == "x"
