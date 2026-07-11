"""Sanitización de secretos: redacta valores pero preserva la señal."""
from __future__ import annotations

from basalt.redact import redact


def test_redacta_tipos_comunes():
    samples = {
        "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
        "github-token": "ghp_" + "a" * 36,
        "anthropic-key": "sk-ant-" + "a" * 24,
        "slack-token": "xoxb-" + "1" * 20,
        "stripe-key": "sk_live_" + "a" * 24,
        "google-api-key": "AIza" + "b" * 35,
        "jwt": "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4",
    }
    for label, secret in samples.items():
        out, n = redact(f"clave = {secret}")
        assert n >= 1, label
        assert secret not in out, label
        assert f"<BASALT_REDACTED:{label}>" in out, label


def test_redacta_uri_con_credencial_conserva_usuario():
    out, n = redact("postgres://admin:s3cr3tpass@db.internal:5432/app")
    assert n == 1
    assert "s3cr3tpass" not in out
    assert "admin" in out and "<BASALT_REDACTED:uri-credential>" in out


def test_redacta_asignacion_de_secreto():
    out, n = redact('password = "hunter2superlong"')
    assert n == 1
    assert "hunter2superlong" not in out
    assert "password" in out                      # conserva la clave (señal para el red agent)


def test_private_key_pem():
    out, n = redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE.....\n")
    assert n == 1 and "<BASALT_REDACTED:private-key>" in out


def test_no_toca_texto_normal():
    txt = "def foo(x):\n    return x + 1  # nada sensible aqui\n"
    out, n = redact(txt)
    assert out == txt and n == 0


def test_devuelve_conteo_multiple():
    out, n = redact("AKIAIOSFODNN7EXAMPLE y otro AKIA1234567890ABCDEF")
    assert n == 2
    assert "AKIA" not in out
