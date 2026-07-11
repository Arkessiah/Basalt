"""FindingsStore: dedupe por fingerprint, acumulación de votos, persistencia."""
from __future__ import annotations

from basalt.findings import Finding, FindingsStore


def _finding(**kw) -> Finding:
    base = dict(title="reentrancy en withdraw", severity="high", category="reentrancy",
                target="Vault.sol", location="Vault.sol:42")
    base.update(kw)
    return Finding(**base)


def test_fingerprint_estable_e_insensible_a_mayusculas():
    a = _finding()
    b = _finding(title="REENTRANCY EN WITHDRAW")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_distingue_por_categoria_y_localizacion():
    a = _finding()
    assert a.fingerprint() != _finding(category="access-control").fingerprint()
    assert a.fingerprint() != _finding(location="Vault.sol:99").fingerprint()


def test_add_dedup_y_suma_votos(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    store.add(_finding())          # voto 1 (nuevo)
    store.add(_finding())          # voto 2 (mismo fingerprint)
    store.add(_finding())          # voto 3
    assert len(store.all()) == 1
    assert store.all()[0].votes == 3


def test_confirmed_filtra_por_status_y_min_votes(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    f = _finding(status="confirmed")
    store.add(f)                                  # votos=1
    assert store.confirmed(min_votes=2) == []     # 1 voto no basta
    store.add(_finding(status="confirmed"))       # votos=2
    assert len(store.confirmed(min_votes=2)) == 1


def test_candidate_no_aparece_en_confirmed(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    store.add(_finding(status="candidate"))
    store.add(_finding(status="candidate"))
    assert store.confirmed(min_votes=1) == []


def test_record_rejected_persiste_y_no_pisa_confirmado(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    store.add(_finding(status="confirmed"))          # confirmado, votos=1
    store.record_rejected(_finding())                # mismo fp -> no degrada
    assert store.all()[0].status == "confirmed"
    assert len(store.rejected()) == 0


def test_add_asciende_un_rechazado_previo(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    store.record_rejected(_finding())                # primero rechazado (votos=0)
    assert store.rejected() and store.all()[0].votes == 0
    store.add(_finding(status="confirmed"))          # otro run lo reproduce -> asciende
    assert store.all()[0].status == "confirmed"
    assert store.all()[0].votes == 1
    assert store.rejected() == []


def test_rejected_separado_de_confirmed(tmp_path):
    store = FindingsStore(tmp_path / "f.jsonl")
    store.record_rejected(_finding(title="a"))
    store.add(_finding(title="b", status="confirmed"))
    store.add(_finding(title="b", status="confirmed"))
    assert len(store.rejected()) == 1
    assert len(store.confirmed(min_votes=2)) == 1


def test_persistencia_roundtrip(tmp_path):
    path = tmp_path / "f.jsonl"
    s1 = FindingsStore(path)
    s1.add(_finding(status="confirmed"))
    s1.add(_finding(status="confirmed"))          # mismo fp -> votos=2
    s2 = FindingsStore(path)                       # recarga desde disco
    assert len(s2.all()) == 1
    assert s2.all()[0].votes == 2
    assert s2.all()[0].status == "confirmed"
