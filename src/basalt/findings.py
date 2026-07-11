"""Modelo de hallazgo + store versionado con dedupe y voto de consenso."""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    title: str
    severity: str            # SEVERITIES
    category: str            # p.ej. "reentrancy", "memory-safety", "prompt-injection"
    target: str              # ruta/repo auditado
    location: str = ""       # fichero:linea
    description: str = ""
    poc: str = ""            # prueba de concepto reproducible (obligatoria para "confirmed")
    status: str = "candidate"  # candidate -> confirmed -> patched -> closed | rejected
    votes: int = 0           # nº de runs independientes que lo reprodujeron
    finder: str = ""         # provider/modelo que lo encontró
    meta: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        base = f"{self.category}|{self.target}|{self.location}|{self.title}".lower()
        return hashlib.sha256(base.encode()).hexdigest()[:16]


class FindingsStore:
    """Persistencia JSONL con dedupe por fingerprint y acumulación de votos."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._by_fp: dict[str, Finding] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    f = Finding(**json.loads(line))
                    self._by_fp[f.fingerprint()] = f

    def add(self, f: Finding) -> Finding:
        """Añade o funde un CONFIRMADO por fingerprint; suma un voto (reproducción independiente).

        Si el fingerprint ya existía como `rejected` (un run lo descartó y otro lo reprodujo),
        lo ASCIENDE a confirmado y adopta su evidencia de verificación."""
        fp = f.fingerprint()
        if fp in self._by_fp:
            existing = self._by_fp[fp]
            existing.votes += 1
            if f.status == "confirmed" and existing.status not in ("confirmed", "patched"):
                existing.status = "confirmed"
                existing.meta = f.meta
        else:
            f.votes = max(f.votes, 1)
            self._by_fp[fp] = f
        self._flush()
        return self._by_fp[fp]

    def record_rejected(self, f: Finding) -> Finding:
        """Persiste un candidato RECHAZADO (juez o ejecución) para el embudo del informe.

        No sube voto ni pisa un hallazgo ya presente (nunca degrada un confirmado)."""
        fp = f.fingerprint()
        if fp in self._by_fp:
            return self._by_fp[fp]
        f.status = "rejected"
        f.votes = 0
        self._by_fp[fp] = f
        self._flush()
        return f

    def rejected(self) -> list[Finding]:
        return [f for f in self._by_fp.values() if f.status == "rejected"]

    def update(self, f: Finding) -> Finding:
        """Reemplaza un hallazgo por fingerprint SIN sumar voto (cambio de status/meta)."""
        self._by_fp[f.fingerprint()] = f
        self._flush()
        return f

    def confirmed(self, min_votes: int = 2) -> list[Finding]:
        return [f for f in self._by_fp.values() if f.status == "confirmed" and f.votes >= min_votes]

    def patched(self) -> list[Finding]:
        return [f for f in self._by_fp.values() if f.status == "patched"]

    def all(self) -> list[Finding]:
        return list(self._by_fp.values())

    def _flush(self):
        self.path.write_text("\n".join(json.dumps(asdict(f), ensure_ascii=False)
                                       for f in self._by_fp.values()))
