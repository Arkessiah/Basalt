"""Adaptador de objetivo — sabe cómo particionar, construir, reproducir PoC y testear
un tipo de código concreto (Solidity, Rust, Go, infra…). Aísla la especificidad
del lenguaje del orquestador, que es genérico.
"""
from __future__ import annotations
import glob
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

_DEP_EXCLUDE = ("/node_modules/", "/vendor/", "/.git/", "/target/", "/dist/", "/build/")

if TYPE_CHECKING:  # pragma: no cover
    from ..findings import Finding


@dataclass
class Partition:
    """Un trozo auditable del objetivo (un contrato, un módulo, un fichero)."""
    name: str
    paths: list[str]
    hint: str = ""  # pista de superficie de ataque para el red agent


class Target(ABC):
    kind: str = "generic"
    default_image: str = "ubuntu:24.04"   # imagen de sandbox con el toolchain del lenguaje

    def __init__(self, root: str):
        self.root = root

    #: Ecosistema OSV (PyPI/npm/Go/crates.io) y ficheros de manifiesto de dependencias.
    dep_ecosystem: str = ""
    dep_manifests: tuple[str, ...] = ()

    def dependency_manifests(self) -> list[tuple[str, str, str]]:
        """Lockfiles presentes como (ecosistema_OSV, ruta_absoluta, ruta_relativa)."""
        if not self.dep_ecosystem:
            return []
        out = []
        for fname in self.dep_manifests:
            for p in glob.glob(os.path.join(self.root, "**", fname), recursive=True):
                if os.path.isfile(p) and not any(e in p for e in _DEP_EXCLUDE):
                    out.append((self.dep_ecosystem, p, os.path.relpath(p, self.root)))
        return out

    def poc_instructions(self) -> str:
        """Instrucciones LANGUAGE-SPECIFIC para el red agent sobre cómo escribir el PoC
        (fichero, comando que lo ejecuta, dónde imprimir el sentinel). Se inyecta en el
        prompt para no acoplar el prompt a un lenguaje."""
        return ("PoC = script shell `hk_poc.sh` (se ejecuta con `bash hk_poc.sh`). "
                "Imprime EXACTAMENTE `BASALT-POC-TRIGGERED` por stdout SOLO en el camino de "
                "explotación exitosa. Sandbox SIN red; el PoC debe ser autocontenido.")

    @abstractmethod
    def partitions(self) -> list[Partition]:
        """Divide el objetivo en trozos que el recon prioriza y el red audita."""

    @abstractmethod
    def context(self, part: Partition) -> str:
        """Devuelve el código/artefactos relevantes de la partición (para el prompt)."""

    def build_cmd(self) -> list[str] | None:
        """Comando de build en el sandbox (None si no aplica)."""
        return None

    def test_cmd(self) -> list[str] | None:
        """Suite de tests en el sandbox (para el grader)."""
        return None

    # --- Reproducción de PoC (verificación por ejecución) -------------------
    def poc_artifact(self, finding: "Finding") -> tuple[str, str]:
        """Dónde aterriza el PoC dentro del sandbox y su contenido.

        Devuelve (ruta_relativa_en_/work, contenido). Por defecto, un script shell
        que el `reproduce_cmd` ejecuta; el PoC debe imprimir el sentinel al explotar.
        """
        return "hk_poc.sh", (finding.poc or "")

    def reproduce_cmd(self) -> list[str] | None:
        """Comando que EJECUTA el PoC en el sandbox. Éxito = el sentinel aparece
        en stdout (lo comprueba el orquestador). None = este target no sabe
        reproducir por ejecución todavía (el hallazgo no se podrá confirmar)."""
        return ["bash", "-c", "bash hk_poc.sh"]
