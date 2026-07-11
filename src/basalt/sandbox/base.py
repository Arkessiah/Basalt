"""Sandbox de ejecución aislada — donde se VERIFICA cada hallazgo.

Principio central del purple-team (Google/Anthropic): un hallazgo solo es real
si se reproduce por EJECUCIÓN en un entorno limpio. El sandbox aísla eso
(Docker/gVisor), con egress de red restringido. NUNCA se ejecuta el PoC en el host.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass

# Señal inequívoca de "el exploit se disparó". El PoC del red agent DEBE emitir
# esta línea por stdout en el camino de explotación. La verificación por ejecución
# considera un hallazgo reproducido solo si el comando corre (sin timeout) y esta
# marca aparece en la salida — evita confundir "build OK" o "test falló" con éxito.
POC_SENTINEL = "BASALT-POC-TRIGGERED"


class SandboxUnavailable(RuntimeError):
    """El driver de sandbox no está disponible (p.ej. Docker no instalado)."""


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class Sandbox(ABC):
    """Ejecuta comandos sobre una copia aislada del objetivo."""

    @abstractmethod
    def run(self, cmd: list[str], *, workdir: str = "/work", timeout: int = 120,
            network: bool = False) -> RunResult:
        ...

    @abstractmethod
    def put(self, host_path: str, container_path: str) -> None:
        """Copia un fichero del host al sandbox."""

    @abstractmethod
    def put_tree(self, host_dir: str, dest: str = "") -> None:
        """Copia un árbol de directorios (contexto de build) al sandbox."""

    @abstractmethod
    def write(self, content: str, container_path: str) -> None:
        """Materializa contenido de texto (p.ej. el PoC) como fichero en el sandbox."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def cleanup(self):  # override si procede
        pass
