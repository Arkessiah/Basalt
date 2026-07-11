"""Sandbox basado en Docker — donde se reproduce cada PoC por EJECUCIÓN.

Aislamiento por defecto: egress de red cerrado (`--network none`), FS de solo
lectura salvo el work-dir montado, y límites de CPU/mem para acotar el blast radius
de un PoC hostil. Con `gvisor=True` añade `--runtime=runsc` (kernel de usuario).
"""
from __future__ import annotations
import shutil
import subprocess
import tempfile
from pathlib import Path
from .base import Sandbox, RunResult, SandboxUnavailable

# Directorios que nunca aportan al build y solo inflan la copia al sandbox.
_IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", "target", "__pycache__", ".venv", "venv",
    ".basalt", "out", "cache", "artifacts", "*.pyc",
)


class DockerSandbox(Sandbox):
    def __init__(self, image: str = "ubuntu:24.04", mounts: dict[str, str] | None = None,
                 gvisor: bool = False, cpus: str = "2", memory: str = "2g",
                 pids_limit: int = 512):
        if not shutil.which("docker"):
            raise SandboxUnavailable("Docker no está instalado / no está en PATH.")
        self.image = image
        self.mounts = mounts or {}
        self.gvisor = gvisor
        self.cpus = cpus
        self.memory = memory
        self.pids_limit = pids_limit
        self._stage = Path(tempfile.mkdtemp(prefix="basalt_"))

    def put(self, host_path: str, container_path: str) -> None:
        dest = self._stage / container_path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(host_path, dest)

    def put_tree(self, host_dir: str, dest: str = "") -> None:
        target = self._stage / dest.lstrip("/")
        shutil.copytree(host_dir, target, ignore=_IGNORE, dirs_exist_ok=True,
                        symlinks=False)

    def write(self, content: str, container_path: str) -> None:
        dest = self._stage / container_path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    def run(self, cmd, *, workdir="/work", timeout=120, network=False) -> RunResult:
        base = ["docker", "run", "--rm", "-w", workdir, "-v", f"{self._stage}:/work",
                f"--cpus={self.cpus}", f"--memory={self.memory}",
                f"--pids-limit={self.pids_limit}"]
        if self.gvisor:
            base += ["--runtime=runsc"]
        if not network:
            base += ["--network", "none"]
        for h, c in self.mounts.items():
            base += ["-v", f"{h}:{c}:ro"]
        base += [self.image] + cmd
        try:
            r = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
            return RunResult(r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            return RunResult(124, out, err, timed_out=True)

    def cleanup(self):
        shutil.rmtree(self._stage, ignore_errors=True)
