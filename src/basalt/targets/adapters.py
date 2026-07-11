"""Adaptadores de objetivo por lenguaje.

Cada adaptador sabe: cómo particionar el repo, qué imagen de sandbox (toolchain)
usar, dónde aterriza el PoC y con qué comando se reproduce. El contrato común es
el SENTINEL (`BASALT-POC-TRIGGERED`): un hallazgo solo se confirma si su PoC lo emite
al ejecutarse en sandbox limpio. Solidity/Rust/etc. son adaptadores especializados;
`GenericTarget` cubre cualquier lenguaje con un PoC de shell.
"""
from __future__ import annotations
import glob
import os
from .base import Target, Partition

# Directorios que nunca contienen código a auditar (ruido / dependencias).
_EXCLUDE = ("/node_modules/", "/target/", "/.git/", "/vendor/", "/dist/",
            "/build/", "/.venv/", "/venv/", "/__pycache__/")


def _read(path: str) -> str:
    try:
        return open(path, errors="ignore").read()
    except OSError:
        return ""


def _collect(root: str, exts: tuple[str, ...], *, extra_exclude: tuple[str, ...] = ()) -> list[str]:
    excl = _EXCLUDE + extra_exclude
    out = []
    for f in glob.glob(os.path.join(root, "**", "*"), recursive=True):
        if f.endswith(exts) and not any(e in f for e in excl) and os.path.isfile(f):
            out.append(f)
    return sorted(out)


def _ctx(paths: list[str]) -> str:
    return "\n\n".join(f"// FILE: {p}\n{_read(p)}" for p in paths if os.path.exists(p))


class SolidityTarget(Target):
    """Contratos Solidity (Foundry). Reproducción de PoC = test de Foundry que dispara
    la vuln y hace `console.log("BASALT-POC-TRIGGERED")` (`forge test`)."""
    kind = "solidity"
    default_image = "ghcr.io/foundry-rs/foundry:latest"

    def partitions(self) -> list[Partition]:
        sols = _collect(self.root, (".sol",), extra_exclude=("/lib/",))
        return [Partition(name=os.path.relpath(s, self.root), paths=[s],
                          hint="reentrancy, access-control, overflow, oracle, tx.origin") for s in sols]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def build_cmd(self):
        return ["bash", "-c", "forge build"]

    def test_cmd(self):
        return ["bash", "-c", "forge test -vvv"]

    def poc_artifact(self, finding):
        return "test/HK_PoC.t.sol", (finding.poc or "")

    def reproduce_cmd(self):
        return ["bash", "-c", "forge test --match-path test/HK_PoC.t.sol -vv"]

    def poc_instructions(self) -> str:
        return ("PoC = un fichero de test de Foundry COMPLETO (aterriza en `test/HK_PoC.t.sol`, "
                "se corre con `forge test`). Tras explotar la vuln, llama a "
                "`console.log(\"BASALT-POC-TRIGGERED\");`. Requiere que el proyecto tenga forge-std.")


class RustTarget(Target):
    """Rust: foco en bloques `unsafe`. PoC = programa autocontenido compilado con rustc."""
    kind = "rust"
    default_image = "rust:1.79-slim"
    dep_ecosystem = "crates.io"
    dep_manifests = ("Cargo.lock",)

    def partitions(self) -> list[Partition]:
        rs = _collect(self.root, (".rs",))
        pri = [r for r in rs if "unsafe" in _read(r)]       # prioriza ficheros con unsafe
        chosen = pri or rs
        return [Partition(name=os.path.relpath(r, self.root), paths=[r],
                          hint="unsafe blocks, integer overflow, panic paths, deserialization")
                for r in chosen]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def poc_artifact(self, finding):
        return "hk_poc.rs", (finding.poc or "")

    def reproduce_cmd(self):
        return ["bash", "-c", "rustc hk_poc.rs -o hk_poc_bin && ./hk_poc_bin"]

    def poc_instructions(self) -> str:
        return ("PoC = un programa Rust autocontenido `hk_poc.rs` (con `fn main`), compilado y "
                "ejecutado con `rustc hk_poc.rs -o hk_poc_bin && ./hk_poc_bin`. Reproduce la "
                "lógica vulnerable e imprime `BASALT-POC-TRIGGERED` (println!) SOLO al explotar.")


class PythonTarget(Target):
    """Python: PoC = script que importa/ejercita el módulo objetivo (`python3 hk_poc.py`)."""
    kind = "python"
    default_image = "python:3.12-slim"
    dep_ecosystem = "PyPI"
    dep_manifests = ("requirements.txt", "requirements-dev.txt", "poetry.lock")

    def partitions(self) -> list[Partition]:
        py = _collect(self.root, (".py",))
        return [Partition(name=os.path.relpath(p, self.root), paths=[p],
                          hint="injection, deserialization (pickle/yaml), path traversal, "
                               "command exec, SSRF, auth bypass, unsafe eval") for p in py]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def poc_artifact(self, finding):
        return "hk_poc.py", (finding.poc or "")

    def reproduce_cmd(self):
        return ["bash", "-c", "python3 hk_poc.py"]

    def poc_instructions(self) -> str:
        return ("PoC = un script Python `hk_poc.py` (se corre con `python3 hk_poc.py` desde la "
                "raíz del repo, ya montada). Importa el módulo vulnerable o reproduce la lógica; "
                "imprime `BASALT-POC-TRIGGERED` SOLO en el camino de explotación exitosa. Solo stdlib "
                "(sandbox sin red).")


class GoTarget(Target):
    """Go: PoC = programa `main` en `hkpoc/` que ejercita el paquete objetivo (`go run ./hkpoc`)."""
    kind = "go"
    default_image = "golang:1.22"
    dep_ecosystem = "Go"
    dep_manifests = ("go.mod",)

    def partitions(self) -> list[Partition]:
        go = _collect(self.root, (".go",))
        return [Partition(name=os.path.relpath(p, self.root), paths=[p],
                          hint="injection, path traversal, SSRF, auth bypass, race conditions, "
                               "unchecked errors, integer overflow") for p in go]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def poc_artifact(self, finding):
        # Subdir propio para no chocar con otros `package main` del repo.
        return "hkpoc/main.go", (finding.poc or "")

    def reproduce_cmd(self):
        return ["bash", "-c", "go run ./hkpoc"]

    def poc_instructions(self) -> str:
        return ("PoC = un `package main` en `hkpoc/main.go` (se corre con `go run ./hkpoc` desde "
                "la raíz del módulo, ya montada). Importa el paquete vulnerable por su ruta de "
                "módulo (ver go.mod) o reproduce la lógica; imprime `BASALT-POC-TRIGGERED` (fmt.Println) "
                "SOLO al explotar. Sin deps externas (sandbox sin red).")


class TypeScriptTarget(Target):
    """TS/JS/React: PoC = módulo ESM `hk_poc.mjs` (`node hk_poc.mjs`)."""
    kind = "typescript"
    default_image = "node:20-slim"
    dep_ecosystem = "npm"
    dep_manifests = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")

    def partitions(self) -> list[Partition]:
        files = _collect(self.root, (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
        return [Partition(name=os.path.relpath(p, self.root), paths=[p],
                          hint="XSS, prototype pollution, injection, SSRF, auth bypass, "
                               "insecure deserialization, ReDoS, path traversal") for p in files]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def poc_artifact(self, finding):
        return "hk_poc.mjs", (finding.poc or "")

    def reproduce_cmd(self):
        return ["bash", "-c", "node hk_poc.mjs"]

    def poc_instructions(self) -> str:
        return ("PoC = un módulo ESM JavaScript `hk_poc.mjs` (se corre con `node hk_poc.mjs` desde "
                "la raíz, ya montada). Si el objetivo es TS, importa la salida compilada o reproduce "
                "la lógica vulnerable en JS; imprime `BASALT-POC-TRIGGERED` (console.log) SOLO al explotar. "
                "Solo APIs de Node (sandbox sin red).")


class GenericTarget(Target):
    """Fallback: cualquier repo/lenguaje. PoC de shell (`bash hk_poc.sh`)."""
    kind = "generic"
    default_image = "ubuntu:24.04"
    EXT = (".go", ".ts", ".tsx", ".js", ".jsx", ".py", ".sol", ".rs", ".c", ".cpp", ".rb", ".php", ".java")

    def partitions(self) -> list[Partition]:
        files = _collect(self.root, self.EXT)
        return [Partition(name=os.path.relpath(f, self.root), paths=[f]) for f in files[:200]]

    def context(self, part: Partition) -> str:
        return _ctx(part.paths)

    def dependency_manifests(self) -> list[tuple[str, str, str]]:
        # Repo genérico/poliglota: busca lockfiles de TODOS los ecosistemas conocidos.
        from ..deps import ECOSYSTEMS
        out = []
        for eco, fnames in ECOSYSTEMS.items():
            for fname in fnames:
                for p in glob.glob(os.path.join(self.root, "**", fname), recursive=True):
                    if os.path.isfile(p) and "/node_modules/" not in p and "/vendor/" not in p:
                        out.append((eco, p, os.path.relpath(p, self.root)))
        return out


ADAPTERS = {
    "solidity": SolidityTarget,
    "rust": RustTarget,
    "python": PythonTarget,
    "go": GoTarget,
    "typescript": TypeScriptTarget,
    "generic": GenericTarget,
}

# Alias cómodos hacia el kind canónico.
_ALIASES = {"py": "python", "golang": "go", "ts": "typescript", "js": "typescript",
            "node": "typescript", "react": "typescript", "sol": "solidity", "rs": "rust"}


def make_target(kind: str, root: str) -> Target:
    kind = (kind or "generic").lower()
    kind = _ALIASES.get(kind, kind)
    return ADAPTERS.get(kind, GenericTarget)(root)
