"""N-day por dependencia: cruza los lockfiles del target contra CVEs conocidos (OSV.dev).

A diferencia del flujo red→verify (que reproduce un PoC por ejecución), esto es un SCAN:
se parsea el manifiesto de dependencias y se consulta la base pública OSV. No ejecuta
código del target (solo lee texto y consulta una API), así que corre en el host, no en
sandbox — pero SÍ necesita red. La procedencia de estos hallazgos es `osv-match` (match
contra la base de avisos), no `tool-proven` por ejecución: se etiqueta como tal para ser
honestos en el informe.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass

from .findings import Finding

OSV_API = "https://api.osv.dev"

# Ecosistemas OSV soportados y sus ficheros de manifiesto.
ECOSYSTEMS = {
    "PyPI": ("requirements.txt", "requirements-dev.txt", "poetry.lock"),
    "npm": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    "Go": ("go.mod",),
    "crates.io": ("Cargo.lock",),
    "RubyGems": ("Gemfile.lock",),
    "Packagist": ("composer.lock",),
    "NuGet": ("packages.lock.json",),
}


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    direct: bool = True   # False = dependencia transitiva (reachability incierta)


# --------------------------------------------------------------------------- parsers
def parse_requirements(text: str) -> list[tuple[str, str]]:
    """requirements.txt: solo versiones fijadas con `==` (lo demás no es resoluble sin pip)."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    """package-lock.json v2/v3 (`packages`) o v1 (`dependencies`)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue                                   # "" = el propio proyecto
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            out.append((name, ver))

    def _walk(deps: dict):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append((name, meta["version"]))
                _walk(meta.get("dependencies") or {})
    if not out:
        _walk(data.get("dependencies") or {})
    return out


def parse_go_mod(text: str) -> list[tuple[str, str, bool]]:
    """go.mod: directivas `require` (bloque o suelta). Marca `// indirect` (transitivas)."""
    out = []
    in_block = False
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = (re.match(r"^(?:require\s+)?([\w./~-]+)\s+v([\w.+-]+)", line)
             if (in_block or line.startswith("require ")) else None)
        if m:
            out.append((m.group(1), m.group(2), not indirect))
    return out


def _parse_toml_packages(text: str) -> list[tuple[str, str]]:
    """Bloques `[[package]]` con name/version (Cargo.lock, poetry.lock). TOML mínimo."""
    out = []
    name = ver = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            name = ver = None
        elif line.startswith("name ="):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version ="):
            ver = line.split("=", 1)[1].strip().strip('"')
            if name and ver:
                out.append((name, ver))
    return out


parse_cargo_lock = _parse_toml_packages
parse_poetry_lock = _parse_toml_packages

# name@version en claves de pnpm-lock (v6 usa `/name/version`, v9 `/name@version`); soporta scoped.
_PNPM_KEY = re.compile(r"^\s+'?/?((?:@[^/@\s]+/)?[^/@\s]+)[@/](\d[^:\s'(]*)", re.M)


def parse_pnpm_lock(text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _PNPM_KEY.finditer(text)]


_YARN_VER = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?', re.M)


def parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """yarn.lock (v1 y berry): la cabecera trae el nombre; la línea `version` la versión."""
    out = []
    header = None
    for raw in text.splitlines():
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            header = raw.strip().strip('"')            # p.ej. `lodash@^4.17.4, lodash@~4.17.0:`
        else:
            m = _YARN_VER.match(raw)
            if m and header:
                spec = header.split(",")[0].strip().strip('"')
                at = spec.rfind("@")                   # separa name de la range (respeta scoped)
                name = spec[:at] if at > 0 else spec
                out.append((name, m.group(1)))
                header = None
    return out


_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9._-]+) \(([\d][^)]*)\)\s*$", re.M)


def parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    """Gemfile.lock: specs con 4 espacios de indentación (`    name (version)`)."""
    return [(m.group(1), m.group(2)) for m in _GEM_SPEC.finditer(text)]


def parse_composer_lock(text: str) -> list[tuple[str, str]]:
    """composer.lock (PHP): `packages` y `packages-dev` con name/version."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for key in ("packages", "packages-dev"):
        for p in data.get(key, []) or []:
            name, ver = p.get("name"), p.get("version")
            if name and ver:
                out.append((name, ver.lstrip("v")))
    return out


def parse_nuget_lock(text: str) -> list[tuple[str, str]]:
    """packages.lock.json (NuGet): versiones `resolved` por framework."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for fw_deps in (data.get("dependencies") or {}).values():
        if isinstance(fw_deps, dict):
            for name, meta in fw_deps.items():
                ver = meta.get("resolved") if isinstance(meta, dict) else None
                if name and ver:
                    out.append((name, ver))
    return out


# Parser por defecto por ecosistema (para descubrimiento genérico) y por nombre de fichero.
_PARSERS = {
    "PyPI": parse_requirements,
    "npm": parse_package_lock,
    "Go": parse_go_mod,
    "crates.io": parse_cargo_lock,
    "RubyGems": parse_gemfile_lock,
    "Packagist": parse_composer_lock,
    "NuGet": parse_nuget_lock,
}
_PARSER_BY_FILE = {
    "requirements.txt": parse_requirements,
    "requirements-dev.txt": parse_requirements,
    "poetry.lock": parse_poetry_lock,
    "package-lock.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "packages.lock.json": parse_nuget_lock,
}


def parse_manifest(text: str, ecosystem: str, filename: str = "") -> list[Package]:
    """Parsea un manifiesto. Si `filename` coincide con un parser conocido lo usa; si no,
    cae al parser por defecto del ecosistema (compat)."""
    import os
    parser = _PARSER_BY_FILE.get(os.path.basename(filename)) if filename else None
    parser = parser or _PARSERS.get(ecosystem)
    if not parser:
        return []
    seen = set()
    pkgs = []
    for item in parser(text):
        name, ver = item[0], item[1]
        direct = item[2] if len(item) > 2 else True
        key = (name, ver)
        if key not in seen:
            seen.add(key)
            pkgs.append(Package(name=name, version=ver, ecosystem=ecosystem, direct=direct))
    return pkgs


# --------------------------------------------------------------------------- OSV client
class OSVClient:
    """Cliente mínimo de OSV.dev. Inyectable/sustituible en tests."""

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    # OSV rechaza con 400 un querybatch de más de 1000 consultas: se trocea en tandas.
    BATCH_LIMIT = 1000

    def query_batch(self, packages: list[Package]) -> list[list[str]]:
        """Devuelve, por paquete (mismo orden), la lista de IDs de vulnerabilidad."""
        import httpx
        out: list[list[str]] = []
        for i in range(0, len(packages), self.BATCH_LIMIT):
            chunk = packages[i:i + self.BATCH_LIMIT]
            queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                       for p in chunk]
            r = httpx.post(f"{OSV_API}/v1/querybatch", json={"queries": queries},
                           timeout=self.timeout)
            r.raise_for_status()
            results = r.json().get("results", [])
            if len(results) != len(chunk):   # sin esto, los IDs se asignarían al paquete equivocado
                raise ValueError(f"OSV devolvió {len(results)} resultados para {len(chunk)} consultas")
            out.extend([v.get("id") for v in (res or {}).get("vulns", [])] for res in results)
        return out

    def get_vuln(self, vuln_id: str) -> dict:
        import httpx
        r = httpx.get(f"{OSV_API}/v1/vulns/{vuln_id}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()


def _severity_of(vuln: dict) -> str:
    """Deriva una severidad de Basalt desde el objeto OSV (GHSA severity o CVSS score)."""
    spec = vuln.get("database_specific") or {}
    label = str(spec.get("severity", "")).lower()
    if label in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if label == "moderate" else label
    # CVSS: OSV suele dar el vector; si el campo es un score numérico, banda por umbral.
    for s in vuln.get("severity", []) or []:
        try:
            score = float(str(s.get("score", "")))
        except ValueError:
            continue
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return "high"  # por defecto conservador: un N-day sin severidad clara no es "info"


def _fixed_versions(vuln: dict) -> list[str]:
    out = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    out.append(ev["fixed"])
    return sorted(set(out))


def vuln_to_finding(pkg: Package, vuln: dict, manifest_rel: str) -> Finding:
    osv_id = vuln.get("id", "OSV-?")
    aliases = vuln.get("aliases", []) or []
    cves = [a for a in aliases if a.startswith("CVE-")]
    summary = vuln.get("summary") or (vuln.get("details", "")[:160])
    fixed = _fixed_versions(vuln)
    refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")]
    f = Finding(
        title=f"{pkg.name}@{pkg.version}: {osv_id}" + (f" ({cves[0]})" if cves else ""),
        severity=_severity_of(vuln),
        category="known-vulnerable-dependency",
        target=manifest_rel,
        location=manifest_rel,
        description=(f"{'Direct' if pkg.direct else 'Transitive (indirect)'} dependency with a "
                     f"known vulnerability. {summary}".strip()
                     + (f" Fixed in: {', '.join(fixed)}." if fixed else "")
                     + ("" if pkg.direct else
                        " As a transitive dependency, see the reachability line to know whether "
                        "the vulnerable symbol is actually exercised.")),
        poc="",  # N-day: no hay PoC de ejecución; la evidencia es el match de versión contra OSV
        status="confirmed",
        finder="osv",
    )
    f.meta = {
        "provenance": "osv-match",
        "osv_id": osv_id,
        "cves": cves,
        "ecosystem": pkg.ecosystem,
        "package": pkg.name,
        "version": pkg.version,
        "direct": pkg.direct,
        "fixed": fixed,
        "references": refs[:5],
        "verify": {"stage": "dependency-scan", "reproduced": None, "provenance": "osv-match"},
    }
    return f


@dataclass
class DepScanResult:
    manifests_scanned: int
    packages_checked: int
    findings: list[Finding]
    error: str = ""


def scan(manifests: list[tuple[str, str, str]], *, osv: OSVClient | None = None,
         min_votes: int = 1) -> DepScanResult:
    """manifests = [(ecosystem, ruta_absoluta, ruta_relativa)]. Devuelve findings de N-day.

    `osv` inyectable (tests). Los findings salen con votos suficientes para contar como
    confirmados (un match de OSV es una fuente autoritativa; no pasa por consenso de LLM).
    """
    osv = osv or OSVClient()
    all_pkgs: list[Package] = []
    origin: list[str] = []       # ruta relativa del manifiesto de cada paquete
    scanned = 0
    for ecosystem, abspath, rel in manifests:
        try:
            text = open(abspath, errors="ignore").read()
        except OSError:
            continue
        pkgs = parse_manifest(text, ecosystem, filename=abspath)
        if pkgs:
            scanned += 1
        all_pkgs.extend(pkgs)
        origin.extend([rel] * len(pkgs))

    if not all_pkgs:
        return DepScanResult(scanned, 0, [])

    try:
        ids_per_pkg = osv.query_batch(all_pkgs)
    except Exception as e:  # noqa: BLE001 — sin red / OSV caído: degradar con aviso, no romper
        return DepScanResult(scanned, len(all_pkgs), [], error=f"consulta OSV falló: {e}")

    from .findings import SEVERITIES
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    cache: dict[str, dict] = {}
    by_key: dict[tuple, Finding] = {}     # (paquete, versión, CVE) → dedup de registros OSV
    for pkg, rel, ids in zip(all_pkgs, origin, ids_per_pkg):
        for vid in ids:
            if not vid:
                continue
            if vid not in cache:
                try:
                    cache[vid] = osv.get_vuln(vid)
                except Exception:  # noqa: BLE001
                    cache[vid] = {"id": vid}
            f = vuln_to_finding(pkg, cache[vid], rel)
            f.votes = max(min_votes, 1)   # match autoritativo → cuenta como confirmado
            # Colapsa varios avisos OSV del MISMO CVE en un hallazgo (evita inflar el conteo).
            cve = f.meta["cves"][0] if f.meta.get("cves") else vid
            key = (pkg.name, pkg.version, cve)
            prev = by_key.get(key)
            if prev is None:
                by_key[key] = f
            elif sev_rank.get(f.severity, -1) > sev_rank.get(prev.severity, -1):
                by_key[key] = f          # conserva el registro de mayor severidad
    return DepScanResult(scanned, len(all_pkgs), list(by_key.values()))
