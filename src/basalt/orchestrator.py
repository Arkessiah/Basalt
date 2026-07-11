"""Orquestador del purple-team: recon → red(find ×N) → purple(verify) → blue(patch) → grader.

Regla de oro: un hallazgo NO es real hasta que el purple lo reproduce por EJECUCIÓN
en sandbox limpio; el consenso por votos (N runs) filtra alucinaciones antes de
molestar al blue.

Verificación en dos etapas:
  1) JUEZ LLM (pre-filtro barato): descarta lo que ni siquiera tiene un PoC creíble.
  2) EJECUCIÓN (autoritativa): reproduce el PoC en un DockerSandbox limpio y solo
     confirma si el exploit emite el sentinel. Sin ejecución, no hay "confirmed".
"""
from __future__ import annotations
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable
from .config import Settings
from .agents.roles import ROLES
from .findings import Finding, FindingsStore
from .targets.base import Partition
from .targets.adapters import make_target
from .sandbox.base import Sandbox, POC_SENTINEL, SandboxUnavailable
from .sandbox.docker_sandbox import DockerSandbox


# Delimitadores de spotlighting: TODO lo que va dentro es contenido NO CONFIABLE del
# target (datos a analizar), nunca instrucciones. Defensa anti-prompt-injection: un
# target hostil puede incrustar órdenes en su código/comentarios/README para secuestrar
# al agente. Los prompts de rol instruyen a ignorar/instrucciones dentro de estos marcadores.
_UNTRUSTED_OPEN = "<<<UNTRUSTED_TARGET_CONTENT>>>"
_UNTRUSTED_CLOSE = "<<<END_UNTRUSTED_TARGET_CONTENT>>>"


def _wrap_untrusted(text: str) -> str:
    # Sanitiza secretos antes de que el contenido del target llegue al modelo/logs:
    # el marcador preserva la señal (hay un secreto) sin exponer el valor real.
    from .redact import redact
    red, _n = redact(text)
    return f"{_UNTRUSTED_OPEN}\n{red}\n{_UNTRUSTED_CLOSE}"


def _extract_json_array(text: str) -> list | None:
    """Extrae un array JSON de una respuesta de LLM, tolerando fences ```json,
    prosa alrededor, o un objeto envoltorio `{"findings": [...]}`."""
    if not text:
        return None
    # 1) quita fences de código markdown
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    body = fenced.group(1) if fenced else text
    # 2) intento directo (array u objeto con 'findings'/'results')
    for candidate in (body.strip(), text.strip()):
        try:
            data = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("findings", "results", "items", "vulnerabilities"):
                if isinstance(data.get(k), list):
                    return data[k]
    # 3) fallback: primer '[' … último ']'
    m = re.search(r"\[.*\]", body, re.S) or re.search(r"\[.*\]", text, re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            return data if isinstance(data, list) else None
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def _parse_findings_json(text: str, target: str, finder: str) -> list[Finding]:
    """Extrae un array JSON de hallazgos de la respuesta del red agent (tolerante)."""
    items = _extract_json_array(text)
    if items is None:
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(Finding(
            title=it.get("title", "sin título"),
            severity=str(it.get("severity", "medium")).lower(),
            category=it.get("category", "unknown"),
            target=target,
            location=it.get("location", ""),
            description=it.get("description", ""),
            poc=it.get("poc", ""),
            finder=finder,
        ))
    return out


@dataclass
class AuditReport:
    target: str
    total_candidates: int
    confirmed: list[Finding]
    funnel: dict = field(default_factory=dict)  # embudo: candidatos→rechazados→confirmados

    def summary(self) -> str:
        fn = self.funnel or {}
        return (f"Target: {self.target}\n"
                f"Embudo: {self.total_candidates} candidatos → "
                f"{fn.get('rejected_judge', 0)} rechazados por el juez → "
                f"{fn.get('rejected_exec', 0)} no reproducidos en sandbox → "
                f"{len(self.confirmed)} CONFIRMADOS (verificados por ejecución + votados)")


@dataclass
class PatchOutcome:
    """Resultado de parchear un hallazgo confirmado y graduarlo por ejecución."""
    finding: Finding
    accepted: bool
    checks: dict          # {"build", "poc_closed", "tests_pass"}
    notes: str = ""
    files: list[str] = None  # ficheros modificados por el blue

    def __post_init__(self):
        if self.files is None:
            self.files = []


class Orchestrator:
    def __init__(self, cfg: Settings, target_root: str,
                 sandbox_factory: Callable[[], Sandbox] | None = None):
        self.cfg = cfg
        self.target = make_target(cfg.target_kind, target_root)
        self.store = FindingsStore(cfg.store_path)
        self.agents = {r: ROLES[r](cfg.roles[r]) for r in ROLES}
        # Inyectable para tests; por defecto un DockerSandbox limpio por verificación.
        self._sandbox_factory = sandbox_factory or self._default_sandbox

    def _default_sandbox(self) -> Sandbox:
        sb = self.cfg.sandbox or {}
        driver = sb.get("driver", "docker")
        if driver != "docker":
            raise SandboxUnavailable(f"driver de sandbox no soportado: {driver!r}")
        # Imagen: la de config si se fija; si no, la del toolchain del lenguaje.
        image = sb.get("image") or self.target.default_image
        return DockerSandbox(
            image=image,
            gvisor=sb.get("gvisor", False),
            cpus=str(sb.get("cpus", "2")),
            memory=str(sb.get("memory", "2g")),
        )

    def plan(self, max_partitions: int | None = None) -> dict:
        """Estimación de coste SIN llamar a modelos (para `--dry-run`)."""
        parts = self.target.partitions()
        total = len(parts)
        if max_partitions:
            parts = parts[:max_partitions]
        return {
            "target": self.target.root, "kind": self.target.kind,
            "partitions_total": total, "partitions_audited": len(parts),
            "red_runs": self.cfg.red_runs,
            "recon_calls": 1 if self.cfg.recon else 0,
            "find_calls": len(parts) * self.cfg.red_runs,
            "note": ("verificación (juez + ejecución en sandbox) y patch son variables "
                     "según el nº de candidatos que produzca el red"),
        }

    def audit(self, max_partitions: int | None = None,
              on_partition: Callable[[int, int, str], None] | None = None,
              only_paths: set[str] | None = None) -> AuditReport:
        parts = self.target.partitions()
        if only_paths is not None:              # modo --changed: solo particiones tocadas
            want = {os.path.realpath(p) for p in only_paths}
            parts = [pt for pt in parts
                     if any(os.path.realpath(p) in want for p in pt.paths)]
        if self.cfg.recon:
            parts = self._recon(parts)          # el LLM prioriza por riesgo → `--max` coge las peores
        if max_partitions:
            parts = parts[:max_partitions]
        candidates = 0
        funnel = {"rejected_judge": 0, "rejected_exec": 0, "confirmed_reproductions": 0}
        for i, part in enumerate(parts):
            if on_partition:
                on_partition(i + 1, len(parts), part.name)
            ctx = self.target.context(part)
            cands = self._find_parallel(part, ctx)          # RED ×N en paralelo (consenso)
            candidates += len(cands)
            self._verify_parallel(cands, part, ctx, funnel)  # verificación por ejecución + embudo
        confirmed = self.store.confirmed(self.cfg.min_votes)
        funnel["candidates"] = candidates
        funnel["confirmed"] = len(confirmed)
        return AuditReport(self.target.root, candidates, confirmed, funnel)

    def _recon(self, parts: list[Partition]) -> list[Partition]:
        """RECON — el LLM prioriza las particiones por riesgo y puede refinar el hint.
        Robusto: ante cualquier fallo, mantiene el orden original."""
        if len(parts) < 2:
            return parts
        listing = "\n".join(f"- {p.name}: {p.hint}" for p in parts[:300])
        q = ("Prioriza estas particiones por RIESGO de seguridad. Devuelve SOLO un array JSON "
             '[{"name","risk":"low|medium|high","hint"}] ordenado de MAYOR a menor riesgo.\n\n'
             + _wrap_untrusted(listing))
        try:
            order = _extract_json_array(self.agents["recon"].run(q, temperature=0.0))
        except Exception:  # noqa: BLE001
            return parts
        if not order:
            return parts
        rank = {"high": 0, "medium": 1, "low": 2}
        by_name = {p.name: p for p in parts}
        seq: list[tuple[int, Partition]] = []
        used: set[str] = set()
        for it in order:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            if name in by_name and name not in used:
                used.add(name)
                p = by_name[name]
                if it.get("hint"):
                    p = Partition(name=p.name, paths=p.paths, hint=str(it["hint"]))
                seq.append((rank.get(str(it.get("risk", "medium")).lower(), 1), p))
        for p in parts:                          # las no mencionadas, al final
            if p.name not in used:
                seq.append((3, p))
        seq.sort(key=lambda t: t[0])
        return [p for _, p in seq]

    def _find_parallel(self, part: Partition, ctx: str) -> list[Finding]:
        """Lanza los `red_runs` find-agents en paralelo y agrega sus candidatos.

        Cada run es una reproducción independiente: hallazgos con el mismo fingerprint
        en runs distintos se convierten en VOTOS al verificarse (consenso anti-alucinación).
        """
        from . import checks
        catalog = checks.prompt_block(self.target.kind, self.cfg.checks or None)
        prompt = (f"OBJETIVO: {part.name}\nPISTA superficie: {part.hint}\n\n"
                  + (f"{catalog}\n\n" if catalog else "")
                  + f"CÓMO ESCRIBIR EL PoC (lenguaje {self.target.kind}):\n"
                  f"{self.target.poc_instructions()}\n\n"
                  f"Devuelve SOLO un array JSON de hallazgos "
                  f"[{{title,severity,category,location,description,poc}}].\n\n"
                  f"{_wrap_untrusted(ctx)}")
        finder = self.cfg.roles["red_find"].name

        def one_run(_i: int) -> list[Finding]:
            try:
                text = self.agents["red_find"].run(prompt)
            except Exception:  # noqa: BLE001 — un run que falla no debe tumbar la auditoría
                return []
            return _parse_findings_json(text, part.name, finder)

        out: list[Finding] = []
        with ThreadPoolExecutor(max_workers=self._workers(self.cfg.red_runs)) as ex:
            for lst in ex.map(one_run, range(self.cfg.red_runs)):
                out.extend(lst)
        return out

    def _verify_parallel(self, cands: list[Finding], part: Partition, ctx: str,
                         funnel: dict | None = None) -> None:
        """Verifica cada candidato por EJECUCIÓN (cada uno en su sandbox), vota en el store
        y alimenta el EMBUDO (rechazados por juez / por ejecución / confirmados).

        El acceso al `FindingsStore` y al `funnel` va bajo lock (no son thread-safe); cada
        verificación usa su propio sandbox vía la factory, así que corren independientes.
        """
        lock = threading.Lock()

        def verify_and_store(f: Finding) -> None:
            try:
                ok = self._verify(f, part, ctx)
            except Exception:  # noqa: BLE001
                ok = False
            stage = (f.meta.get("verify") or {}).get("stage", "") if isinstance(f.meta, dict) else ""
            with lock:
                if ok:
                    f.status = "confirmed"
                    self.store.add(f)   # suma voto si ya existía (dedupe por fingerprint)
                    if funnel is not None:
                        funnel["confirmed_reproductions"] = funnel.get("confirmed_reproductions", 0) + 1
                else:
                    self.store.record_rejected(f)   # persiste el rechazo (embudo del informe)
                    if funnel is not None:
                        key = "rejected_judge" if stage == "judge" else "rejected_exec"
                        funnel[key] = funnel.get(key, 0) + 1

        if not cands:
            return
        with ThreadPoolExecutor(max_workers=self._workers(len(cands))) as ex:
            list(ex.map(verify_and_store, cands))

    def _workers(self, n: int) -> int:
        """Concurrencia acotada: nunca menos de 1 ni más que `max_parallel`."""
        return max(1, min(n, self.cfg.max_parallel))

    # --- N-day por dependencia (scan de lockfiles vs OSV) -------------------
    def scan_dependencies(self, osv=None):
        """Cruza los lockfiles del target vs OSV.dev y añade los N-day al store.

        Hallazgos confirmados por match autoritativo (provenance `osv-match`), no por
        ejecución. No usa sandbox (no ejecuta código del target), pero requiere red.
        """
        from . import deps
        manifests = self.target.dependency_manifests()
        result = deps.scan(manifests, osv=osv, min_votes=self.cfg.min_votes)
        for f in result.findings:
            self.store.update(f)   # confirmado por OSV; no pasa por consenso de votos
        return result

    def _verify(self, f: Finding, part: Partition, ctx: str) -> bool:
        """Puerta anti-falsos-positivos en dos etapas.

        1) Juez LLM (barato): si dice que no es real, se descarta sin gastar sandbox.
        2) Ejecución (autoritativa): el PoC debe reproducir en sandbox limpio.
        Con `require_execution=False` la etapa 2 se omite (modo degradado explícito).
        """
        if not self._judge(f, ctx):
            f.meta["verify"] = {"stage": "judge", "reproduced": False}
            return False
        if not self.cfg.require_execution:
            f.meta["verify"] = {"stage": "judge-only", "reproduced": True}
            f.meta["provenance"] = "model-asserted"   # solo opinión del juez, sin ejecución
            return True
        try:
            reproduced = self._reproduce(f, part)
            if reproduced:
                f.meta["provenance"] = "tool-proven"   # reproducido por ejecución en sandbox
        except SandboxUnavailable as e:
            # Sin ejecución NO se promueve a confirmado: el juez solo no basta.
            f.meta["verify"] = {"stage": "exec", "reproduced": False,
                                "reason": f"sandbox no disponible: {e}"}
            return False
        return reproduced

    def _judge(self, f: Finding, ctx: str) -> bool:
        """PURPLE — juez adversarial LLM. Pre-filtro escéptico (exige PoC creíble)."""
        q = (f"Hallazgo a verificar (sé ESCÉPTICO; rechaza si no hay PoC reproducible o "
             f"es falso positivo). Responde JSON {{\"real\": bool, \"reason\": str}}.\n\n"
             f"{json.dumps(f.__dict__, ensure_ascii=False)}\n\nCONTEXTO:\n"
             f"{_wrap_untrusted(ctx[:6000])}")
        out = self.agents["purple_verify"].run(q, temperature=0.0)
        m = re.search(r"\{.*\}", out, re.S)
        try:
            return bool(json.loads(m.group(0)).get("real")) if m else False
        except Exception:
            return False

    @staticmethod
    def _looks_like_cold_start(r) -> bool:
        """Heurística: contenedor que no llegó a ejecutar (exit≠0 sin salida alguna).

        Un fallo real de PoC casi siempre deja rastro (traceback en stderr); vacío total
        con exit≠0 y sin timeout apunta a un cold-start transitorio de Docker."""
        return (not r.timed_out) and r.exit_code != 0 and not r.stdout and not r.stderr

    def _run_retry(self, sb, cmd, *, timeout: int, network: bool, retries: int = 1):
        """Ejecuta `cmd` reintentando ante cold-start transitorio de Docker."""
        r = sb.run(cmd, timeout=timeout, network=network)
        while retries > 0 and self._looks_like_cold_start(r):
            retries -= 1
            r = sb.run(cmd, timeout=timeout, network=network)
        return r

    def _reproduce(self, f: Finding, part: Partition) -> bool:
        """Reproduce el PoC por EJECUCIÓN en un sandbox limpio.

        Reproducido ⇔ el `reproduce_cmd` corre sin timeout y su stdout contiene el
        sentinel `BASALT-POC-TRIGGERED`. Un build que falla o un PoC que no dispara el
        sentinel = NO reproducido (conservador: nunca confirma por accidente).
        """
        rcmd = self.target.reproduce_cmd()
        if not rcmd:
            f.meta["verify"] = {"stage": "exec", "reproduced": False,
                                "reason": "target sin reproduce_cmd"}
            return False
        sb_cfg = self.cfg.sandbox or {}
        with self._sandbox_factory() as sb:
            sb.put_tree(self.target.root)                      # contexto de build
            poc_path, poc_content = self.target.poc_artifact(f)
            sb.write(poc_content or f.poc, poc_path)           # materializa el PoC
            build = self.target.build_cmd()
            if build:
                b = self._run_retry(sb, build, timeout=sb_cfg.get("build_timeout", 300),
                                    network=sb_cfg.get("build_network", False),
                                    retries=sb_cfg.get("retries", 1))
                if not b.ok:
                    f.meta["verify"] = {"stage": "build", "reproduced": False,
                                        "reason": "build falló", "tail": b.stderr[-800:]}
                    return False
            r = self._run_retry(sb, rcmd, timeout=sb_cfg.get("poc_timeout", 180),
                                network=sb_cfg.get("network", False),
                                retries=sb_cfg.get("retries", 1))
            reproduced = (not r.timed_out) and (POC_SENTINEL in r.stdout)
            f.meta["verify"] = {"stage": "exec", "reproduced": reproduced,
                                "exit": r.exit_code, "sentinel": POC_SENTINEL,
                                "tail": r.stdout[-800:]}
            return reproduced

    # --- Fase BLUE (patch) + GRADER (confirmación por ejecución) -------------
    def patch(self, findings: list[Finding] | None = None) -> list[PatchOutcome]:
        """Parchea los hallazgos confirmados y grada cada patch por EJECUCIÓN.

        Un patch se ACEPTA solo si, en sandbox limpio: (1) el build sigue verde,
        (2) el PoC original YA NO emite el sentinel (vuln cerrada) y (3) los tests
        existentes pasan. Aceptado → status `patched`.
        """
        targets = findings if findings is not None else self.store.confirmed(self.cfg.min_votes)
        parts = {p.name: p for p in self.target.partitions()}
        outcomes: list[PatchOutcome] = []
        for f in targets:
            part = parts.get(f.target)
            ctx = self.target.context(part) if part else f"{f.description}\n\nPoC:\n{f.poc}"
            patch = self._blue_patch(f, ctx)
            if not patch or not patch.get("files"):
                outcomes.append(PatchOutcome(
                    f, False, {"build": False, "poc_closed": False, "tests_pass": False},
                    notes="blue no produjo un patch aplicable"))
                continue
            outcome = self._grade_patch(f, patch)
            if outcome.accepted:
                f.status = "patched"
                f.meta["patch"] = {"files": outcome.files, "checks": outcome.checks,
                                   "rationale": patch.get("rationale", "")}
                self.store.update(f)      # cambia status sin sumar voto
            outcomes.append(outcome)
        return outcomes

    def _blue_patch(self, f: Finding, ctx: str) -> dict | None:
        """BLUE — propone un fix mínimo (ficheros completos). Devuelve el JSON parseado."""
        q = (f"Hallazgo CONFIRMADO a parchear. Devuelve SOLO JSON "
             f'{{"files":[{{"path","content"}}],"test":"...","rationale":"..."}} con el '
             f"contenido COMPLETO de cada fichero modificado (no un diff).\n\n"
             f"{json.dumps(f.__dict__, ensure_ascii=False)}\n\nCÓDIGO:\n"
             f"{_wrap_untrusted(ctx[:8000])}")
        out = self.agents["blue_patch"].run(q, temperature=0.1)
        m = re.search(r"\{.*\}", out, re.S)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def _grade_patch(self, f: Finding, patch: dict) -> PatchOutcome:
        """GRADER — confirma el patch por EJECUCIÓN: build verde + PoC cerrado + tests OK."""
        checks = {"build": False, "poc_closed": False, "tests_pass": False}
        files = [s for s in patch.get("files", []) if isinstance(s, dict) and s.get("path")]
        paths = [s["path"] for s in files]
        if not files:
            return PatchOutcome(f, False, checks, "patch sin ficheros", paths)
        rcmd = self.target.reproduce_cmd()
        if not rcmd:
            return PatchOutcome(f, False, checks, "target sin reproduce_cmd", paths)
        sb_cfg = self.cfg.sandbox or {}
        try:
            sb = self._sandbox_factory()
        except SandboxUnavailable as e:
            return PatchOutcome(f, False, checks, f"sandbox no disponible: {e}", paths)
        with sb:
            sb.put_tree(self.target.root)
            for spec in files:                                  # aplica el fix
                sb.write(spec.get("content", ""), spec["path"])
            poc_path, poc_content = self.target.poc_artifact(f)  # PoC original
            sb.write(poc_content or f.poc, poc_path)

            build = self.target.build_cmd()
            if build:
                b = sb.run(build, timeout=sb_cfg.get("build_timeout", 300),
                           network=sb_cfg.get("build_network", False))
                checks["build"] = b.ok
                if not b.ok:
                    return PatchOutcome(f, False, checks, "el patch rompe el build", paths)
            else:
                checks["build"] = True

            r = sb.run(rcmd, timeout=sb_cfg.get("poc_timeout", 180),
                       network=sb_cfg.get("network", False))
            checks["poc_closed"] = (not r.timed_out) and (POC_SENTINEL not in r.stdout)

            test = self.target.test_cmd()
            if test:
                t = sb.run(test, timeout=sb_cfg.get("test_timeout", 300),
                           network=sb_cfg.get("build_network", False))
                checks["tests_pass"] = t.ok
            else:
                checks["tests_pass"] = True

        accepted = all(checks.values())
        note = "patch aceptado" if accepted else "patch rechazado (algún check falló)"
        return PatchOutcome(f, accepted, checks, note, paths)
