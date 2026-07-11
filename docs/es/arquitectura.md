# Basalt — Arquitectura

Basalt es un purple-team de agentes de IA con **verificación por ejecución**.
Este documento explica cómo encajan las piezas y cómo extenderlas.

## El pipeline

```
recon → red_find (× N) → purple_verify → EJECUCIÓN → blue_patch → grader
```

1. **recon** (`agents/roles.py`, `prompts/recon.md`) mapea la superficie de
   ataque y prioriza las particiones del objetivo por riesgo (así `--max N`
   audita las N más peligrosas).
2. **red_find** lanza `red_runs` agentes independientes en paralelo por
   partición, cada uno devuelve hallazgos candidatos con un PoC ejecutable. Los
   hallazgos idénticos entre runs acumulan **votos** (consenso).
3. **purple_verify** es un juez LLM escéptico — pre-filtro barato que exige un
   PoC creíble antes de gastar un sandbox.
4. **Ejecución** (`orchestrator._reproduce` + `sandbox/`) copia el objetivo y el
   PoC a un sandbox Docker limpio (`--network none`, con límites) y lo ejecuta.
   El hallazgo se `confirma` solo si el PoC imprime el sentinel
   `BASALT-POC-TRIGGERED`. Es el núcleo anti-falsos-positivos.
5. **blue_patch + grader** proponen un fix mínimo (ficheros completos) y lo
   gradúan por ejecución: el build sigue verde, el PoC ya no dispara y los tests
   pasan.

Los hallazgos se guardan en un `FindingsStore` JSONL (`findings.py`) con dedup
por fingerprint y acumulación de votos. Solo se muestra como `confirmed` cuando
`votos >= min_votes`.

## Procedencia y embudo de verificación

Cada hallazgo registra cómo se estableció en `meta.provenance`:

| Procedencia     | Significado                                             |
|-----------------|--------------------------------------------------------|
| `tool-proven`   | PoC reproducido por ejecución en el sandbox            |
| `osv-match`     | Versión de dependencia con un CVE conocido (OSV.dev)   |
| `pattern-match` | Secreto hardcodeado detectado por patrón               |
| `model-asserted`| El juez aprobó pero se omitió la ejecución (degradado) |

Los informes incluyen un **embudo**: `candidatos → rechazados por el juez → no
reproducidos → confirmados`, para que el filtrado sea visible.

## Escáneres deterministas (sin LLM)

- **`deps.py`** — parsea lockfiles (PyPI/npm/Go/crates.io/RubyGems/Packagist/
  NuGet), consulta OSV.dev, deduplica por CVE y marca deps directas/transitivas.
- **`reachability.py`** — ejecuta `govulncheck` (Go) para marcar hallazgos
  `reachable` / `not-reachable` / `unknown`.
- **`secrets_scan.py`** — escanea con los patrones de redacción; reporta tipo y
  ubicación (nunca el valor del secreto).

## Aislamiento y defensa anti-injection

- El sandbox corre sin red y con límites de CPU/memoria/pids; soporta gVisor
  (`--runtime=runsc`).
- El contenido no confiable del objetivo se envuelve en delimitadores de
  spotlighting y se sanean secretos (`redact.py`) antes de llegar al modelo.
- **Separación de autoridad**: los agentes solo devuelven texto/JSON — nunca
  invocan herramientas ni el sandbox. El orquestador determinista media toda
  ejecución, así una inyección desde el objetivo no puede disparar acciones.

## Extender

- **Proveedor de modelo**: subclase de `ModelProvider` en `providers/` con
  `@register("nombre")`.
- **Target de lenguaje**: subclase de `Target` en `targets/adapters.py`.
- **Categoría de vulnerabilidad**: una entrada `Check` en `checks.py`.
- **Idioma (i18n)**: overrides en `i18n.py`.
