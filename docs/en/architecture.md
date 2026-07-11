# Basalt — Architecture

Basalt is a purple-team of AI agents with **execution-based verification**. This
document explains how the pieces fit together and how to extend them.

## The pipeline

```
recon → red_find (× N) → purple_verify → EXECUTION → blue_patch → grader
```

1. **recon** (`agents/roles.py`, `prompts/recon.md`) maps the attack surface and
   prioritizes the target's partitions by risk. Output reorders which partitions
   get audited first (so `--max N` audits the riskiest N).
2. **red_find** runs `red_runs` independent agents in parallel per partition,
   each returning candidate findings with a runnable PoC. Identical findings
   across runs accrue **votes** (consensus).
3. **purple_verify** is a skeptical LLM judge — a cheap pre-filter that demands a
   credible PoC before spending a sandbox run.
4. **Execution** (`orchestrator._reproduce` + `sandbox/`) copies the target and
   the PoC into a clean Docker sandbox (`--network none`, resource-limited) and
   runs it. The finding is `confirmed` only if the PoC prints the sentinel
   `BASALT-POC-TRIGGERED`. This is the anti-false-positive core.
5. **blue_patch + grader** propose a minimal fix (full file contents) and grade
   it by execution: build stays green, the PoC no longer fires, tests still pass.

Findings are stored in a JSONL `FindingsStore` (`findings.py`) with dedup by
fingerprint and vote accumulation. A finding is only surfaced as `confirmed`
when `votes >= min_votes`.

## Provenance & the verification funnel

Every finding records how it was established in `meta.provenance`:

| Provenance      | Meaning                                              |
|-----------------|------------------------------------------------------|
| `tool-proven`   | PoC reproduced by execution in the sandbox           |
| `osv-match`     | Dependency version matched a known CVE (OSV.dev)     |
| `pattern-match` | Hardcoded secret matched by regex                    |
| `model-asserted`| Judge approved but execution was skipped (degraded)  |

Reports include a **funnel**: `candidates → rejected by judge → not reproduced →
confirmed`, so the filtering is visible.

## Deterministic scanners (no LLM)

- **`deps.py`** — parses lockfiles (PyPI/npm/Go/crates.io/RubyGems/Packagist/
  NuGet), queries OSV.dev, dedups by CVE, and marks direct vs transitive deps.
- **`reachability.py`** — runs `govulncheck` for Go to mark findings
  `reachable` / `not-reachable` / `unknown`.
- **`secrets_scan.py`** — scans files with the redaction patterns; reports type
  and location only (never the secret value).

## Isolation & injection defense

- The sandbox runs with networking disabled and CPU/memory/pids limits; gVisor
  (`--runtime=runsc`) is supported.
- Untrusted target content is wrapped in spotlighting delimiters and
  secret-redacted (`redact.py`) before it reaches any model.
- **Separation of authority**: model agents only return text/JSON — they never
  invoke tools or the sandbox. The deterministic orchestrator mediates all
  execution, so an injection from the target cannot trigger actions.

## Extending

- **Model provider**: subclass `ModelProvider` in `src/basalt/providers/` and
  decorate with `@register("name")`. Providers get retry/backoff for free.
- **Language target**: subclass `Target` in `src/basalt/targets/adapters.py`
  with a default sandbox image, a PoC harness, and (optionally) a dependency
  ecosystem.
- **Vulnerability category**: add a `Check` to `src/basalt/checks.py`.
- **Language (i18n)**: add overrides in `src/basalt/i18n.py`.
