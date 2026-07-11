# Changelog

All notable changes to Basalt are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-10

First public release.

### Added

- **Execution-based verification core.** `recon → red → purple →
  execution → blue → grader`. A finding is only `confirmed` when its PoC is
  reproduced in a clean, network-less Docker sandbox (sentinel
  `BASALT-POC-TRIGGERED`) with consensus voting across parallel runs.
- **Multi-language targets**: Python, Go, TypeScript/JS, Rust, Solidity, and a
  generic fallback — each with its own sandbox toolchain image and PoC harness.
- **Dependency N-day scanning** against [OSV.dev](https://osv.dev) for PyPI,
  npm, Go, crates.io, RubyGems, Packagist and NuGet lockfiles, with CVE dedup
  and direct/transitive marking.
- **Go reachability** via `govulncheck` (reachable / not-reachable / unknown).
- **Hardcoded-secret scanning** (cross-language) that never stores secret
  values.
- **Reports**: Markdown, JSON, HTML, and a professional Word + PDF audit
  document with an evidence bundle (zip + integrity hash). Verification funnel
  and honest provenance labels.
- **CI-gate**: `--fail-on <severity>`, a `gate` command, and `--changed` to
  audit only files changed vs a base branch.
- **Pluggable model providers** (`claude_cli`, `claude_api`, `openai_compat`,
  `ollama`) with retry/backoff and per-role fallback chains.
- **MCP server** (`basalt mcp-serve`) exposing audit tools to MCP clients.
- **i18n**: English by default, Spanish via `lang: es`, extensible.
- Prompt-injection hardening (content spotlighting, secret redaction).

### Known limitations

- The **LLM discovery path** (recon → red logic-bug finding) is **beta**;
  the deterministic scanners (N-day, reachability, secrets) are stable.
- Reachability is Go-only (`govulncheck`); other ecosystems report `unknown`.
- Solidity PoC reproduction needs `forge-std` in the target project.
