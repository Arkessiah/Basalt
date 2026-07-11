# Contributing to Basalt

Thanks for your interest! Basalt is a purple-team of AI agents that audits code
security and **verifies findings by execution**. Contributions are welcome.

## Development setup

```bash
git clone https://github.com/Arkessiah/Basalt
cd Basalt
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,claude,doc]"     # add ,mcp for the MCP server
cp config/basalt.example.yaml config/basalt.yaml
```

Docker is required to run execution-based verification. `govulncheck`
(`go install golang.org/x/vuln/cmd/govulncheck@latest`) is optional, for Go
reachability.

## Before opening a PR

```bash
ruff check src tests     # lint (line length 110)
pytest -q                # tests must pass (no Docker/network needed — fakes)
```

CI runs `ruff` + `pytest` on Python 3.11 and 3.12.

## Guidelines

- **Keep the anti-false-positive core honest.** A finding is only `confirmed`
  when reproduced by execution (sentinel `BASALT-POC-TRIGGERED`) or matched
  against an authoritative DB (OSV). Never promote a finding on model opinion
  alone; label provenance accurately (`tool-proven` / `model-asserted` /
  `osv-match` / `pattern-match`).
- **Providers, targets and checks are pluggable.** Add a model backend as a
  class in `src/basalt/providers/` with `@register`; a language as a `Target`
  in `src/basalt/targets/`; a vulnerability category in `src/basalt/checks.py`.
- **User-facing output is i18n'd.** English is the source; add Spanish (or new
  language) overrides in `src/basalt/i18n.py`.
- **Never weaken sandbox isolation** to make something pass.
- Add tests for new behavior. Match the surrounding style.

## Commit / PR

- Small, focused PRs with a clear description.
- Reference an issue when applicable.
- By contributing you agree your work is licensed under the project's MIT
  license.
