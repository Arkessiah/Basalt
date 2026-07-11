# Security Policy

## Authorized use only

Basalt is a **defensive** security tool. It finds vulnerabilities, writes
proof-of-concept exploits, and verifies them by execution in an isolated
sandbox. Only run Basalt against:

- code and infrastructure that **you own**, or
- targets you have **explicit written authorization** to test.

Using Basalt against systems you do not own or are not authorized to test may
be illegal. You are solely responsible for how you use this tool. The authors
accept no liability for misuse (see `LICENSE`).

### Operational safety

- Basalt executes generated PoCs and target code inside a Docker sandbox with
  networking disabled (`--network none`) and resource limits. Do **not** disable
  this isolation when auditing untrusted code.
- The agents read untrusted target content and are therefore a prompt-injection
  surface. Basalt mitigates this (content spotlighting, secret redaction, and a
  design where model agents never invoke tools directly), but treat any host
  running audits as you would any code-execution environment.

## Reporting a vulnerability in Basalt

If you discover a security issue **in Basalt itself**, please report it
privately — do **not** open a public issue.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this
  repository, or
- open a minimal private channel with the maintainer.

Please include: affected version/commit, a description, and a reproduction if
possible. We aim to acknowledge reports within a few days and will coordinate a
fix and disclosure timeline with you.

## Supported versions

Basalt is pre-1.0. Security fixes land on `main`; pin a commit for
reproducibility.
