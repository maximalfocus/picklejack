# Contributing to picklejack

Thanks for your interest. `picklejack` is a small, **local, container-only** educational
demonstration of Insecure Deserialization (OWASP **A08:2021**, **CWE-502**) and its fix. The goal
of every change is to keep that lesson **correct, clear, and safe to run locally** — not to grow a
product.

## Ground rules — the safety boundary

Contributions must preserve the boundary the project is built on:

- **Everything stays fictional and local.** No real organizations, users, endpoints, credentials,
  or personal data. All "secrets" are conspicuously fake demonstration values.
- **The code-execution proof stays confined to the read-only `id`.** No destructive, persistent,
  filesystem-writing, stacked, or egress-producing payloads; no reverse shell, container escape,
  or privilege escalation. These are out of scope by design.
- **The vulnerable app stays behind its two opt-in actions** (its Compose profile plus
  `ALLOW_VULNERABLE_DEMO=true`) and inside its hardened, no-egress container.
- **Nothing is hosted or deployed.** Published ports stay loopback-only. There is no production
  target.
- **No secure path regresses.** The secure application must never reconstruct arbitrary objects
  from untrusted input.

## Development

The only host requirement is **Docker** (with the Compose plugin). Python, dependencies, and all
tooling run inside the image — you do not need a host Python environment.

```sh
# Run the full verification boundary (ruff + mypy + pytest), exactly as CI does.
docker compose run --build --rm verify

# One-shot secure demo over real localhost HTTP.
docker compose run --build --rm demo

# Full side-by-side comparison of both apps (opt-in).
ALLOW_VULNERABLE_DEMO=true docker compose --profile compare run --build --rm compare
```

Please make sure `docker compose run --build --rm verify` is green before opening a pull request;
CI runs the identical command.

## Pull requests

- Keep changes small and focused; explain what the change teaches or fixes.
- Update the walkthrough or README when behaviour a reader observes changes.
- Do not include any personal credential — none is required to build, test, or contribute.

## Reporting vulnerabilities

The insecure behaviour of the vulnerable contrast app is intentional. To report an *unintended*
vulnerability, follow [`SECURITY.md`](SECURITY.md) and use the private reporting path rather than a
public issue.
