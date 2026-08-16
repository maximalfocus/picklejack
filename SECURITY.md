# Security Policy

## This project contains intentionally vulnerable code

`picklejack` is a **local, container-only educational demonstration**. It deliberately ships an
**intentionally insecure** application that reconstructs untrusted bytes into live Python objects
(`pickle.loads` / `yaml.load`) with no integrity check, so that Insecure Deserialization
(OWASP **A08:2021 Software and Data Integrity Failures**, **CWE-502**) can be shown next to its
fix. That behaviour — forged-snapshot acceptance, object-injection disclosure of a conspicuously
fictional demonstration secret, and in-container execution of the single read-only command `id`
through both deserializers — is **by design and in scope**. It is not a defect, and reports about
the intentionally vulnerable contrast app behaving insecurely will be closed as working as
intended.

The vulnerable application only starts behind **two deliberate opt-in actions** (its Compose
profile plus `ALLOW_VULNERABLE_DEMO=true`), runs non-root in a hardened, read-only, **no-egress**
container, publishes nothing beyond loopback, and executes no command other than `id`. It must
never be deployed. See [`README.md`](README.md) and [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

## Reporting an *unintended* vulnerability

If you find a security problem that is **not** part of the intentional demonstration — for example
in the secure application, the build or container configuration, the tooling, or anything that
could harm someone running the demo locally — please report it **privately**, not in a public
issue:

- Use **GitHub's private vulnerability reporting** for this repository:
  **Security → Advisories → Report a vulnerability**
  (`https://github.com/maximalfocus/picklejack/security/advisories/new`).

Please include the affected file or command, what you observed, and how to reproduce it. Because
everything is fictional and local, do not include any real credential, personal data, or details
of a third-party system.

## Scope and expectations

This is educational software with **no hosted service** and **no production-safety claim**. It
carries no service-level, support-duration, compatibility, or response-time commitment. There is
no supported production deployment to patch; fixes are made on a best-effort basis to keep the
demonstration correct and safe to run locally.
