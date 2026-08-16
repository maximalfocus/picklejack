# picklejack

A small, **local, container-only** educational demonstration of **Insecure Deserialization**
(OWASP **A08:2021 Software and Data Integrity Failures**, **CWE-502**) and its fix: **parse a
data-only format into an explicit schema — never reconstruct arbitrary objects from untrusted input.**

> ⚠️ **Local educational code. Do not deploy.** Everything here is fully fictional and self-contained.
> It ships no exploit against any real system and runs only on loopback inside Docker.

The project models a fictional multi-tenant reporting-workspace service. A user can **export** their
workspace as a portable **snapshot** and later **import** a snapshot to reconstruct that view. The
insecure version of such a feature reconstructs attacker-controlled bytes back into live objects (where
reconstructing an object can run code); the secure version parses a **data-only** snapshot into a typed
schema and never builds arbitrary objects.

This repository is being built issue by issue. **Currently delivered:** the secure baseline — the
multi-tenant workspace model, demo authentication, and the secure `GET /workspace/export` /
`POST /workspace/import` endpoints, verified through a Docker Compose boundary. The intentionally
vulnerable contrast app, the deserialization escalation ladder, the comparison CLI, the full regression
matrix, and the walkthrough are added in later slices.

## Requirements

Only **Docker** (with the Docker Compose plugin). No host Python, `uv`, or project packages are needed —
Python, dependencies, and all tooling run inside the image.

## Usage

```sh
# Run the secure API on http://127.0.0.1:8000 (loopback only).
docker compose up --build secure

# One-shot demo: seed fresh deterministic state, exercise the secure and
# legitimate behaviour over real localhost HTTP, report, and exit.
docker compose run --build --rm demo

# Run the full verification boundary (ruff + mypy + pytest) inside the image.
docker compose run --build --rm verify

# Dispose of all state.
docker compose down -v
```

The secure app also serves its generated OpenAPI docs at `http://127.0.0.1:8000/docs`.

## Security model

- The secure `POST /workspace/import` accepts a **data-only** snapshot — JSON parsed into a Pydantic
  schema, or YAML read with `yaml.safe_load` (primitive data only) validated against the **same
  schema**. It contains **no `pickle` path** on any request-borne input and reconstructs a workspace
  solely from allowlisted, typed fields (workspace name, panels, filters).
- Any snapshot that is not a valid data-only snapshot — a forged snapshot, a `pickle` payload, an
  unsafe-YAML payload — is **rejected with one generic response**: nothing is reconstructed as an
  object, a conspicuously fictional demonstration secret held only in code is unreachable, no command
  executes, and no error reveals which fields, types, or formats are accepted.
- For products that genuinely cannot yet drop an opaque binary snapshot, a **secondary,
  defence-in-depth** path (`POST /workspace/import/verified`) **authenticates the snapshot's integrity
  (HMAC) before deserializing** and uses a **restricted `Unpickler` with a type allowlist**. It accepts
  a legitimate server-signed snapshot and rejects a tampered or unsigned one. This is a mitigation, not
  the primary control: a leaked signing key or a dangerous type reachable from otherwise-trusted data
  still bites, so untrusted input should be parsed as data against a schema wherever possible.
- Every snapshot rejection emits exactly one generic structured JSON audit event (actor, tenant, action,
  outcome, correlation id) — never the snapshot, a token, a secret, or the accepted fields/types.
- Fixtures are deterministic and **read-only**: no request path mutates domain state.

## License

Released under the MIT License once the repository is published; see the delivery plan.
