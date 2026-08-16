# picklejack — Insecure Deserialization walkthrough

A five-minute, side-by-side tour of **Insecure Deserialization** and the fix that prevents it.
Everything here runs locally in containers against fictional data.

> ⚠️ **The vulnerable application is intentionally insecure local educational code. Never deploy it.**
> Its code-execution proof is confined to the single read-only `id` command inside a hardened container
> with no network egress. Destructive, persistent, filesystem-writing, stacked, and egress-producing
> payloads are **out of scope by design**.

## Parsing data versus reconstructing objects — the whole idea

Turning bytes back into something usable has two very different meanings:

- **parsing data** — bytes → a validated, typed **data structure** (numbers, strings, lists, dicts). The
  parser only ever produces inert data; it cannot run your code.
- **deserializing into live objects** — bytes → **reconstructed Python objects**. Reconstructing an
  object can *call code* (`pickle` runs an object's `__reduce__`; unsafe YAML executes `!!python/...`
  tags). At that moment attacker-controlled bytes gain the power to run.

Insecure deserialization happens when a service reconstructs **live objects** from **untrusted** bytes.
The two applications differ in exactly this:

| | secure (`POST /workspace/import`) | vulnerable (`POST /workspace/import`) |
|---|---|---|
| untrusted snapshot is treated as | **data** parsed into a schema | **objects** reconstructed from bytes |
| how it loads | `json.loads` / `yaml.safe_load` → Pydantic schema | `pickle.loads` / `yaml.load` (object-constructing) |
| a `pickle` / `!!python/object/apply` payload | rejected generically, nothing built | **runs on the server** |

## Terminology

- **Insecure Deserialization** — a.k.a. **object injection**, **unsafe/untrusted deserialization**.
- **OWASP** — **A08:2021 – Software and Data Integrity Failures**.
- **CWE-502** — *Deserialization of Untrusted Data*.

In plain language: *turning attacker-controlled bytes back into live objects, where reconstructing an
object can run code.*

## The escalation ladder (vulnerable app)

Authenticated as a fictional tenant user, against fresh state, the same flaw is proven through **two
different deserializers** (`pickle` and unsafe PyYAML):

1. **Baseline / legitimate.** A benign snapshot the service issued imports to the tenant's own workspace
   view — indistinguishable from ordinary use, and the secure app imports it **identically**.
2. **Forged snapshot accepted.** A snapshot the service never issued is accepted with **no integrity
   check**, and its attacker-authored object is trusted and reconstructed (object injection).
3. **Information disclosure.** A crafted object reconstructs into the application configuration's
   fictional **integration secret** — data no legitimate snapshot carries. No command runs; state is
   unchanged.
4. **In-container code execution.** A `pickle` `__reduce__` payload **and** an unsafe-YAML
   `!!python/object/apply` payload each reach `os.popen('id')` — a `uid=… gid=…` line — and read the
   planted `DEMO_SENTINEL`. This proves arbitrary command execution inside the container, deliberately
   confined to the read-only `id`.

Against the **secure** app, every one of these is **rejected generically**: nothing is reconstructed
from attacker bytes, the integration secret is unreachable, the `os` module is never reached, no command
runs, and no error reveals which fields, types, or formats are accepted.

## Two lessons

1. **Primary control — parse a data-only format into an explicit schema.** Never reconstruct arbitrary
   objects from untrusted input. Accept a data-only snapshot (JSON, or YAML via `yaml.safe_load`) and
   validate it against an explicit schema, rebuilding only allowlisted, typed fields. "It's just the
   snapshot we exported", allowlisting byte patterns, and "validate the object after we build it" are
   **not** defences — by the time you can validate a reconstructed object, its construction has already
   run.
2. **Defence-in-depth — authenticate integrity and restrict the deserializer, as *escapable*
   mitigation.** For products that genuinely cannot yet drop an opaque binary snapshot, the secure app
   also offers `POST /workspace/import/verified`, which verifies an **HMAC** over the snapshot before
   touching its bytes and deserializes through a **restricted `Unpickler` with a type allowlist**. Treat
   this as secondary: a **leaked signing key** or a **dangerous type reachable from otherwise-trusted
   data** still bites, so parse untrusted input as data against a schema wherever possible.

## Run it

Only Docker (with the Compose plugin) is required.

```sh
# Secure app only, on 127.0.0.1:8000
docker compose up --build secure

# Full side-by-side comparison of BOTH apps over real localhost HTTP
ALLOW_VULNERABLE_DEMO=true docker compose --profile compare run --build --rm compare

# The vulnerable app for manual exploration on 127.0.0.1:8001 (two opt-in actions)
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build vulnerable vuln-proxy

# Verification: ruff + mypy + pytest (identical locally and in CI)
docker compose run --build --rm verify

# Prove the vulnerable container's hardening + no egress
ALLOW_VULNERABLE_DEMO=true bash scripts/verify-vulnerable-hardening.sh

# Dispose of all state
docker compose down -v
```

### Local OpenAPI exploration

While a service is up, its generated OpenAPI docs are served locally:

- secure: `http://127.0.0.1:8000/docs`
- vulnerable: `http://127.0.0.1:8001/docs`

### Expected `compare` output

For each snapshot the CLI prints, per app: whether the app **rebuilt objects** from untrusted bytes or
parsed **data** into a schema, which **deserializer** ran, the returned **workspace/output**, whether the
**integration secret leaked**, whether **`os.popen('id')` executed**, and an explicit **vulnerable/secure
verdict**. The vulnerable app is flagged on the attack snapshots; the secure app is flagged on none; both
produce identical benign output.

## Safety recap

- Only the read-only `id` is ever executed; the demo performs no destructive, persistent, or
  egress-producing action.
- Disposable fixture state is byte-for-byte identical before and after every run.
- The vulnerable container runs non-root, with all capabilities dropped, `no-new-privileges`, a
  read-only root filesystem, and **no network egress**.
- All organizations, users, workspaces, tokens, and "secrets" are fictional.
