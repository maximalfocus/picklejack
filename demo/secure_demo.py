"""One-shot secure-app demonstration over real localhost HTTP.

Authenticates as a fictional tenant user and drives the secure
``GET /workspace/export`` / ``POST /workspace/import`` endpoints:

* a benign, server-issued snapshot round-trips (export → import) to the tenant's
  own workspace view, in both the JSON and YAML data-only formats;
* a forged JSON snapshot, an object-constructing unsafe-YAML snapshot, and a
  pickle snapshot are each rejected with one generic response — nothing is
  reconstructed from attacker bytes, the fictional integration secret never
  appears, and no ``id`` output (``uid=``) is produced.

Exits non-zero if any expected outcome does not hold, so the container run doubles
as a check.
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import sys

import httpx

from picklejack.config import DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET

BASE_URL = os.environ.get("PICKLEJACK_BASE_URL", "http://127.0.0.1:8000")
TOKEN = "demo-token-globex-mallory"
EXPECTED_TENANT = "globex"
EXPECTED_WORKSPACE = "Globex Ops Overview"

# A forged JSON snapshot the service never issued: it smuggles an extra field.
FORGED_JSON = json.dumps(
    {
        "workspace_name": "Forged",
        "panels": [],
        "filters": [],
        "stolen_secret": "give-me-the-key",
    }
)

# An object-constructing YAML snapshot. yaml.safe_load refuses the tag instead of
# calling os.popen, so this never executes on the secure path.
UNSAFE_YAML = "!!python/object/apply:os.popen ['id']"

# A real pickle snapshot (benign dict bytes). The secure app has no pickle path,
# so it is refused by format without ever being unpickled.
PICKLE_SNAPSHOT = base64.b64encode(
    pickle.dumps({"workspace_name": "Forged", "panels": [], "filters": []})
).decode()


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def _export(client: httpx.Client, fmt: str) -> httpx.Response:
    return client.get("/workspace/export", params={"format": fmt}, headers=_auth())


def _import(client: httpx.Client, fmt: str, data: str) -> httpx.Response:
    return client.post("/workspace/import", headers=_auth(), json={"format": fmt, "data": data})


def _import_verified(client: httpx.Client, data: str, signature: str) -> httpx.Response:
    return client.post(
        "/workspace/import/verified",
        headers=_auth(),
        json={"data": data, "signature": signature},
    )


def _leaks(text: str) -> str | None:
    if FICTIONAL_INTEGRATION_SECRET in text:
        return "integration secret leaked"
    if DEMO_SENTINEL in text:
        return "demo sentinel leaked"
    if "uid=" in text:
        return "command execution reached (found uid=)"
    return None


def main() -> int:
    failures: list[str] = []

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        print(f"picklejack secure demo → {BASE_URL}\n")

        # 1. Legitimate round-trip in both data-only formats.
        print(f"{'scenario':<40} | outcome")
        print("-" * 80)
        for fmt in ("json", "yaml"):
            exported = _export(client, fmt)
            exported.raise_for_status()
            envelope = exported.json()
            imported = _import(client, envelope["format"], envelope["data"])
            imported.raise_for_status()
            body = imported.json()
            ok = (
                body["tenant"] == EXPECTED_TENANT
                and body["workspace"]["workspace_name"] == EXPECTED_WORKSPACE
                and body["import_mode"] == "data-into-schema"
            )
            status_text = "restored own workspace" if ok else "MISMATCH"
            print(f"{f'benign round-trip ({fmt})':<40} | {status_text}")
            if not ok:
                failures.append(
                    f"benign {fmt} round-trip did not restore the tenant's own workspace"
                )

        # 2. Dangerous snapshots are each rejected generically.
        rejections = [
            ("forged JSON snapshot (extra field)", "json", FORGED_JSON),
            ("unsafe-YAML snapshot (!!python/...)", "yaml", UNSAFE_YAML),
            ("pickle snapshot", "pickle", PICKLE_SNAPSHOT),
        ]
        for label, fmt, data in rejections:
            response = _import(client, fmt, data)
            print(f"{label:<40} | HTTP {response.status_code} (rejected)")
            if response.status_code != 400:
                failures.append(f"{label}: expected generic 400, got {response.status_code}")
            leak = _leaks(response.text)
            if leak is not None:
                failures.append(f"{label}: {leak}")

        # 2b. Defence-in-depth: the integrity-authenticated path accepts a
        # server-signed snapshot and rejects a tampered one.
        signed = client.get("/workspace/export/verified", headers=_auth()).json()
        accepted = _import_verified(client, signed["data"], signed["signature"])
        signed_ok = (
            accepted.status_code == 200
            and accepted.json()["workspace"]["workspace_name"] == EXPECTED_WORKSPACE
        )
        print(
            f"{'signed snapshot (integrity path)':<40} | {'accepted' if signed_ok else 'MISMATCH'}"
        )
        if not signed_ok:
            failures.append(
                "integrity-authenticated path did not accept a legitimate signed snapshot"
            )

        raw = bytearray(base64.b64decode(signed["data"]))
        raw[-1] ^= 0x01
        tampered = _import_verified(
            client, base64.b64encode(bytes(raw)).decode(), signed["signature"]
        )
        print(f"{'tampered signed snapshot':<40} | HTTP {tampered.status_code} (rejected)")
        if tampered.status_code != 400:
            failures.append(f"tampered signed snapshot returned {tampered.status_code}, want 400")
        leak = _leaks(tampered.text)
        if leak is not None:
            failures.append(f"tampered signed snapshot: {leak}")

        # 3. Authentication is generic: an unknown token is a plain 401.
        bad = client.post(
            "/workspace/import",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={"format": "json", "data": FORGED_JSON},
        )
        print(f"{'unknown token':<40} | HTTP {bad.status_code}")
        if bad.status_code != 401:
            failures.append(f"unknown token returned {bad.status_code}, expected 401")

    print()
    if failures:
        print("DEMO RESULT: FAIL")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(
        "DEMO RESULT: PASS — secure app parsed data safely and rejected every dangerous snapshot."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
