"""The defence-in-depth integrity-authenticated snapshot path.

This is a **secondary** mitigation for the case where a product genuinely cannot
yet migrate away from an opaque binary snapshot. It is **not** the primary control
(that is parsing a data-only format into a schema; see :mod:`picklejack.snapshots.secure`).
Two independent controls guard it:

1. **Integrity authentication** — an HMAC over the snapshot bytes is verified with a
   server-side key **before** any deserialization, so only snapshots the service
   itself issued are ever unpickled.
2. **A restricted deserializer** — a :class:`RestrictedUnpickler` whose ``find_class``
   permits only a small allowlist of safe data types, so a ``__reduce__`` /
   ``os.popen`` gadget is refused before any object is constructed.

It still bites if the signing key leaks or a dangerous type is reachable from
otherwise-trusted data, which is why untrusted input should be parsed as data
against a schema wherever possible.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import pickle
from typing import Any

from pydantic import ValidationError

from picklejack.schemas import WorkspaceSnapshot
from picklejack.snapshots.common import SnapshotRejected


class RestrictedUnpickler(pickle.Unpickler):
    """An ``Unpickler`` that permits only a small allowlist of safe data types.

    Plain data containers (dict/list/str/int/…) are reconstructed with dedicated
    pickle opcodes that never call ``find_class``; any global reference — the route
    a ``__reduce__`` code-execution gadget must take — is refused here.
    """

    _ALLOWED: frozenset[tuple[str, str]] = frozenset(
        {
            ("builtins", "dict"),
            ("builtins", "list"),
            ("builtins", "tuple"),
            ("builtins", "str"),
            ("builtins", "int"),
            ("builtins", "float"),
            ("builtins", "bool"),
        }
    )

    def find_class(self, module: str, name: str) -> Any:
        if (module, name) in self._ALLOWED:
            return super().find_class(module, name)
        # Any other global (e.g. os.popen) is refused before it can be called.
        raise SnapshotRejected


def _mac(key: bytes, raw: bytes) -> str:
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def sign_snapshot(snapshot: WorkspaceSnapshot, key: bytes) -> tuple[str, str]:
    """Issue a server-signed opaque snapshot: (base64 bytes, hex HMAC)."""
    raw = pickle.dumps(snapshot.model_dump())
    return base64.b64encode(raw).decode(), _mac(key, raw)


def verify_and_load_signed(data_b64: str, signature: str, key: bytes) -> WorkspaceSnapshot:
    """Verify integrity, then restricted-unpickle, then validate against the schema.

    Raises :class:`SnapshotRejected` — with no distinguishing detail — for a
    tampered, unsigned, disallowed-type, or malformed snapshot. The integrity
    check runs before any deserialization, so a snapshot the service did not sign
    is never unpickled.
    """
    try:
        raw = base64.b64decode(data_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SnapshotRejected from exc

    if not hmac.compare_digest(_mac(key, raw), signature):
        # Integrity check failed: do NOT deserialize an unauthenticated snapshot.
        raise SnapshotRejected

    try:
        obj = RestrictedUnpickler(io.BytesIO(raw)).load()
    except Exception as exc:
        # Any unpickling failure — including a refused disallowed type — is generic.
        raise SnapshotRejected from exc

    try:
        return WorkspaceSnapshot.model_validate(obj)
    except ValidationError as exc:
        raise SnapshotRejected from exc
