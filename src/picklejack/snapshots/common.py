"""Shared snapshot vocabulary: formats and the generic rejection signal.

``SnapshotRejected`` is deliberately information-free. Every secure rejection —
an unknown format, a parse error, a schema violation, or an object-constructing
YAML tag — raises the same exception with no field, type, or format detail, so the
HTTP boundary can answer with one generic response and no oracle.
"""

from __future__ import annotations

# Data-only formats the secure import path understands.
FORMAT_JSON = "json"
FORMAT_YAML = "yaml"


class SnapshotRejected(Exception):
    """A snapshot is not a valid data-only snapshot and is rejected generically.

    The cause is intentionally not carried on the exception: callers must not turn
    it into a client-visible field/type/format oracle.
    """
