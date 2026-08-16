"""ASGI entry point for the intentionally vulnerable application (local demo only).

Importing this module raises unless ``ALLOW_VULNERABLE_DEMO=true`` is set, so the
vulnerable server cannot start without explicit acknowledgement.
"""

from __future__ import annotations

from picklejack.apps.vulnerable import create_vulnerable_app

app = create_vulnerable_app()
