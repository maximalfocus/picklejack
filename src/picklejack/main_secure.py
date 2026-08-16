"""ASGI entry point for the secure application."""

from __future__ import annotations

from picklejack.apps.secure import create_secure_app

app = create_secure_app()
