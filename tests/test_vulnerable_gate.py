"""The vulnerable app refuses to start without explicit acknowledgement (FR-012)."""

from __future__ import annotations

import pytest

from picklejack.apps.vulnerable import (
    ALLOW_ENV,
    VulnerableDemoNotAllowed,
    create_vulnerable_app,
)


def test_refuses_without_acknowledgement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOW_ENV, raising=False)
    with pytest.raises(VulnerableDemoNotAllowed):
        create_vulnerable_app()


def test_refuses_with_wrong_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOW_ENV, "false")
    with pytest.raises(VulnerableDemoNotAllowed):
        create_vulnerable_app()


def test_starts_only_with_exact_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOW_ENV, "true")
    app = create_vulnerable_app()
    assert app.title.startswith("picklejack (VULNERABLE")
