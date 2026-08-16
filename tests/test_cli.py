"""The comparison CLI and its scenario engine (FR-010)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from picklejack.cli import (
    _build_parser,
    format_comparison,
    format_exchange,
    format_outcome_table,
)
from picklejack.config import FICTIONAL_INTEGRATION_SECRET
from picklejack.scenarios import compare
from tests.conftest import GLOBEX_TOKEN


def test_engine_classifies_both_apps(client: TestClient, vulnerable_client: TestClient) -> None:
    comparisons = compare(client, vulnerable_client, GLOBEX_TOKEN)
    by_key = {c.scenario.key: c for c in comparisons}

    # Benign: both apps import to the identical workspace view.
    benign = by_key["benign"]
    assert benign.secure.workspace_view == benign.vulnerable.workspace_view == "Quarterly Review"
    assert benign.secure.verdict == "secure" and benign.vulnerable.verdict == "secure"

    # Secret disclosure: secure rejects (400), vulnerable leaks the secret.
    secret = by_key["secret_pickle"]
    assert secret.secure.status_code == 400 and secret.secure.verdict == "secure"
    assert secret.vulnerable.secret_leaked and secret.vulnerable.verdict == "VULNERABLE"

    # Code execution through both deserializers: vulnerable runs id, secure does not.
    for key in ("rce_pickle", "rce_yaml"):
        rce = by_key[key]
        assert rce.vulnerable.code_executed and rce.vulnerable.verdict == "VULNERABLE"
        assert not rce.secure.code_executed and rce.secure.verdict == "secure"


def test_compare_table_shows_every_signal(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    text = format_comparison(compare(client, vulnerable_client, GLOBEX_TOKEN))
    assert "rebuilt objects" in text
    assert "VULNERABLE" in text
    assert "Quarterly Review" in text  # identical benign view
    assert FICTIONAL_INTEGRATION_SECRET in text  # disclosed on the vulnerable side
    assert "uid=" in text  # os.popen('id') output surfaced
    for label in ("object injection → secret (pickle)", "code execution (yaml)"):
        assert label in text


def test_outcome_table_marks_secure_as_safe(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    comparisons = compare(client, vulnerable_client, GLOBEX_TOKEN)
    rce = next(c for c in comparisons if c.scenario.key == "rce_pickle")
    table = format_outcome_table(rce)
    assert "code executed" in table
    assert "verdict" in table
    assert "VULNERABLE" in table
    assert "secure" in table


def test_verbose_exchange_redacts_the_token(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    comparisons = compare(client, vulnerable_client, GLOBEX_TOKEN)
    exchange = format_exchange("vulnerable", comparisons[0].scenario, comparisons[0].vulnerable)
    assert "Bearer ***redacted***" in exchange
    assert GLOBEX_TOKEN not in exchange


def test_parser_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args([])


def test_parser_compare_defaults() -> None:
    args = _build_parser().parse_args(["compare"])
    assert args.command == "compare"
    assert args.secure_url.endswith(":8000")
    assert args.vulnerable_url.endswith(":8001")
    assert args.verbose is False
