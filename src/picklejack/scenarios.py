"""Scenario engine for the vulnerable/secure comparison.

Pure, transport-agnostic logic: given an HTTP client for an app, run the
escalation ladder and classify each result. This module contains no terminal I/O
and is directly testable by injecting an ``httpx.Client`` (including one bound to
an in-process ASGI app). It never raises on a rejected snapshot — a generic 400
from the secure app is itself an observable outcome.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from picklejack.config import FICTIONAL_INTEGRATION_SECRET
from picklejack.snapshots.attacker import (
    forged_pickle_snapshot,
    rce_pickle_snapshot,
    rce_yaml_snapshot,
    secret_pickle_snapshot,
    secret_yaml_snapshot,
)

# A benign, data-only snapshot a service could legitimately issue. Both apps import
# it to the same workspace view.
BENIGN_JSON = json.dumps(
    {
        "workspace_name": "Quarterly Review",
        "panels": [{"title": "Revenue", "kind": "line_chart", "position": 1}],
        "filters": [{"field": "region", "operator": "eq", "value": "APAC", "position": 1}],
    }
)


@dataclass(frozen=True)
class Scenario:
    """One row of the escalation ladder: a snapshot in a declared format."""

    key: str
    label: str
    fmt: str
    data: str


def build_scenarios() -> tuple[Scenario, ...]:
    """The scripted ladder (built lazily so payloads are constructed once)."""
    return (
        Scenario("benign", "benign snapshot the service issued", "json", BENIGN_JSON),
        Scenario("forged", "forged snapshot accepted", "pickle", forged_pickle_snapshot()),
        Scenario(
            "secret_pickle",
            "object injection → secret (pickle)",
            "pickle",
            secret_pickle_snapshot(),
        ),
        Scenario("secret_yaml", "object injection → secret (yaml)", "yaml", secret_yaml_snapshot()),
        Scenario("rce_pickle", "code execution (pickle)", "pickle", rce_pickle_snapshot()),
        Scenario("rce_yaml", "code execution (yaml)", "yaml", rce_yaml_snapshot()),
    )


SCENARIOS: tuple[Scenario, ...] = build_scenarios()


@dataclass(frozen=True)
class Outcome:
    """The classified result of one scenario against one app."""

    scenario: Scenario
    status_code: int
    reconstructed_objects: bool
    deserializer: str
    workspace_view: str
    secret_leaked: bool
    code_executed: bool

    @property
    def accepted(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def verdict(self) -> str:
        dangerous = self.reconstructed_objects or self.secret_leaked or self.code_executed
        return "VULNERABLE" if dangerous else "secure"


def _clip(text: str, width: int = 56) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def classify(scenario: Scenario, response: httpx.Response) -> Outcome:
    """Derive the observable signals from an import response (any app, any status)."""
    text = response.text
    secret_leaked = FICTIONAL_INTEGRATION_SECRET in text
    code_executed = "uid=" in text
    reconstructed_objects = False
    deserializer = "— (rejected)"
    workspace_view = "—"

    if 200 <= response.status_code < 300:
        body = response.json()
        if "reconstructed_from_untrusted_bytes" in body:  # the vulnerable app
            reconstructed_objects = bool(body["reconstructed_from_untrusted_bytes"])
            deserializer = str(body["deserializer"])
            ws = body.get("workspace")
            workspace_view = ws["workspace_name"] if ws else _clip(str(body["reconstructed"]))
        else:  # the secure app
            deserializer = f"safe:{body['source_format']}"
            ws = body.get("workspace")
            workspace_view = ws["workspace_name"] if ws else "—"

    return Outcome(
        scenario=scenario,
        status_code=response.status_code,
        reconstructed_objects=reconstructed_objects,
        deserializer=deserializer,
        workspace_view=workspace_view,
        secret_leaked=secret_leaked,
        code_executed=code_executed,
    )


def run_scenario(client: httpx.Client, token: str, scenario: Scenario) -> Outcome:
    """Send one scenario snapshot to an app and classify the response."""
    response = client.post(
        "/workspace/import",
        headers={"Authorization": f"Bearer {token}"},
        json={"format": scenario.fmt, "data": scenario.data},
    )
    return classify(scenario, response)


@dataclass(frozen=True)
class Comparison:
    """The secure and vulnerable outcomes for one scenario, side by side."""

    scenario: Scenario
    secure: Outcome
    vulnerable: Outcome


def compare(secure: httpx.Client, vulnerable: httpx.Client, token: str) -> list[Comparison]:
    """Run every scenario against both apps and pair the outcomes."""
    return [
        Comparison(
            scenario=scenario,
            secure=run_scenario(secure, token, scenario),
            vulnerable=run_scenario(vulnerable, token, scenario),
        )
        for scenario in SCENARIOS
    ]
