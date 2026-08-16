"""The picklejack comparison CLI.

``compare`` runs the escalation ladder against both apps and prints a narrative
plus before/after tables; ``interactive`` sends snapshots you paste to both apps. A
``--verbose`` flag surfaces the underlying HTTP exchange. All scenario logic lives
in :mod:`picklejack.scenarios`, which is directly testable without any terminal.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import httpx

from picklejack.domain.fixtures import GLOBEX_TOKEN
from picklejack.scenarios import (
    Comparison,
    Outcome,
    Scenario,
    compare,
    run_scenario,
)

DEFAULT_SECURE_URL = "http://127.0.0.1:8000"
DEFAULT_VULNERABLE_URL = "http://127.0.0.1:8001"

_NARRATIVE = (
    "picklejack — Insecure Deserialization, side by side.\n"
    "The vulnerable app reconstructs OBJECTS from untrusted bytes (pickle.loads / yaml.load);\n"
    "the secure app parses DATA into an explicit schema and never builds arbitrary objects.\n"
    "The same snapshots are submitted to both apps below.\n"
)

_COL = 28


def _yn(value: bool) -> str:
    return "YES" if value else "no"


def _row(label: str, secure: str, vulnerable: str) -> str:
    return f"  {label:<20} {secure:<{_COL}} {vulnerable}"


def format_outcome_table(comparison: Comparison) -> str:
    secure, vulnerable = comparison.secure, comparison.vulnerable
    lines = [
        f"Scenario: {comparison.scenario.label}  [{comparison.scenario.fmt}]",
        _row("", "secure", "vulnerable"),
        _row("status", str(secure.status_code), str(vulnerable.status_code)),
        _row(
            "rebuilt objects",
            _yn(secure.reconstructed_objects),
            _yn(vulnerable.reconstructed_objects),
        ),
        _row("deserializer", secure.deserializer, vulnerable.deserializer),
        _row("workspace/output", secure.workspace_view, vulnerable.workspace_view),
        _row("secret leaked", _yn(secure.secret_leaked), _yn(vulnerable.secret_leaked)),
        _row("code executed", _yn(secure.code_executed), _yn(vulnerable.code_executed)),
        _row("verdict", secure.verdict, vulnerable.verdict),
    ]
    return "\n".join(lines)


def format_comparison(comparisons: Sequence[Comparison]) -> str:
    blocks = [_NARRATIVE, *(format_outcome_table(c) for c in comparisons)]
    return "\n\n".join(blocks)


def format_exchange(app: str, scenario: Scenario, outcome: Outcome) -> str:
    return "\n".join(
        [
            f"[{app}] POST /workspace/import",
            "  > Authorization: Bearer ***redacted***",
            f'  > {{"format": {scenario.fmt!r}, "data": {_clip(scenario.data)!r}}}',
            f"  < HTTP {outcome.status_code}  deserializer={outcome.deserializer}",
            f"  < workspace/output: {outcome.workspace_view}",
        ]
    )


def _clip(text: str, width: int = 48) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def _summary(comparisons: Sequence[Comparison]) -> str:
    vulnerable_hits = sum(1 for c in comparisons if c.vulnerable.verdict == "VULNERABLE")
    secure_hits = sum(1 for c in comparisons if c.secure.verdict == "VULNERABLE")
    return (
        f"Summary: vulnerable app flagged on {vulnerable_hits}/{len(comparisons)} snapshots; "
        f"secure app flagged on {secure_hits}/{len(comparisons)}."
    )


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--secure-url", default=DEFAULT_SECURE_URL)
    parser.add_argument("--vulnerable-url", default=DEFAULT_VULNERABLE_URL)
    parser.add_argument("--token", default=GLOBEX_TOKEN)
    parser.add_argument("--verbose", action="store_true", help="show the HTTP exchange")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="picklejack", description="Compare the deserialization apps."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_common(sub.add_parser("compare", help="run the scripted escalation ladder"))
    _add_common(sub.add_parser("interactive", help="send snapshots you paste to both apps"))
    return parser


def _run_compare(args: argparse.Namespace) -> int:
    with (
        httpx.Client(base_url=args.secure_url, timeout=10.0) as secure,
        httpx.Client(base_url=args.vulnerable_url, timeout=10.0) as vulnerable,
    ):
        comparisons = compare(secure, vulnerable, args.token)
    print(format_comparison(comparisons))
    if args.verbose:
        print()
        for comparison in comparisons:
            print(format_exchange("secure", comparison.scenario, comparison.secure))
            print(format_exchange("vulnerable", comparison.scenario, comparison.vulnerable))
            print()
    print()
    print(_summary(comparisons))
    return 0


def _run_interactive(args: argparse.Namespace) -> int:
    print("Interactive mode — paste `<format> <base64-or-text-data>` per line (Ctrl-D to exit).")
    with (
        httpx.Client(base_url=args.secure_url, timeout=10.0) as secure,
        httpx.Client(base_url=args.vulnerable_url, timeout=10.0) as vulnerable,
    ):
        for line in sys.stdin:
            stripped = line.rstrip("\n")
            if not stripped:
                continue
            fmt, _, data = stripped.partition(" ")
            scenario = Scenario("custom", "custom snapshot", fmt, data)
            comparison = Comparison(
                scenario=scenario,
                secure=run_scenario(secure, args.token, scenario),
                vulnerable=run_scenario(vulnerable, args.token, scenario),
            )
            print(format_outcome_table(comparison))
            if args.verbose:
                print(format_exchange("secure", scenario, comparison.secure))
                print(format_exchange("vulnerable", scenario, comparison.vulnerable))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "compare":
        return _run_compare(args)
    return _run_interactive(args)


if __name__ == "__main__":
    sys.exit(main())
