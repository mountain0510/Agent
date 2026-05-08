"""Command-line interface for the CTF agent."""

from __future__ import annotations

import argparse
from pathlib import Path

from .agent import CTFAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a minimal adversarial-aware CTF flag finder.")
    parser.add_argument("challenge", type=Path, help="Path to a local CTF challenge directory")
    parser.add_argument("--trace", action="store_true", help="Print planning trace")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = CTFAgent().run(args.challenge)
    if args.trace:
        for index, step in enumerate(result.plan_trace, start=1):
            print(f"[{index}] {step.action} {step.target} :: {step.reason}")
    if result.flag:
        print(result.flag)
        return 0
    print("No flag found")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
