#!/usr/bin/env python3
"""CLI for the prompt-injection guard.

Usage:
    python cli.py "Ignore all previous instructions and ..."
    echo "some prompt" | python cli.py
    python cli.py --json "..."

Exit codes: 0 = allow, 1 = flag, 2 = block, 3 = usage error.
"""

from __future__ import annotations

import argparse
import json
import sys

from guard.engine import GuardEngine

EXIT_CODES = {"allow": 0, "flag": 1, "block": 2}


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a prompt for prompt-injection risk.")
    parser.add_argument("prompt", nargs="?", help="Prompt text (or pipe via stdin)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--flag-threshold", type=int, default=30)
    parser.add_argument("--block-threshold", type=int, default=65)
    args = parser.parse_args()

    text = args.prompt if args.prompt is not None else sys.stdin.read()
    text = text.strip()
    if not text:
        print("error: empty prompt", file=sys.stderr)
        return 3

    engine = GuardEngine(flag_threshold=args.flag_threshold, block_threshold=args.block_threshold)
    result = engine.evaluate(text)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"Score:   {result.score}/100")
        print(f"Verdict: {result.verdict.upper()}")
        print(f"  heuristic layer:   {result.heuristic_score}/100")
        print(f"  statistical layer: {result.statistical_score}/100")
        if result.findings:
            print("Detectors fired:")
            for f in result.findings:
                print(f"  - [{f.detector}] {f.reason} (+{f.points})")
        else:
            print("Detectors fired: none")
    return EXIT_CODES[result.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
