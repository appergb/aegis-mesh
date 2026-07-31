#!/usr/bin/env python3
"""Require a release tag to exactly match the project version."""

from __future__ import annotations

import argparse
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def expected_tag() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return f"v{project['version']}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    expected = expected_tag()
    if args.tag != expected:
        parser.error(f"release tag must be exactly {expected}")
    print(f"PASS release tag {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
