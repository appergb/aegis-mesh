#!/usr/bin/env python3
"""Portable trailing-whitespace and final-newline validation."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "dist", "build", "__pycache__", ".pytest_cache"}


def main() -> int:
    issues: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if set(relative.parts) & SKIP_PARTS:
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(keepends=True), 1):
            content = line.rstrip("\r\n")
            if content.endswith((" ", "\t")):
                issues.append(f"{relative}:{number}: trailing whitespace")
        if raw and not raw.endswith(b"\n"):
            issues.append(f"{relative}: missing final newline")
    if issues:
        print("\n".join(issues))
        return 1
    print("PASS whitespace validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
