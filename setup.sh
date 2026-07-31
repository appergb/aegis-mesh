#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_dir"

required_version="$(tr -d '\n' < .python-version)"
if [[ -x .venv/bin/python ]]; then
  actual_version="$(.venv/bin/python -c 'import platform; print(platform.python_version())')"
  if [[ "$actual_version" != "$required_version" ]]; then
    echo "Existing .venv uses Python $actual_version; Aegis Mesh requires $required_version." >&2
    exit 1
  fi
else
  python_bin=""
  for candidate in python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      actual_version="$("$candidate" -c 'import platform; print(platform.python_version())')"
      if [[ "$actual_version" == "$required_version" ]]; then
        python_bin="$candidate"
        break
      fi
    fi
  done
  if [[ -z "$python_bin" ]]; then
    echo "Aegis Mesh requires Python $required_version. Install it or create a matching .venv." >&2
    exit 1
  fi
  "$python_bin" -m venv .venv
fi

.venv/bin/python -m pip install --require-hashes -r requirements-validation.lock
echo "Environment ready. Run: make validate"
