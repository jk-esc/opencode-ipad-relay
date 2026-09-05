#!/bin/bash
# check.sh — run the full local verification gate (mirrors CI).
set -euo pipefail

cd "$(dirname "$0")/.."

PY=python3
if [ -x ".venv/bin/python" ]; then
  PY=.venv/bin/python
fi
RUFF=.venv/bin/ruff
MYPY=.venv/bin/mypy
BANDIT=.venv/bin/bandit

step() { printf '\n==> %s\n' "$*"; }

step "shellcheck"
shellcheck install.sh uninstall.sh src/opencode-web scripts/check.sh

step "shfmt"
shfmt -i 2 -d install.sh uninstall.sh src/opencode-web scripts/check.sh

step "ruff check"
"$RUFF" check src/ tests/

step "ruff format"
"$RUFF" format --check src/ tests/

step "mypy"
"$MYPY" src/opencode-web-proxy.py --ignore-missing-imports

step "bandit"
"$BANDIT" -r src/ -q

step "pytest"
"$PY" -m pytest tests/python/ --cov=src --cov-report=term-missing

step "bats"
bats tests/bats/

step "gitleaks"
if [ -d .git ]; then
  gitleaks git --redact .
else
  echo "(no .git yet — scanning working tree)"
  gitleaks dir --redact .
fi

step "actionlint"
if [ -d .github/workflows ]; then
  actionlint .github/workflows/*.yml
else
  echo "(no workflows yet — skipping)"
fi

printf '\nAll checks passed.\n'
