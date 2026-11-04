#!/bin/sh
# Fresh-machine check: install and build this tree, pay once on a live desk,
# then verify the receipt in the explorer by id, offline, and as a forgery.
set -eu
cd "$(dirname "$0")/.."
"${PYTHON:-python3}" -m venv .venv
.venv/bin/pip install -q -r requirements-dev.txt
.venv/bin/pip install -q -e .
(cd console && npm ci && npm run build && PLAYWRIGHT_SKIP_BROWSER_GC=1 npx playwright install chromium)
MANDATE_WALKTHROUGH=1 .venv/bin/pytest -q -p no:cacheprovider \
  e2e/test_explorer_walkthrough.py
