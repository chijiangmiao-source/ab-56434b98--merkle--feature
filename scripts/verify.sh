#!/usr/bin/env bash
# Entrypoint for the one-shot verify container.
# Runs: image-build sanity -> code tests -> live HTTP smoke.
# Exits non-zero if any stage fails.
set -euo pipefail
export PYTHONPATH=/app

echo "== [1/3] image build sanity: app importable in built image =="
python -c "import app.main; print('app.main imports OK')"

echo "== [2/3] code tests (out-of-order merge, fork freeze, restart) =="
python -m pytest -v

echo "== [3/3] live HTTP smoke against http://app:8000 =="
python scripts/smoke.py

echo "== verify: ALL STAGES PASSED =="
