#!/usr/bin/env bash
# Host-side verification entrypoint:
#   1) builds both images (image-build check)
#   2) starts the app and the one-shot verify container
# The verify container runs code tests + HTTP smoke and exits; its exit code
# is propagated to the caller by --exit-code-from.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build
docker compose up --exit-code-from verify verify
