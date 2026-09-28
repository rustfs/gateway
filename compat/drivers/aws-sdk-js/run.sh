#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-js driver. AWS's JavaScript SDK, v3, on Node.js — the SDK behind most browser and server
# JavaScript that talks to S3 — driven at the API level by driver.mjs beside this script, which
# `ci/compat/install_clients.sh` installs from its own package-lock.json with `npm ci`.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
exec node "$COMPAT_CLIENTS_DIR/aws-sdk-js/src/driver.mjs" "$@"
