#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-go driver. AWS's Go SDK, v2 — the SDK behind rclone and mint's aws-sdk-go-v2 suite — driven
# at the API level by the small program beside this script, which `ci/compat/install_clients.sh`
# builds from its own go.mod and go.sum.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
exec "$COMPAT_CLIENTS_DIR/aws-sdk-go/driver" "$@"
