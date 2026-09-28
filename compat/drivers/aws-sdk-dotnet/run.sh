#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-dotnet driver. AWS's .NET SDK (AWSSDK.S3 v4), the S3 client of the .NET ecosystem, driven
# at the API level by the small program beside this script, which `ci/compat/install_clients.sh`
# builds from its own packages.lock.json. It is the SDK here that signs plain PutObject uploads over
# plaintext as signed aws-chunked with a signed checksum trailer by default.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
exec dotnet "$COMPAT_CLIENTS_DIR/aws-sdk-dotnet/app/driver.dll" "$@"
