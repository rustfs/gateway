#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-java-v2 driver. AWS's Java SDK 2.x — the SDK behind most JVM data tooling that speaks S3,
# and the one whose default PutObject carries a CRC32 in an x-amz-trailer behind signed aws-chunked
# framing even over plaintext — driven at the API level by the program beside this script, which
# `ci/compat/install_clients.sh` builds from its own pom.xml.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
exec java -cp "$COMPAT_CLIENTS_DIR/aws-sdk-java-v2/lib/*" compat.Driver "$@"
