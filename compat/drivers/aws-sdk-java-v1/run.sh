#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-java-v1 driver. AWS's Java SDK 1.x, out of support but still linked by a long tail of
# deployed JVM applications (older Hadoop s3a, Spark and Presto builds among them). Its signer is
# independent of 2.x: it frames uploads as STREAMING-AWS4-HMAC-SHA256-PAYLOAD with no trailer. Driven
# at the API level by the program beside this script, which `ci/compat/install_clients.sh` builds
# from its own pom.xml.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
# The end-of-support announcement is a stack-trace-sized stderr banner on every start.
exec java -Daws.java.v1.disableDeprecationAnnouncement=true -cp "$COMPAT_CLIENTS_DIR/aws-sdk-java-v1/lib/*" compat.Driver "$@"
