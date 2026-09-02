#!/usr/bin/env bash
set -uo pipefail

# boto3 driver. Python's de-facto S3 client, and the SDK whose historical bug reports the s3s
# regression suite was built out of. It is driven at the raw API level, so a scenario's failure
# names one operation rather than a workflow.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
exec python3 "$HERE/driver.py" "$@"
