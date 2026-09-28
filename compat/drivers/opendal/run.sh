#!/usr/bin/env bash
set -uo pipefail

# OpenDAL driver. Apache OpenDAL is how a large part of the Rust data ecosystem reaches S3, and it
# is the client that found s3s's hang on a stalled request (s3s-project/s3s#316). It is driven
# through its Python binding, which wraps the same Rust `services-s3` backend, so the matrix needs
# no second Rust lock file for it.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
exec python3 "$HERE/driver.py" "$@"
