#!/usr/bin/env bash
set -uo pipefail

# aws-sdk-rust driver. AWS's Rust SDK (aws-sdk-s3), whose sigv4 signer and aws-chunked body are a
# third independent implementation of the streaming upload shapes — it sends signed chunks with a
# signed trailer over plaintext by default — driven at the API level by the small program beside
# this script, which `ci/compat/install_clients.sh` builds from its own Cargo.toml and Cargo.lock.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR COMPAT_CLIENTS_DIR
exec "$COMPAT_CLIENTS_DIR/aws-sdk-rust/target/release/driver" "$@"
