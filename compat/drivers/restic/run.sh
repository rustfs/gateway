#!/usr/bin/env bash
set -uo pipefail

# restic driver. A backup tool rather than a general S3 client, and the reason it is in the matrix
# is its transport: restic's S3 backend is minio-go with an explicit region, which is the one
# client family in this matrix that signs uploads as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` over a
# plaintext endpoint. Every other client here either hashes the whole payload or declares
# `UNSIGNED-PAYLOAD`, so without restic the chunk-signature state machine has no real-SDK traffic
# at all. Its object layout — many small writes plus a few multi-megabyte packs — is also the
# small-object-heavy write pattern no single-object scenario produces.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
scenario="${1:?scenario id required}"

case "$scenario" in
bucket-lifecycle)
    unsupported "$scenario" "restic creates its repository bucket on init but has no command that removes a bucket"
    ;;
small-object-roundtrip | trailer-chunked-upload | large-multipart-upload | list-pagination | \
    range-download | presigned-get | presigned-put | versioned-object | copy-object | delete-batch | \
    sync-directory)
    unsupported "$scenario" "restic addresses a repository, not individual objects; it exposes no command for this scenario"
    ;;
streaming-chunked-upload | backup-restore) ;;
*)
    printf 'restic driver: unknown scenario %s\n' "$scenario" >&2
    exit 64
    ;;
esac

export AWS_ACCESS_KEY_ID="$COMPAT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$COMPAT_SECRET_KEY"
# minio-go asks the server for a bucket's region unless one is configured. restic passes this
# through, and configuring it is what keeps the scenario measuring uploads rather than a
# GetBucketLocation the reference backend does not register.
export AWS_DEFAULT_REGION="$COMPAT_REGION"
export RESTIC_PASSWORD="compat-matrix"
export RESTIC_REPOSITORY="s3:${COMPAT_ENDPOINT}/${COMPAT_BUCKET}"
export RESTIC_CACHE_DIR="$COMPAT_WORKDIR/cache"

source_dir="$COMPAT_WORKDIR/source"
restore_dir="$COMPAT_WORKDIR/restore"
mkdir -p "$source_dir" "$restore_dir"

# Incompressible bytes: restic compresses by default, and a compressible payload would produce a
# pack too small to force multi-chunk framing, which would make the wire assertion pass or fail on
# the entropy of the fixture rather than on the client's behaviour.
if ! head -c 20971520 /dev/urandom >"$source_dir/payload.bin" 2>/dev/null; then
    emit "$scenario" fail "could not create the scenario fixture"
    exit 0
fi

if ! init_output="$(restic init 2>&1)"; then
    printf '%s\n' "$init_output" >&2
    emit "$scenario" fail "restic init failed: $(printf '%s' "$init_output" | tail -n 1)"
    exit 0
fi

if ! backup_output="$(restic backup --no-scan "$source_dir" 2>&1)"; then
    printf '%s\n' "$backup_output" >&2
    emit "$scenario" fail "restic backup failed: $(printf '%s' "$backup_output" | tail -n 1)"
    exit 0
fi

if [[ "$scenario" == streaming-chunked-upload ]]; then
    # The upload happened. Whether it happened as signed chunked framing is decided from the
    # server's own record of the request, not from this exit code — see the scenario's
    # wire_assertions and ci/compat/report.py.
    emit "$scenario" pass ""
    exit 0
fi

if ! restore_output="$(restic restore latest --target "$restore_dir" 2>&1)"; then
    printf '%s\n' "$restore_output" >&2
    emit "$scenario" fail "restic restore failed: $(printf '%s' "$restore_output" | tail -n 1)"
    exit 0
fi

restored="$(find "$restore_dir" -name payload.bin -type f | head -n 1)"
if [[ -z "$restored" ]]; then
    emit "$scenario" fail "restic restore produced no payload.bin"
    exit 0
fi
if ! cmp -s "$source_dir/payload.bin" "$restored"; then
    emit "$scenario" fail "the restored file differs from the backed-up file"
    exit 0
fi
emit "$scenario" pass ""
