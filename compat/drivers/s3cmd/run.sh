#!/usr/bin/env bash
set -uo pipefail

# s3cmd driver. The oldest widely deployed S3 command-line client, with its own hand-written signer
# and XML handling rather than an AWS SDK underneath, which is why it disagrees with servers in
# places the SDKs agree. It is configured for SigV4 here; its `signurl` still produces a
# SigV2 query-string URL, which is a signing path no other client in this matrix exercises.
#
# Measured wire behaviour: every upload over the plaintext endpoint declares the whole-payload
# SHA-256 and sends no chunk framing, so the two aws-chunked scenarios are out of its reach.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
scenario="${1:?scenario id required}"

case "$scenario" in
streaming-chunked-upload)
    unsupported "$scenario" "s3cmd declares the whole-payload SHA-256 for every upload and has no aws-chunked mode"
    ;;
trailer-chunked-upload)
    unsupported "$scenario" "s3cmd sends no trailing checksum; it has no aws-chunked mode"
    ;;
list-pagination)
    unsupported "$scenario" "s3cmd ls always asks for the server's maximum page and exposes no page-size option, so it cannot walk a 7-key page"
    ;;
presigned-put)
    unsupported "$scenario" "s3cmd signurl signs GET URLs only"
    ;;
versioned-object)
    unsupported "$scenario" "s3cmd has no bucket-versioning or version-id commands"
    ;;
backup-restore)
    unsupported "$scenario" "s3cmd is not a backup tool; it has no repository format to restore"
    ;;
bucket-lifecycle | small-object-roundtrip | large-multipart-upload | range-download | presigned-get | \
    copy-object | delete-batch | sync-directory) ;;
*)
    printf 's3cmd driver: unknown scenario %s\n' "$scenario" >&2
    exit 64
    ;;
esac

host="${COMPAT_ENDPOINT#http://}"
config="$COMPAT_WORKDIR/s3cfg"
# host_bucket equal to host_base is s3cmd's spelling of path-style addressing.
cat >"$config" <<CONFIG
[default]
access_key = $COMPAT_ACCESS_KEY
secret_key = $COMPAT_SECRET_KEY
host_base = $host
host_bucket = $host
bucket_location = $COMPAT_REGION
use_https = False
signature_v2 = False
multipart_chunk_size_mb = 5
max_retries = 1
progress_meter = False
CONFIG
s3() { s3cmd --config "$config" --no-check-md5 "$@"; }

step() {
    local label="$1" output
    shift
    if ! output="$("$@" 2>&1)"; then
        printf '%s\n' "$output" >&2
        emit "$scenario" fail "$label failed: $(printf '%s' "$output" | tail -n 1)"
        exit 0
    fi
    STEP_OUTPUT="$output"
}

fail_with() {
    emit "$scenario" fail "$1"
    exit 0
}

bucket="s3://$COMPAT_BUCKET"
work="$COMPAT_WORKDIR"

step "s3cmd mb" s3 mb "$bucket"

case "$scenario" in
bucket-lifecycle)
    step "s3cmd info" s3 info "$bucket"
    step "s3cmd rb" s3 rb "$bucket"
    if s3 info "$bucket" >/dev/null 2>&1; then
        fail_with "the bucket answered after it was removed"
    fi
    emit "$scenario" pass ""
    ;;
small-object-roundtrip | large-multipart-upload)
    size=4096
    [[ "$scenario" == large-multipart-upload ]] && size=12582912
    head -c "$size" /dev/urandom >"$work/payload.bin"
    step "s3cmd put" s3 put "$work/payload.bin" "$bucket/payload.bin"
    step "s3cmd get" s3 get --force "$bucket/payload.bin" "$work/read-back.bin"
    cmp -s "$work/payload.bin" "$work/read-back.bin" || fail_with "the object read back differs from the object written"
    step "s3cmd info" s3 info "$bucket/payload.bin"
    length="$(printf '%s\n' "$STEP_OUTPUT" | sed -n 's/^ *File size: *\([0-9]*\).*/\1/p')"
    etag="$(printf '%s\n' "$STEP_OUTPUT" | sed -n 's/^ *MD5 sum: *\([^ ]*\).*/\1/p')"
    [[ "$length" == "$size" ]] || fail_with "s3cmd info reported size '$length' for a $size byte object"
    if [[ "$scenario" == large-multipart-upload && "$etag" != *-* ]]; then
        fail_with "a $size byte upload in 5 MiB parts reported the single-part entity tag $etag"
    fi
    emit "$scenario" pass ""
    ;;
range-download)
    head -c 1048576 /dev/urandom >"$work/ranged.bin"
    step "s3cmd put" s3 put "$work/ranged.bin" "$bucket/ranged.bin"
    # `get --continue` resumes a partial file with a `Range: bytes=<size>-` request, which is how
    # s3cmd reads a byte range at all. The first 1000 bytes are already "downloaded".
    head -c 1000 "$work/ranged.bin" >"$work/partial.bin"
    step "s3cmd get --continue" s3 get --continue "$bucket/ranged.bin" "$work/partial.bin"
    cmp -s "$work/ranged.bin" "$work/partial.bin" ||
        fail_with "resuming at byte 1000 produced a file that differs from the source object"
    emit "$scenario" pass ""
    ;;
presigned-get)
    head -c 2048 /dev/urandom >"$work/presigned.bin"
    step "s3cmd put" s3 put "$work/presigned.bin" "$bucket/presigned.bin"
    step "s3cmd signurl" s3 signurl "$bucket/presigned.bin" +300
    url="$(printf '%s' "$STEP_OUTPUT" | tail -n 1)"
    status="$(curl -s -o "$work/fetched.bin" -w '%{http_code}' "$url")"
    [[ "$status" == 200 ]] || fail_with "a presigned GET was answered $status"
    cmp -s "$work/presigned.bin" "$work/fetched.bin" || fail_with "a presigned GET returned bytes that differ from the object"
    emit "$scenario" pass ""
    ;;
copy-object)
    printf 'copy me' >"$work/source.bin"
    step "s3cmd put" s3 put "$work/source.bin" "$bucket/source.bin"
    step "s3cmd cp" s3 cp "$bucket/source.bin" "$bucket/target.bin"
    step "s3cmd get" s3 get --force "$bucket/target.bin" "$work/target.bin"
    cmp -s "$work/source.bin" "$work/target.bin" || fail_with "a server-side copy produced different bytes"
    emit "$scenario" pass ""
    ;;
delete-batch)
    mkdir -p "$work/batch"
    for index in $(seq 0 9); do
        printf 'x' >"$work/batch/$index.txt"
    done
    step "s3cmd put --recursive" s3 put --recursive "$work/batch" "$bucket/"
    # A recursive delete is sent as one multi-object DeleteObjects request.
    step "s3cmd del --recursive" s3 del --recursive --force "$bucket/batch/"
    step "s3cmd ls" s3 ls --recursive "$bucket"
    remaining="$(printf '%s\n' "$STEP_OUTPUT" | grep -c 's3://' || true)"
    [[ "$remaining" -eq 0 ]] || fail_with "$remaining key(s) survived a batch delete"
    emit "$scenario" pass ""
    ;;
sync-directory)
    mkdir -p "$work/tree/nested"
    for index in $(seq 1 12); do
        head -c 1024 /dev/urandom >"$work/tree/nested/file-$index.bin"
    done
    step "s3cmd sync" s3 sync "$work/tree/" "$bucket/mirror/"
    head -c 2048 /dev/urandom >"$work/tree/nested/file-1.bin"
    step "s3cmd sync (rerun)" s3 sync "$work/tree/" "$bucket/mirror/"
    # A sync that copied nothing still exits 0, so the mirror is read back and compared.
    mkdir -p "$work/read-back"
    step "s3cmd sync (read back)" s3 sync "$bucket/mirror/" "$work/read-back/"
    diff -r "$work/tree" "$work/read-back" >&2 || fail_with "the mirror read back differs from the source tree after a rerun"
    emit "$scenario" pass ""
    ;;
esac
