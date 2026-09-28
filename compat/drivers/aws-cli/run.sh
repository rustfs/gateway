#!/usr/bin/env bash
set -uo pipefail

# aws-cli driver. AWS's own command-line client, v2, and the reference most S3 users measure a
# server against. It is botocore underneath, but its high-level `s3` commands choose part sizes,
# concurrency and sync decisions of their own, so a scenario it fails is not always one boto3
# fails.
#
# Measured wire behaviour, which decides two cells below: over the plaintext endpoint every
# upload — single PUT, `s3 cp` past the multipart threshold, each UploadPart — declares the
# whole-payload SHA-256 and sends no chunk framing. Over TLS the same commands send
# `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with an `x-amz-checksum-crc64nvme` trailer. So it can
# express a trailing-checksum upload (over TLS) but never a signed-chunk one.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
scenario="${1:?scenario id required}"

case "$scenario" in
streaming-chunked-upload)
    unsupported "$scenario" "aws-cli (botocore) declares the whole-payload SHA-256 for every upload over a plaintext endpoint and offers no signed aws-chunked mode"
    ;;
presigned-put)
    unsupported "$scenario" "aws s3 presign signs GetObject URLs only"
    ;;
backup-restore)
    unsupported "$scenario" "aws-cli is not a backup tool; it has no repository format to restore"
    ;;
trailer-chunked-upload)
    if [[ -z "${COMPAT_TLS_ENDPOINT:-}" || -z "${COMPAT_CA_BUNDLE:-}" ]]; then
        unsupported "$scenario" "the runner offered no TLS endpoint, and aws-cli sends a trailer only on the unsigned-payload path it takes over TLS"
    fi
    ;;
bucket-lifecycle | small-object-roundtrip | large-multipart-upload | list-pagination | range-download | \
    presigned-get | versioned-object | copy-object | delete-batch | sync-directory) ;;
*)
    printf 'aws-cli driver: unknown scenario %s\n' "$scenario" >&2
    exit 64
    ;;
esac

export AWS_ACCESS_KEY_ID="$COMPAT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$COMPAT_SECRET_KEY"
export AWS_DEFAULT_REGION="$COMPAT_REGION"
export AWS_CONFIG_FILE="$COMPAT_WORKDIR/aws-config"
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_MAX_ATTEMPTS=1
export AWS_PAGER=""
# Path-style addressing, and a 5 MiB multipart threshold so `large-multipart-upload` is split by the
# client's own transfer manager rather than by this script.
cat >"$AWS_CONFIG_FILE" <<'CONFIG'
[default]
s3 =
    addressing_style = path
    multipart_threshold = 5MB
    multipart_chunksize = 5MB
CONFIG

endpoint="$COMPAT_ENDPOINT"
aws_run() { aws --endpoint-url "$endpoint" --no-cli-pager "$@"; }

# Runs one step; on failure prints its output to stderr and records the scenario as failed with
# the step named, because "aws exited 254" says nothing about which request the server refused.
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

bucket="$COMPAT_BUCKET"
work="$COMPAT_WORKDIR"

if [[ "$scenario" == trailer-chunked-upload ]]; then
    endpoint="$COMPAT_TLS_ENDPOINT"
    export AWS_CA_BUNDLE="$COMPAT_CA_BUNDLE"
fi

step "s3api create-bucket" aws_run s3api create-bucket --bucket "$bucket"

case "$scenario" in
bucket-lifecycle)
    step "s3api head-bucket" aws_run s3api head-bucket --bucket "$bucket"
    step "s3api delete-bucket" aws_run s3api delete-bucket --bucket "$bucket"
    if aws_run s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
        fail_with "the bucket answered HeadBucket after it was deleted"
    fi
    emit "$scenario" pass ""
    ;;
small-object-roundtrip | large-multipart-upload | trailer-chunked-upload)
    size=4096
    [[ "$scenario" == large-multipart-upload ]] && size=12582912
    [[ "$scenario" == trailer-chunked-upload ]] && size=1048576
    head -c "$size" /dev/urandom >"$work/payload.bin"
    if [[ "$scenario" == trailer-chunked-upload ]]; then
        # A plain PutObject: over TLS botocore moves the default checksum into a trailer on its own.
        step "s3api put-object" aws_run s3api put-object --bucket "$bucket" --key payload.bin --body "$work/payload.bin"
    else
        step "s3 cp up" aws_run s3 cp "$work/payload.bin" "s3://$bucket/payload.bin" --only-show-errors
    fi
    step "s3 cp down" aws_run s3 cp "s3://$bucket/payload.bin" "$work/read-back.bin" --only-show-errors
    cmp -s "$work/payload.bin" "$work/read-back.bin" || fail_with "the object read back differs from the object written"
    step "s3api head-object" aws_run s3api head-object --bucket "$bucket" --key payload.bin --query '[ContentLength, ETag]' --output text
    read -r length etag <<<"$STEP_OUTPUT"
    [[ "$length" == "$size" ]] || fail_with "HeadObject reported $length for a $size byte object"
    if [[ "$scenario" == large-multipart-upload && "$etag" != *-* ]]; then
        fail_with "a $size byte upload past a 5 MiB threshold reported the single-part entity tag $etag"
    fi
    emit "$scenario" pass ""
    ;;
list-pagination)
    mkdir -p "$work/seed"
    for index in $(seq -f '%04g' 0 24); do
        printf 'key %s\n' "$index" >"$work/seed/$index.txt"
    done
    step "s3 cp --recursive" aws_run s3 cp "$work/seed" "s3://$bucket/page/" --recursive --only-show-errors
    # Walked by hand, one page per call, so the page count is observed rather than hidden inside
    # the CLI's own paginator.
    token=""
    pages=0
    : >"$work/keys.txt"
    while :; do
        if [[ -n "$token" ]]; then
            step "s3api list-objects-v2" aws_run s3api list-objects-v2 --bucket "$bucket" --prefix page/ --max-keys 7 \
                --no-paginate --continuation-token "$token" --output json
        else
            step "s3api list-objects-v2" aws_run s3api list-objects-v2 --bucket "$bucket" --prefix page/ --max-keys 7 \
                --no-paginate --output json
        fi
        pages=$((pages + 1))
        token="$(printf '%s' "$STEP_OUTPUT" | python3 -c 'import json, sys
page = json.load(sys.stdin)
with open(sys.argv[1], "a") as keys:
    for entry in page.get("Contents", []):
        keys.write(entry["Key"] + "\n")
print(page.get("NextContinuationToken", "") if page.get("IsTruncated") else "")' "$work/keys.txt")"
        [[ -z "$token" || "$pages" -ge 20 ]] && break
    done
    listed="$(sort -u "$work/keys.txt" | grep -c '\.txt$' || true)"
    [[ "$listed" -eq 25 ]] || fail_with "walked $pages page(s) of 7 and enumerated $listed of 25 keys"
    [[ "$pages" -ge 2 ]] || fail_with "a 25 key listing at 7 keys per page returned $pages page(s)"
    emit "$scenario" pass ""
    ;;
range-download)
    head -c 1048576 /dev/urandom >"$work/ranged.bin"
    step "s3api put-object" aws_run s3api put-object --bucket "$bucket" --key ranged.bin --body "$work/ranged.bin"
    step "s3api get-object --range" aws_run s3api get-object --bucket "$bucket" --key ranged.bin --range bytes=1000-5000 "$work/slice.bin"
    dd if="$work/ranged.bin" bs=1 skip=1000 count=4001 of="$work/expected.bin" 2>/dev/null
    cmp -s "$work/expected.bin" "$work/slice.bin" ||
        fail_with "bytes=1000-5000 returned $(wc -c <"$work/slice.bin" | tr -d ' ') bytes that differ from the same slice of the source"
    emit "$scenario" pass ""
    ;;
presigned-get)
    head -c 2048 /dev/urandom >"$work/presigned.bin"
    step "s3api put-object" aws_run s3api put-object --bucket "$bucket" --key presigned.bin --body "$work/presigned.bin"
    step "s3 presign" aws_run s3 presign "s3://$bucket/presigned.bin" --expires-in 300
    url="$(printf '%s' "$STEP_OUTPUT" | tail -n 1)"
    # Redeemed by curl, not by the CLI: generation is the client's half, verification the server's.
    status="$(curl -s -o "$work/fetched.bin" -w '%{http_code}' "$url")"
    [[ "$status" == 200 ]] || fail_with "a presigned GET was answered $status"
    cmp -s "$work/presigned.bin" "$work/fetched.bin" || fail_with "a presigned GET returned bytes that differ from the object"
    emit "$scenario" pass ""
    ;;
versioned-object)
    step "s3api put-bucket-versioning" aws_run s3api put-bucket-versioning --bucket "$bucket" \
        --versioning-configuration Status=Enabled
    step "s3api get-bucket-versioning" aws_run s3api get-bucket-versioning --bucket "$bucket" --query Status --output text
    [[ "$STEP_OUTPUT" == Enabled ]] || fail_with "versioning reported '$STEP_OUTPUT' after it was enabled"
    printf 'first' >"$work/first.txt"
    printf 'second' >"$work/second.txt"
    step "s3api put-object (first)" aws_run s3api put-object --bucket "$bucket" --key versioned.bin --body "$work/first.txt" \
        --query VersionId --output text
    first="$STEP_OUTPUT"
    step "s3api put-object (second)" aws_run s3api put-object --bucket "$bucket" --key versioned.bin --body "$work/second.txt"
    step "s3api list-object-versions" aws_run s3api list-object-versions --bucket "$bucket" --prefix versioned.bin \
        --query 'length(Versions)' --output text
    [[ "$STEP_OUTPUT" -ge 2 ]] 2>/dev/null || fail_with "two writes to an enabled bucket enumerated '$STEP_OUTPUT' version(s)"
    step "s3api get-object --version-id" aws_run s3api get-object --bucket "$bucket" --key versioned.bin \
        --version-id "$first" "$work/oldest.txt"
    cmp -s "$work/first.txt" "$work/oldest.txt" || fail_with "an explicit version read returned the wrong version's bytes"
    emit "$scenario" pass ""
    ;;
copy-object)
    printf 'copy me' >"$work/source.bin"
    step "s3api put-object" aws_run s3api put-object --bucket "$bucket" --key source.bin --body "$work/source.bin"
    step "s3api copy-object" aws_run s3api copy-object --bucket "$bucket" --key target.bin --copy-source "$bucket/source.bin"
    step "s3api get-object" aws_run s3api get-object --bucket "$bucket" --key target.bin "$work/target.bin"
    cmp -s "$work/source.bin" "$work/target.bin" || fail_with "a server-side copy produced different bytes"
    emit "$scenario" pass ""
    ;;
delete-batch)
    printf 'x' >"$work/x.txt"
    objects=""
    for index in $(seq 0 9); do
        step "s3api put-object" aws_run s3api put-object --bucket "$bucket" --key "batch/$index.txt" --body "$work/x.txt"
        objects="$objects{Key=batch/$index.txt},"
    done
    step "s3api delete-objects" aws_run s3api delete-objects --bucket "$bucket" --delete "Objects=[${objects%,}],Quiet=true"
    # --no-paginate: the CLI's own paginator merges pages and drops KeyCount from what it prints.
    step "s3api list-objects-v2" aws_run s3api list-objects-v2 --bucket "$bucket" --no-paginate --query KeyCount --output text
    [[ "$STEP_OUTPUT" == 0 ]] || fail_with "$STEP_OUTPUT key(s) survived a batch delete"
    emit "$scenario" pass ""
    ;;
sync-directory)
    mkdir -p "$work/tree/nested"
    for index in $(seq 1 12); do
        head -c 1024 /dev/urandom >"$work/tree/nested/file-$index.bin"
    done
    step "s3 sync" aws_run s3 sync "$work/tree" "s3://$bucket/mirror" --only-show-errors
    head -c 2048 /dev/urandom >"$work/tree/nested/file-1.bin"
    step "s3 sync (rerun)" aws_run s3 sync "$work/tree" "s3://$bucket/mirror" --only-show-errors
    # The exit code of a sync says nothing about what it copied, so the mirror is read back and
    # compared file by file.
    step "s3 sync (read back)" aws_run s3 sync "s3://$bucket/mirror" "$work/read-back" --only-show-errors
    diff -r "$work/tree" "$work/read-back" >&2 || fail_with "the mirror read back differs from the source tree after a rerun"
    emit "$scenario" pass ""
    ;;
esac
