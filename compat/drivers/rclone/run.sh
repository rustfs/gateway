#!/usr/bin/env bash
set -uo pipefail

# rclone driver. rclone drives aws-sdk-go-v2 at high concurrency and is how a real deployment mirrors
# a large tree, so it produces list-then-copy traffic shapes no single-object scenario reaches. It
# is also this matrix's only `UNSIGNED-PAYLOAD` writer, which is a payload mode of its own.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
scenario="${1:?scenario id required}"

case "$scenario" in
trailer-chunked-upload)
    unsupported "$scenario" "rclone offers no trailing-checksum upload switch; it declares UNSIGNED-PAYLOAD instead"
    ;;
streaming-chunked-upload)
    # Measured, not assumed: an unfiltered 9 MiB upload through this driver reaches the server as
    # `x-amz-content-sha256: UNSIGNED-PAYLOAD` with no chunk framing at all, and aws-sdk-go-v2
    # exposes no switch that selects signed aws-chunked framing. Recording that as a failure would
    # blame the server for a client's payload-mode choice; the wire assertion would go red for a
    # reason the server cannot fix.
    unsupported "$scenario" "aws-sdk-go-v2 declares UNSIGNED-PAYLOAD for object uploads and offers no signed aws-chunked mode"
    ;;
presigned-get | presigned-put)
    unsupported "$scenario" "rclone link produces a URL only for backends it can sign for interactively, not as a scenario step"
    ;;
versioned-object | copy-object | delete-batch | backup-restore)
    unsupported "$scenario" "rclone exposes no command that isolates this operation"
    ;;
bucket-lifecycle | small-object-roundtrip | large-multipart-upload | list-pagination | \
    range-download | sync-directory) ;;
*)
    printf 'rclone driver: unknown scenario %s\n' "$scenario" >&2
    exit 64
    ;;
esac

export RCLONE_CONFIG=/dev/null
export RCLONE_S3_PROVIDER=Other
export RCLONE_S3_ACCESS_KEY_ID="$COMPAT_ACCESS_KEY"
export RCLONE_S3_SECRET_ACCESS_KEY="$COMPAT_SECRET_KEY"
export RCLONE_S3_ENDPOINT="$COMPAT_ENDPOINT"
export RCLONE_S3_REGION="$COMPAT_REGION"
export RCLONE_S3_FORCE_PATH_STYLE=true
# Deliberately NOT setting no_check_bucket: with it, rclone skips bucket creation altogether and
# every upload answers NoSuchBucket, which would record a driver misconfiguration as a server
# failure. Left at its default, rclone probes with HeadBucket and creates with CreateBucket, both
# of which the reference backend registers.
export RCLONE_RETRIES=1
export RCLONE_LOW_LEVEL_RETRIES=1

remote=":s3:$COMPAT_BUCKET"
rclone_run() { rclone --config /dev/null "$@"; }

if [[ "$scenario" != bucket-lifecycle ]]; then
    if ! mkdir_output="$(rclone_run mkdir "$remote" 2>&1)"; then
        printf '%s\n' "$mkdir_output" >&2
        emit "$scenario" fail "rclone mkdir failed: $(printf '%s' "$mkdir_output" | tail -n 1)"
        exit 0
    fi
fi

case "$scenario" in
bucket-lifecycle)
    if ! mkdir_output="$(rclone_run mkdir "$remote" 2>&1)"; then
        printf '%s\n' "$mkdir_output" >&2
        emit "$scenario" fail "rclone mkdir failed: $(printf '%s' "$mkdir_output" | tail -n 1)"
        exit 0
    fi
    if ! rmdir_output="$(rclone_run rmdir "$remote" 2>&1)"; then
        printf '%s\n' "$rmdir_output" >&2
        emit "$scenario" fail "rclone rmdir failed: $(printf '%s' "$rmdir_output" | tail -n 1)"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
small-object-roundtrip | large-multipart-upload)
    size=4096
    export RCLONE_S3_UPLOAD_CUTOFF=200M
    export RCLONE_S3_CHUNK_SIZE=5M
    case "$scenario" in
    large-multipart-upload)
        size=12582912
        # Below the payload size, so rclone decides on its own to split the object into parts.
        export RCLONE_S3_UPLOAD_CUTOFF=5M
        ;;
    esac
    source_file="$COMPAT_WORKDIR/payload.bin"
    read_back_dir="$COMPAT_WORKDIR/read-back"
    mkdir -p "$read_back_dir"
    head -c "$size" /dev/urandom >"$source_file"
    if ! up_output="$(rclone_run copyto "$source_file" "$remote/payload.bin" 2>&1)"; then
        printf '%s\n' "$up_output" >&2
        emit "$scenario" fail "rclone copyto up failed: $(printf '%s' "$up_output" | tail -n 1)"
        exit 0
    fi
    if ! down_output="$(rclone_run copyto "$remote/payload.bin" "$read_back_dir/payload.bin" 2>&1)"; then
        printf '%s\n' "$down_output" >&2
        emit "$scenario" fail "rclone copyto down failed: $(printf '%s' "$down_output" | tail -n 1)"
        exit 0
    fi
    if ! cmp -s "$source_file" "$read_back_dir/payload.bin"; then
        emit "$scenario" fail "the object read back differs from the object written"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
list-pagination)
    seed="$COMPAT_WORKDIR/seed"
    mkdir -p "$seed"
    for index in $(seq -f '%04g' 0 24); do
        printf 'key %s\n' "$index" >"$seed/$index.txt"
    done
    if ! copy_output="$(rclone_run copy "$seed" "$remote/page" 2>&1)"; then
        printf '%s\n' "$copy_output" >&2
        emit "$scenario" fail "rclone copy failed while seeding the listing: $(printf '%s' "$copy_output" | tail -n 1)"
        exit 0
    fi
    if ! listing="$(rclone_run --s3-list-chunk 7 lsf "$remote/page" 2>&1)"; then
        printf '%s\n' "$listing" >&2
        emit "$scenario" fail "rclone lsf failed: $(printf '%s' "$listing" | tail -n 1)"
        exit 0
    fi
    listed="$(printf '%s\n' "$listing" | grep -c '\.txt$' || true)"
    if [[ "$listed" -ne 25 ]]; then
        emit "$scenario" fail "rclone lsf enumerated $listed of 25 seeded keys at a list chunk of 7"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
range-download)
    source_file="$COMPAT_WORKDIR/ranged.bin"
    head -c 1048576 /dev/urandom >"$source_file"
    if ! up_output="$(rclone_run copyto "$source_file" "$remote/ranged.bin" 2>&1)"; then
        printf '%s\n' "$up_output" >&2
        emit "$scenario" fail "rclone copyto failed: $(printf '%s' "$up_output" | tail -n 1)"
        exit 0
    fi
    if ! rclone_run cat --offset 1000 --count 4001 "$remote/ranged.bin" >"$COMPAT_WORKDIR/slice.bin" 2>"$COMPAT_WORKDIR/slice.err"; then
        cat "$COMPAT_WORKDIR/slice.err" >&2
        emit "$scenario" fail "rclone cat --offset failed: $(tail -n 1 "$COMPAT_WORKDIR/slice.err")"
        exit 0
    fi
    dd if="$source_file" bs=1 skip=1000 count=4001 of="$COMPAT_WORKDIR/expected.bin" 2>/dev/null
    if ! cmp -s "$COMPAT_WORKDIR/expected.bin" "$COMPAT_WORKDIR/slice.bin"; then
        emit "$scenario" fail "the returned range differs from the same slice of the source object"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
sync-directory)
    tree="$COMPAT_WORKDIR/tree"
    mkdir -p "$tree/nested"
    for index in $(seq 1 12); do
        head -c 1024 /dev/urandom >"$tree/nested/file-$index.bin"
    done
    if ! sync_output="$(rclone_run sync "$tree" "$remote/mirror" 2>&1)"; then
        printf '%s\n' "$sync_output" >&2
        emit "$scenario" fail "rclone sync failed: $(printf '%s' "$sync_output" | tail -n 1)"
        exit 0
    fi
    head -c 2048 /dev/urandom >"$tree/nested/file-1.bin"
    if ! resync_output="$(rclone_run sync "$tree" "$remote/mirror" 2>&1)"; then
        printf '%s\n' "$resync_output" >&2
        emit "$scenario" fail "rclone sync rerun failed: $(printf '%s' "$resync_output" | tail -n 1)"
        exit 0
    fi
    if ! check_output="$(rclone_run check "$tree" "$remote/mirror" --size-only 2>&1)"; then
        printf '%s\n' "$check_output" >&2
        emit "$scenario" fail "the mirror differs from the source after a rerun: $(printf '%s' "$check_output" | tail -n 1)"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
esac
