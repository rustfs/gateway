#!/usr/bin/env bash
set -uo pipefail

# mc driver. The MinIO client is what RustFS users reach for first, and its transport is minio-go,
# whose protocol expectations differ from the AWS SDKs in ways that have historically been where
# MinIO-ecosystem compatibility breaks.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

require_env COMPAT_ENDPOINT COMPAT_ACCESS_KEY COMPAT_SECRET_KEY COMPAT_REGION COMPAT_BUCKET COMPAT_WORKDIR
scenario="${1:?scenario id required}"

case "$scenario" in
trailer-chunked-upload)
    unsupported "$scenario" "mc does not expose a trailing-checksum upload; minio-go signs the chunks instead"
    ;;
presigned-get | presigned-put)
    unsupported "$scenario" "mc share generates a URL but redeems it with the same client, which would not test cross-implementation presigning"
    ;;
versioned-object)
    unsupported "$scenario" "mc version enable requires the bucket-versioning admin surface this matrix does not target"
    ;;
copy-object | delete-batch | backup-restore | large-multipart-upload | range-download)
    unsupported "$scenario" "mc exposes no command that isolates this operation"
    ;;
bucket-lifecycle | small-object-roundtrip | streaming-chunked-upload | list-pagination | sync-directory) ;;
*)
    printf 'mc driver: unknown scenario %s\n' "$scenario" >&2
    exit 64
    ;;
esac

config_dir="$COMPAT_WORKDIR/mc-config"
mkdir -p "$config_dir"
alias_name="sut"
mc_run() { mc --config-dir "$config_dir" --quiet --no-color "$@"; }

if ! alias_output="$(mc_run alias set "$alias_name" "$COMPAT_ENDPOINT" "$COMPAT_ACCESS_KEY" "$COMPAT_SECRET_KEY" --api S3v4 2>&1)"; then
    printf '%s\n' "$alias_output" >&2
    emit "$scenario" fail "mc alias set failed: $(printf '%s' "$alias_output" | tail -n 1)"
    exit 0
fi

if ! mb_output="$(mc_run mb "$alias_name/$COMPAT_BUCKET" 2>&1)"; then
    printf '%s\n' "$mb_output" >&2
    emit "$scenario" fail "mc mb failed: $(printf '%s' "$mb_output" | tail -n 1)"
    exit 0
fi

case "$scenario" in
bucket-lifecycle)
    if ! rb_output="$(mc_run rb --force "$alias_name/$COMPAT_BUCKET" 2>&1)"; then
        printf '%s\n' "$rb_output" >&2
        emit "$scenario" fail "mc rb failed: $(printf '%s' "$rb_output" | tail -n 1)"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
small-object-roundtrip | streaming-chunked-upload)
    size=4096
    [[ "$scenario" == streaming-chunked-upload ]] && size=9437184
    source_file="$COMPAT_WORKDIR/payload.bin"
    read_back="$COMPAT_WORKDIR/read-back.bin"
    head -c "$size" /dev/urandom >"$source_file"
    if ! cp_output="$(mc_run cp "$source_file" "$alias_name/$COMPAT_BUCKET/payload.bin" 2>&1)"; then
        printf '%s\n' "$cp_output" >&2
        emit "$scenario" fail "mc cp up failed: $(printf '%s' "$cp_output" | tail -n 1)"
        exit 0
    fi
    if ! get_output="$(mc_run cp "$alias_name/$COMPAT_BUCKET/payload.bin" "$read_back" 2>&1)"; then
        printf '%s\n' "$get_output" >&2
        emit "$scenario" fail "mc cp down failed: $(printf '%s' "$get_output" | tail -n 1)"
        exit 0
    fi
    if ! cmp -s "$source_file" "$read_back"; then
        emit "$scenario" fail "the object read back differs from the object written"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
list-pagination)
    for index in $(seq -f '%04g' 0 24); do
        printf 'key %s\n' "$index" >"$COMPAT_WORKDIR/entry.txt"
        if ! put_output="$(mc_run cp "$COMPAT_WORKDIR/entry.txt" "$alias_name/$COMPAT_BUCKET/page/$index.txt" 2>&1)"; then
            printf '%s\n' "$put_output" >&2
            emit "$scenario" fail "mc cp failed while seeding the listing: $(printf '%s' "$put_output" | tail -n 1)"
            exit 0
        fi
    done
    if ! listing="$(mc_run ls --recursive "$alias_name/$COMPAT_BUCKET/page/" 2>&1)"; then
        printf '%s\n' "$listing" >&2
        emit "$scenario" fail "mc ls failed: $(printf '%s' "$listing" | tail -n 1)"
        exit 0
    fi
    listed="$(printf '%s\n' "$listing" | grep -c '\.txt$' || true)"
    if [[ "$listed" -ne 25 ]]; then
        emit "$scenario" fail "mc ls enumerated $listed of 25 seeded keys"
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
    if ! mirror_output="$(mc_run mirror "$tree" "$alias_name/$COMPAT_BUCKET/mirror" 2>&1)"; then
        printf '%s\n' "$mirror_output" >&2
        emit "$scenario" fail "mc mirror failed: $(printf '%s' "$mirror_output" | tail -n 1)"
        exit 0
    fi
    head -c 2048 /dev/urandom >"$tree/nested/file-1.bin"
    if ! remirror_output="$(mc_run mirror --overwrite "$tree" "$alias_name/$COMPAT_BUCKET/mirror" 2>&1)"; then
        printf '%s\n' "$remirror_output" >&2
        emit "$scenario" fail "mc mirror rerun failed: $(printf '%s' "$remirror_output" | tail -n 1)"
        exit 0
    fi
    # A mirror that copied nothing exits zero too. Count what landed, or this scenario cannot fail.
    if ! mirrored="$(mc_run ls --recursive "$alias_name/$COMPAT_BUCKET/mirror" 2>&1)"; then
        printf '%s\n' "$mirrored" >&2
        emit "$scenario" fail "mc ls after mirror failed: $(printf '%s' "$mirrored" | tail -n 1)"
        exit 0
    fi
    landed="$(printf '%s\n' "$mirrored" | grep -c '\.bin$' || true)"
    if [[ "$landed" -ne 12 ]]; then
        emit "$scenario" fail "mc mirror left $landed of 12 files in the bucket"
        exit 0
    fi
    emit "$scenario" pass ""
    ;;
esac
