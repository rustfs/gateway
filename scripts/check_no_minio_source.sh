#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_minio_source.sh
#
# WHAT THIS CHECKS
#   Four provenance facts about the working tree, all of them mechanical:
#
#     1. No file carries an AGPL licence header or names the AGPL as its own
#        licence. Every source file here is Apache-2.0.
#     2. No file carries a provenance comment saying its contents were ported,
#        adapted, translated or copied from MinIO (or from Garage, which is
#        AGPL too). "Inspired by" is not the line; a line-by-line translation
#        into Rust is a derivative work.
#     3. No MinIO *server* source is vendored: no path under a `minio/minio`,
#        `minio/cmd` or `minio/internal` directory, and no Go file anywhere except
#        directly inside one client-matrix driver directory, `compat/drivers/<client>/`.
#     4. Nothing declares `minio/minio` as a submodule or a dependency.
#     5. A Go client driver stays a client of someone else's SDK: its directory has a
#        go.mod; no go.mod, go.sum or Go file in the tree references a
#        `github.com/minio/` module (the whole organisation, not only the server, so
#        nothing has to be judged case by case); no driver file carries a MinIO
#        copyright line; and every driver Go file carries the Apache-2.0 header.
#
# WHY
#   `minio/minio` is AGPL-3.0 and its repository is archived. Compatibility
#   with its wire behaviour is a legitimate goal and behavioural facts are not
#   copyrightable, so this project reproduces them clean-room: from protocol
#   observation, public API documentation and its own captures. What is not
#   allowed is reading that server's source and porting it — that produces a
#   derivative work, and no amount of rewriting changes the licence that
#   attaches to it.
#
#   The failure mode this guard exists for is silent. A ported function looks
#   exactly like a written one once the variable names are Rust-shaped, and the
#   only durable evidence either way is what the tree says about where its
#   contents came from. So the tree is required to say nothing that contradicts
#   the clean-room claim, and a PR touching dialect behaviour carries the claim
#   in as many words.
#
#   `minio-go` (Apache-2.0) as a *client* test tool is unaffected by all four
#   rules, and so is a `dialect-minio` crate written from observation: this
#   guard is about provenance, not about the word.
#
# HOW TO EXEMPT
#   Rule 1 only, and only for prose that has to name the licence in order to
#   state the policy. Add a line to
#   `scripts/allowances/clean-room-allowances.txt`:
#
#       <path>    # <why this file has to name the AGPL>
#
#   Rules 2 to 5 have no exemption. A file that says it was ported, a vendored
#   server tree, and a dependency edge are the three things this guard exists to
#   make impossible; an allowance for one of them is the guard deleted.
#
#   Rule 3 once refused every Go file. It was narrowed on purpose (rustfs/gateway#974,
#   ruled by the maintainer through the slot coordinator): the rule exists to keep
#   MinIO server source out, and a client-matrix driver that calls AWS's Go SDK is
#   not that. The narrowing is a fixed directory shape plus rule 5, not a list.
#
# USAGE
#   scripts/check_no_minio_source.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_minio_source.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/clean-room-allowances.txt"

cd "$ROOT_DIR"

for required in git grep mktemp; do
    if ! command -v "$required" >/dev/null 2>&1; then
        printf 'check_no_minio_source: required command is missing: %s\n' "$required" >&2
        exit 1
    fi
done

status=0
fail() {
    printf '%s\n' "$1" >&2
    status=1
}

# This script states the patterns it looks for, so it matches itself on every rule. Its own path
# and the allowance file are skipped unconditionally rather than through the allowance list.
SELF="scripts/check_no_minio_source.sh"
ALLOWANCE_PATH="scripts/allowances/clean-room-allowances.txt"

file_list="$(mktemp "${TMPDIR:-/tmp}/gateway-clean-room-files.XXXXXX")"
tracked_list="$(mktemp "${TMPDIR:-/tmp}/gateway-clean-room-tracked.XXXXXX")"
untracked_list="$(mktemp "${TMPDIR:-/tmp}/gateway-clean-room-untracked.XXXXXX")"
hits="$(mktemp "${TMPDIR:-/tmp}/gateway-clean-room-hits.XXXXXX")"
cleanup() { rm -f "$file_list" "$tracked_list" "$untracked_list" "$hits"; }
trap cleanup EXIT

if ! git ls-files --cached --others --exclude-standard >"$file_list"; then
    printf 'check_no_minio_source: cannot list working-tree files\n' >&2
    exit 1
fi
if ! git ls-files --others --exclude-standard >"$untracked_list"; then
    printf 'check_no_minio_source: cannot list untracked files\n' >&2
    exit 1
fi
if ! git ls-files --cached >"$tracked_list"; then
    printf 'check_no_minio_source: cannot list tracked files\n' >&2
    exit 1
fi

files=()
content_files=()
untracked_files=()
tracked_symlink_files=()
manifests=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    case "$file" in
    Cargo.toml | */Cargo.toml) manifests+=("$file") ;;
    esac
    [[ "$file" == "$SELF" || "$file" == "$ALLOWANCE_PATH" ]] && continue
    files+=("$file")
    [[ -f "$file" ]] && content_files+=("$file")
done <"$file_list"
while IFS= read -r file; do
    [[ -n "$file" && -f "$file" ]] || continue
    [[ "$file" == "$SELF" || "$file" == "$ALLOWANCE_PATH" ]] && continue
    untracked_files+=("$file")
done <"$untracked_list"
while IFS= read -r file; do
    [[ -n "$file" && -L "$file" ]] || continue
    [[ "$file" == "$SELF" || "$file" == "$ALLOWANCE_PATH" ]] && continue
    if [[ ! -e "$file" ]]; then
        fail "${file}: tracked symlink is broken; the guard cannot inspect its target"
        continue
    fi
    [[ -f "$file" ]] && tracked_symlink_files+=("$file")
done <"$tracked_list"
if [[ "${#files[@]}" -eq 0 || "${#content_files[@]}" -eq 0 ]]; then
    printf 'check_no_minio_source: no files found under %s; the guard could not read the tree\n' "$ROOT_DIR" >&2
    exit 1
fi

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    # Normalize all lines in one process; comments and exact-path matching stay unchanged.
    if ! normalized_allowances="$(while IFS= read -r line; do
        printf '%s\n' "${line%%#*}"
    done <"$ALLOWANCE_FILE" | tr -s ' \t' ' ')"; then
        printf 'check_no_minio_source: cannot normalize the allowance file\n' >&2
        exit 1
    fi
    while IFS= read -r line; do
        line="${line# }"
        line="${line% }"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <<<"$normalized_allowances"
else
    printf 'check_no_minio_source: %s is missing; the allowlist cannot be skipped\n' "$ALLOWANCE_FILE" >&2
    exit 1
fi

is_allowed() {
    local candidate="$1" allowed
    while IFS= read -r allowed; do
        [[ "$allowed" == "$candidate" ]] && return 0
    done <<<"$ALLOWANCES"
    return 1
}

# A no-match exit is expected; an unreadable input or other grep error fails closed.
scan_files() {
    local rc=0
    if grep "$@" >"$hits"; then
        return
    else
        rc=$?
    fi
    if [[ "$rc" -ne 1 ]]; then
        fail "check_no_minio_source: batch scan failed"
    fi
    : >"$hits"
}

scan_tree() {
    local pattern="$1" rc=0
    local -a extra_files=()
    local offset
    if [[ "${#untracked_files[@]}" -gt 0 ]]; then
        extra_files+=("${untracked_files[@]}")
    fi
    if [[ "${#tracked_symlink_files[@]}" -gt 0 ]]; then
        extra_files+=("${tracked_symlink_files[@]}")
    fi
    : >"$hits"
    if git grep -IlEi -- "$pattern" -- >>"$hits"; then
        :
    else
        rc=$?
        if [[ "$rc" -ne 1 ]]; then
            fail "check_no_minio_source: tracked-tree scan failed"
        fi
    fi
    # git grep deliberately does not follow tracked symlinks. Scan their ordinary-file targets,
    # together with untracked files, in bounded batches so neither class can evade provenance
    # checks and a large tree cannot exceed the process argument limit.
    for ((offset = 0; offset < ${#extra_files[@]}; offset += 64)); do
        if grep -IlEi -- "$pattern" "${extra_files[@]:offset:64}" >>"$hits"; then
            :
        else
            rc=$?
            if [[ "$rc" -ne 1 ]]; then
                fail "check_no_minio_source: extra-file batch scan failed"
            fi
        fi
    done
}

# Rules 1 and 2 share one tree read. Only the small set of matching files is inspected again to
# distinguish an allowlisted licence mention from a forbidden provenance statement.
AGPL_PATTERN='GNU AFFERO GENERAL PUBLIC LICENSE|AGPL-3\.0|Affero General Public License'
PORT_PATTERN='(ported|adapted|translated|transcribed|transliterated|copied|derived|lifted|taken|based)[[:space:]]+(from|on)[[:space:]]+[^.]{0,60}(minio|garage)'
scan_tree "${AGPL_PATTERN}|${PORT_PATTERN}"
matched_files=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ "$file" == "$SELF" || "$file" == "$ALLOWANCE_PATH" ]] && continue
    matched_files+=("$file")
done <"$hits"

if [[ "${#matched_files[@]}" -gt 0 ]]; then
    scan_files -IlEi -- "$AGPL_PATTERN" "${matched_files[@]}"
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        if ! is_allowed "$file"; then
            fail "${file}: names the AGPL; every file in this repository is Apache-2.0, and AGPL text here means AGPL source here"
        fi
    done <"$hits"

    scan_files -IHEni -- "$PORT_PATTERN" "${matched_files[@]}"
    last_file=""
    diagnostic_count=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        # This one exact sentence states the clean-room prohibition; it does not claim that any
        # implementation came from the server. Keep the exception narrower than a path allowance
        # so a positive copied/ported provenance statement in the same crate still fails.
        if [[ "$line" == crates/dialect-minio/MAP.md:[0-9]*:This\ crate\ is\ clean-room\ protocol\ code.\ It\ must\ never\ be\ derived\ from\ MinIO\ server\ source. ]]; then
            continue
        fi
        file="${line%%:*}"
        if [[ "$file" != "$last_file" ]]; then
            fail "${file}: claims its contents came from an AGPL implementation; a port is a derivative work, not inspiration"
            last_file="$file"
            diagnostic_count=0
        fi
        if [[ "$diagnostic_count" -lt 3 ]]; then
            printf '%s\n' "$line" >&2
            diagnostic_count=$((diagnostic_count + 1))
        fi
    done <"$hits"
fi

# Rule 3 — no vendored server source. Go only directly inside compat/drivers/<client>/.
go_driver_files=()
go_driver_dirs=()
go_modules=()
for file in "${files[@]}"; do
    case "$file" in
    */minio/minio/* | minio/minio/* | */minio/cmd/* | minio/cmd/* | */minio/internal/* | minio/internal/*)
        fail "${file}: sits under a vendored MinIO server tree"
        continue
        ;;
    esac
    case "$file" in
    go.mod | */go.mod | go.sum | */go.sum) go_modules+=("$file") ;;
    esac
    [[ "$file" == *.go ]] || continue
    if [[ "$file" =~ ^compat/drivers/[^/]+/[^/]+\.go$ ]]; then
        go_driver_files+=("$file")
        dir="${file%/*}"
        case " ${go_driver_dirs[*]:-} " in
        *" $dir "*) ;;
        *) go_driver_dirs+=("$dir") ;;
        esac
    else
        fail "${file}: a Go source file outside compat/drivers/<client>/; the MinIO server is Go, and Go is admitted here only as a client-matrix driver"
    fi
done

# Rule 5 — a Go client driver is a client of someone else's SDK, never MinIO code.
for dir in "${go_driver_dirs[@]:+${go_driver_dirs[@]}}"; do
    [[ -f "$dir/go.mod" ]] || fail "${dir}: has Go source but no go.mod; its module graph cannot be checked"
done
go_scanned=()
[[ "${#go_modules[@]}" -gt 0 ]] && go_scanned+=("${go_modules[@]}")
[[ "${#go_driver_files[@]}" -gt 0 ]] && go_scanned+=("${go_driver_files[@]}")
if [[ "${#go_scanned[@]}" -gt 0 ]]; then
    scan_files -alEi -- 'github\.com/minio/' "${go_scanned[@]}"
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        fail "${file}: references a github.com/minio module; a Go client driver may depend on no MinIO code at all"
    done <"$hits"
fi
if [[ "${#go_driver_files[@]}" -gt 0 ]]; then
    scan_files -alEi -- '(copyright.*minio|minio,[[:space:]]*inc)' "${go_driver_files[@]}"
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        fail "${file}: carries a MinIO copyright line"
    done <"$hits"
    # Listed as the complement of the files that match: `grep -L` reports its exit status
    # differently between GNU and BSD grep, and a guard must not depend on which one runs it.
    scan_files -alF -- 'Licensed under the Apache License, Version 2.0' "${go_driver_files[@]}"
    headed=" $(tr '\n' ' ' <"$hits") "
    for file in "${go_driver_files[@]}"; do
        [[ "$headed" == *" $file "* ]] ||
            fail "${file}: lacks the Apache-2.0 licence header every source file here carries"
    done
fi

# Rule 4 — no submodule or dependency edge onto the server repository.
if [[ -f .gitmodules ]]; then
    scan_files -IlEi -- 'minio/minio(\.git)?' .gitmodules
    [[ ! -s "$hits" ]] || fail '.gitmodules: declares the MinIO server repository as a submodule'
fi
if [[ "${#manifests[@]}" -gt 0 ]]; then
    # Do not use grep -I here: Cargo manifests are required text inputs, and treating a NUL-bearing
    # manifest as a harmless binary would silently skip a forbidden dependency after the NUL.
    scan_files -alEi -- '^[[:space:]]*minio[[:space:]]*=' "${manifests[@]}"
    while IFS= read -r manifest; do
        [[ -n "$manifest" ]] || continue
        fail "${manifest}: declares a \`minio\` dependency; the client library is \`minio-go\` and is not a Rust crate"
    done <"$hits"
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Clean-room provenance is a licence boundary, not a style rule. MinIO's server
is AGPL-3.0 and archived; its wire *behaviour* may be reproduced from protocol
observation and public documentation, and its *source* may not be read, copied,
vendored or ported. See docs/dialects.md.
EOF
fi

exit "$status"
