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
#     3. No MinIO *server* source is vendored: a Go file, or any path under a
#        `minio/minio`, `minio/cmd` or `minio/internal` directory.
#     4. Nothing declares `minio/minio` as a submodule or a dependency.
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
#   Rules 2, 3 and 4 have no exemption. A file that says it was ported, a
#   vendored server tree, and a dependency edge are the three things this guard
#   exists to make impossible; an allowance for one of them is the guard
#   deleted.
#
# USAGE
#   scripts/check_no_minio_source.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_minio_source.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/clean-room-allowances.txt"

cd "$ROOT_DIR"

status=0

# This script states the patterns it looks for, so it matches itself on every rule. Its own path
# and the allowance file are skipped unconditionally rather than through the allowance list: a
# guard that could be silenced by being listed in the file it reads is not a guard.
SELF="scripts/check_no_minio_source.sh"
ALLOWANCE_PATH="scripts/allowances/clean-room-allowances.txt"

# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form lists
# only tracked files, so a newly added file stays invisible until the commit that adds it has
# already happened. Binary files are filtered per rule with `grep -I`.
files=()
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ "$file" == "$SELF" ]] && continue
    [[ "$file" == "$ALLOWANCE_PATH" ]] && continue
    files+=("$file")
done < <(git ls-files --cached --others --exclude-standard 2>/dev/null || true)

# A guard whose input is missing must fail, not skip. This one always has input: the repository is
# never empty, so an empty list means `git ls-files` did not run, and reporting success on that is
# how a green line comes to mean nothing.
if [[ "${#files[@]}" -eq 0 ]]; then
    printf 'check_no_minio_source: no files found under %s; the guard could not read the tree\n' "$ROOT_DIR" >&2
    exit 1
fi

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -s ' \t' ' ')"
        line="${line# }"
        line="${line% }"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
fi

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "$1"
}

# ---------------------------------------------------------------------------
# Rule 1 — no AGPL licence header, and nothing claiming the AGPL as its licence.
# ---------------------------------------------------------------------------
AGPL_PATTERN='GNU AFFERO GENERAL PUBLIC LICENSE|AGPL-3\.0|Affero General Public License'

for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if grep -IEqi "$AGPL_PATTERN" "$file" 2>/dev/null; then
        if is_allowed "$file"; then
            continue
        fi
        printf '%s: names the AGPL; every file in this repository is Apache-2.0, and AGPL text here means AGPL source here\n' \
            "$file" >&2
        status=1
    fi
done

# ---------------------------------------------------------------------------
# Rule 2 — no provenance comment claiming a port from an AGPL implementation.
# ---------------------------------------------------------------------------
# The verbs are the ones a person writes when they are being honest about what they did. The window
# between the verb and the project name is bounded so that a sentence mentioning both in unrelated
# clauses does not match.
PORT_PATTERN='(ported|adapted|translated|transcribed|transliterated|copied|derived|lifted|taken|based)[[:space:]]+(from|on)[[:space:]]+[^.]{0,60}(minio|garage)'

for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if grep -IEqi "$PORT_PATTERN" "$file" 2>/dev/null; then
        printf '%s: claims its contents came from an AGPL implementation; a port is a derivative work, not inspiration\n' \
            "$file" >&2
        grep -IEni "$PORT_PATTERN" "$file" 2>/dev/null | head -3 >&2
        status=1
    fi
done

# ---------------------------------------------------------------------------
# Rule 3 — no vendored server source.
# ---------------------------------------------------------------------------
for file in "${files[@]}"; do
    case "$file" in
        *.go)
            printf '%s: a Go source file; the MinIO server is Go, and this project has no Go in it\n' "$file" >&2
            status=1
            ;;
        */minio/minio/* | minio/minio/* | */minio/cmd/* | minio/cmd/* | */minio/internal/* | minio/internal/*)
            printf '%s: sits under a vendored MinIO server tree\n' "$file" >&2
            status=1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Rule 4 — no submodule or dependency edge onto the server repository.
# ---------------------------------------------------------------------------
if [[ -f .gitmodules ]] && grep -Eqi 'minio/minio(\.git)?' .gitmodules; then
    printf '.gitmodules: declares the MinIO server repository as a submodule\n' >&2
    status=1
fi

while IFS= read -r manifest; do
    [[ -n "$manifest" ]] || continue
    [[ -f "$manifest" ]] || continue
    if grep -Eqi '^[[:space:]]*minio[[:space:]]*=' "$manifest"; then
        printf '%s: declares a `minio` dependency; the client library is `minio-go` and is not a Rust crate\n' \
            "$manifest" >&2
        status=1
    fi
done < <(git ls-files --cached --others --exclude-standard -- 'Cargo.toml' '*/Cargo.toml' 2>/dev/null || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Clean-room provenance is a licence boundary, not a style rule. MinIO's server
is AGPL-3.0 and archived; its wire *behaviour* may be reproduced from protocol
observation and public documentation, and its *source* may not be read, copied,
vendored or ported. See docs/dialects.md.
EOF
fi

exit "$status"
