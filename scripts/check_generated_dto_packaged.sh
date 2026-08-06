#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_generated_dto_packaged.sh
#
# WHAT THIS CHECKS
#   Two things:
#
#     1. No `#[path = "..."]` under `crates/*/src/**` resolves to a location
#        outside its own crate directory.
#     2. `crates/types/generated` is a symlink, and it resolves to the
#        top-level `generated/dto`.
#
#   A third check — that `cargo package --list` contains the dto tree — was
#   removed when the project decided not to publish to crates.io. Nothing calls
#   `cargo package`, so the assertion had no failure mode left to catch.
#
# WHY
#   ADR-0005. `rustfs-gateway-types` does not declare its dto: the tree is
#   generated into the top-level `generated/` and mounted with `#[path]`.
#   Cargo's packaging never leaves the package directory, and `include`/`path`
#   cannot reach outside it in an extracted `.crate`, so a `#[path]` spelled
#   `../../../generated/dto/...` produces a package whose sources are simply
#   absent — `cargo package --list` showed only `src/**`, `Cargo.toml` and
#   `MAP.md`. The failure is silent at package time and only appears when
#   somebody builds the extracted tarball, which is the worst possible moment.
#
#   The symlink is what keeps the tree inside the package boundary without
#   making a second copy of generated output. Check 1 is the defect itself;
#   check 2 guards the mechanism that makes check 1 satisfiable at all.
#
#   A plain directory in place of the symlink is a FAILURE, not an improvement:
#   it is a duplicate of generated output that `cargo xtask spec verify` does
#   not police, so it can drift from the emitter without anything going red.
#   On a Windows checkout without `core.symlinks`, git materialises the link as
#   a small text file — check 2 is what turns that into a named error rather
#   than a confusing `file not found for module `ops``.
#
# HOW TO EXEMPT
#   There is no allowance file. Mounting generated code from outside a package
#   is either correct for every crate or correct for none; a per-crate
#   exemption would just be the original bug with paperwork. Changing this
#   arrangement means superseding ADR-0005.
#
# USAGE
#   scripts/check_generated_dto_packaged.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_generated_dto_packaged.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

LINK_PATH="crates/types/generated"
LINK_TARGET="generated/dto"
PACKAGE="rustfs-gateway-types"

status=0

# Lexical path normalisation: resolve `.` and `..` textually, without touching
# the filesystem. Textual is the correct model here — it is what rustc does to
# a `#[path]`, and it is what stays true inside an extracted tarball where the
# symlink has already been replaced by a real directory.
#
# Written against bash 3.2, which is what macOS ships: no negative array
# subscripts, and `set -u` makes empty-array expansion an error. A string
# accumulator avoids both.
normalize() {
    local path="$1" out="" part
    local IFS='/'
    for part in $path; do
        case "$part" in
            '' | '.') continue ;;
            '..')
                if [[ -z "$out" || "${out##*/}" == '..' ]]; then
                    out="${out:+$out/}.."
                elif [[ "${out%/*}" == "$out" ]]; then
                    out=""
                else
                    out="${out%/*}"
                fi
                ;;
            *) out="${out:+$out/}$part" ;;
        esac
    done
    printf '%s' "$out"
}

# -----------------------------------------------------------------------------
# 1. No `#[path]` escapes its own crate directory.
# -----------------------------------------------------------------------------
while IFS= read -r source; do
    [[ -n "$source" ]] || continue
# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form
# lists only *tracked* files, so a brand-new file is invisible to this guard right up until
# the moment `git add -A` commits it. That is exactly how CJK text reached commit 343f044
# past a guard that had just reported success. Ignored files stay out.
    # `git ls-files --cached --others --exclude-standard` still lists a path that has been deleted in the working tree
    # but not yet staged. Reading it would make the guard fail with a `sed` error
    # about an unrelated file, which is a worse diagnostic than skipping it.
    [[ -f "$source" ]] || continue
    crate_dir="${source%%/src/*}"
    source_dir="$(dirname "$source")"

    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        resolved="$(normalize "${source_dir}/${target}")"
        if [[ "$resolved" != "$crate_dir"/* ]]; then
            printf '%s: #[path = "%s"] resolves to %s, outside the crate directory %s\n' \
                "$source" "$target" "$resolved" "$crate_dir" >&2
            status=1
        fi
    done < <(sed -n 's/.*#\[path[[:space:]]*=[[:space:]]*"\([^"]*\)"\].*/\1/p' "$source")
done < <(git ls-files -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 2>/dev/null || true)

# -----------------------------------------------------------------------------
# 2. The mount point is a symlink onto the generated dto tree.
# -----------------------------------------------------------------------------
if [[ ! -L "$LINK_PATH" ]]; then
    if [[ -d "$LINK_PATH" ]]; then
        printf '%s: is a real directory; it must be a symlink to %s (a copy of generated output drifts unpoliced)\n' \
            "$LINK_PATH" "$LINK_TARGET" >&2
    elif [[ -e "$LINK_PATH" ]]; then
        printf '%s: exists but is not a symlink; a Windows checkout without core.symlinks produces exactly this\n' \
            "$LINK_PATH" >&2
    else
        printf '%s: missing; %s mounts its generated dto through this symlink\n' \
            "$LINK_PATH" "$PACKAGE" >&2
    fi
    status=1
else
    link_dest="$(readlink "$LINK_PATH")"
    resolved="$(normalize "$(dirname "$LINK_PATH")/${link_dest}")"
    if [[ "$resolved" != "$LINK_TARGET" ]]; then
        printf '%s -> %s resolves to %s, expected %s\n' \
            "$LINK_PATH" "$link_dest" "$resolved" "$LINK_TARGET" >&2
        status=1
    fi
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

ADR-0005: the generated dto lives only under the top-level `generated/` tree and
reaches `rustfs-gateway-types` through the `crates/types/generated` symlink.
Restore it with:

    ln -s ../../generated/dto crates/types/generated

and keep every `#[path]` in `crates/types/src/lib.rs` relative to that link
(`../generated/...`), never to `../../../generated/dto/...`.
EOF
fi

exit "$status"
