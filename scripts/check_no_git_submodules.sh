#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_git_submodules.sh
#
# WHAT THIS CHECKS
#   That the repository declares no git submodule: there is no `.gitmodules`
#   file in the working tree or the index, and no index entry has mode 160000
#   (a gitlink), with or without a `.gitmodules` describing it.
#
# WHY
#   Downstream projects consume these crates as Cargo git dependencies, and
#   Cargo initialises every submodule of a git dependency unconditionally when
#   it checks the repository out — whichever package is requested and whatever
#   the workspace excludes; a consumer has no setting to skip it. A submodule
#   that a consumer cannot fetch (a private repository, an SSH-only URL)
#   therefore makes every revision of this repository unusable as a dependency
#   for them. rustfs/gateway#1591 is that failure: a private submodule froze
#   RustFS's pin and broke its public CI before anything compiled.
#
#   A gitlink without `.gitmodules` is checked separately because it is the
#   same hazard with the description deleted: Cargo still walks the index entry.
#
# HOW TO EXEMPT
#   There is no allowance. Pin an external source in a text file and have the
#   build that needs it verify the checkout, as rdma/rustfs-ucx.rev and
#   scripts/build-rdma.sh do.
#
# USAGE
#   scripts/check_no_git_submodules.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_git_submodules.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_no_git_submodules: %s\n' "$*" >&2
    exit 1
}

cd "$ROOT_DIR" || fail "cannot enter the repository root: ${ROOT_DIR}"
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'

# The index is the input. Without one this guard has read nothing, so it must not report green.
index="$(mktemp "${TMPDIR:-/tmp}/gateway-submodules.XXXXXX")" || fail 'cannot create input buffer'
trap 'rm -f "$index"' EXIT
toplevel="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 'cannot enumerate index entries (not a git repository?)'
# `git ls-files` lists only the subtree below the current directory, so a root that is a
# subdirectory of a repository would be judged on part of the index.
[[ "$(cd "$toplevel" && pwd -P)" == "$(pwd -P)" ]] ||
    fail "the root ${ROOT_DIR} is not the top level of its repository (${toplevel})"
git ls-files --stage -z >"$index" 2>/dev/null || fail 'cannot enumerate index entries (not a git repository?)'
[[ -s "$index" ]] || fail 'the index is empty; refusing to report a tree it has not read'

status=0
if [[ -e .gitmodules ]] || git ls-files --error-unmatch -- .gitmodules >/dev/null 2>&1; then
    printf '.gitmodules: declares git submodules\n' >&2
    status=1
fi

while IFS= read -r -d '' entry; do
    mode="${entry%% *}"
    path="${entry#*$'\t'}"
    if [[ "$mode" == 160000 ]]; then
        printf '%s: gitlink (mode 160000) — a submodule entry in the index\n' "$path" >&2
        status=1
    fi
done <"$index"

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Cargo initialises every submodule of a git dependency, so one a consumer cannot fetch makes this
whole repository unusable as a dependency for them (rustfs/gateway#1591). Remove the submodule
(`git rm --cached <path>` and delete .gitmodules) and pin the source in a text file that the build
needing it verifies, as rdma/rustfs-ucx.rev and scripts/build-rdma.sh do.
EOF
fi

exit "$status"
