#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_dto_non_exhaustive.sh
#
# WHAT THIS CHECKS
#   That no generated dto struct carries `#[non_exhaustive]`.
#
# WHY
#   The intuitive answer — "mark them non_exhaustive so adding a field is not a
#   breaking change" — is wrong here, and measurably so. `#[non_exhaustive]`
#   forbids functional update syntax as well as full literals:
#
#       error[E0639]: cannot create non-exhaustive struct using struct expression
#
#   so `Foo { a, ..Default::default() }` stops compiling. rustfs has 4619 such
#   sites. Meanwhile a plain struct with `#[derive(Default)]` is *already*
#   immune to a new `Option` field, because FRU fills it in. The attribute buys
#   nothing and costs every construction site.
#
#   Real enums are the opposite case: downstream matches on them rather than
#   constructing them, so `#[non_exhaustive]` there is correct and this guard
#   deliberately does not look at them.
#
#   See ADR-0004 rules P1 and P5.
#
# HOW TO EXEMPT
#   There is no exemption. A dto that needs `#[non_exhaustive]` is a dto that
#   should not be a struct; take it to an ADR.
#
# USAGE
#   scripts/check_no_dto_non_exhaustive.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_dto_non_exhaustive.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

status=0

# Walk every generated dto file and report a `#[non_exhaustive]` that is followed
# by a `struct` before the next `enum`. Attribute and item sit on separate lines,
# so this needs a tiny state machine rather than a grep.
while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ -f "$file" ]] || continue
    awk -v f="$file" '
        # Skip comments first. The generated dto documents this very rule, so the
        # literal `#[non_exhaustive]` appears in prose; matching it there would make
        # the guard fire on the text that explains why it exists.
        /^[[:space:]]*(\/\/|\*)/ { next }
        /#\[non_exhaustive\]/ { pending = NR; next }
        pending && /^[[:space:]]*(pub )?struct / {
            printf "%s:%d: dto struct carries #[non_exhaustive], which forbids ..Default::default() (E0639); see ADR-0004 P1\n", f, pending > "/dev/stderr"
            bad = 1
            pending = 0
            next
        }
        pending && /^[[:space:]]*(pub )?enum / { pending = 0; next }
        { if (pending && $0 !~ /^[[:space:]]*(#|\/\/|$)/) pending = 0 }
        END { exit bad ? 1 : 0 }
    ' "$file" || status=1
# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form lists
# only *tracked* files, so a brand-new file stays invisible to this guard right up until the
# moment `git add -A` commits it. That is how CJK text reached commit 343f044 past a guard run
# that had just reported success. `--exclude-standard` keeps ignored files out.
done < <(git ls-files --cached --others --exclude-standard -- 'generated/dto/*' 'generated/dto/**' 2>/dev/null || true)

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

ADR-0004 P1: dto structs are plain, public-field, `#[derive(Default)]` structs.
Adding an `Option` field to one of those is already a minor change, because
downstream writes `..Default::default()`. Marking it `#[non_exhaustive]` breaks
exactly that syntax and buys nothing in return.
EOF
fi

exit "$status"
