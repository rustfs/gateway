#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_license_headers.sh
#
# WHAT THIS CHECKS
#   That every tracked `.rs` file opens with the Apache-2.0 licence header used
#   across rustfs/rustfs:
#
#       // Copyright <year> RustFS Team
#       //
#       // Licensed under the Apache License, Version 2.0 (the "License");
#       // ...
#
#   The assertion is deliberately loose: the first 14 lines must contain the
#   line `Licensed under the Apache License, Version 2.0`. It is NOT a
#   byte-for-byte comparison, because the copyright year moves and future
#   contributors may be credited on the copyright line. What must not vary is
#   the licence grant itself.
#
#   Scope: tracked `*.rs` files only. `target/` is untracked and therefore never
#   seen; `generated/**` is excluded explicitly so that a future codegen output
#   tree does not have to carry per-file headers (the generator's own source
#   does). Shell scripts are not required to carry a header — the main
#   repository only headers 19 of its 72 scripts, and a guard nobody follows is
#   worse than no guard.
#
# WHY
#   ADR-0001 (licensing and provenance boundary): this project is Apache-2.0 and
#   is a clean-room implementation. A per-file licence header is what makes the
#   grant survive file-level copying — a file lifted out of this repository into
#   another project carries its licence with it, and a file arriving here
#   WITHOUT the header is exactly the case that needs provenance review before
#   it is merged. The header is therefore a provenance tripwire, not paperwork.
#
# HOW TO EXEMPT
#   Add the exact repository-relative path to
#   `scripts/allowances/license-header-allowances.txt` (create it if absent):
#
#       path/to/file.rs    # <why this file cannot carry the header>
#
#   Vendored third-party code under a compatible licence is the only expected
#   reason, and it belongs in a clearly named `vendor/` or `third_party/` tree
#   with its upstream licence text preserved.
#
# USAGE
#   scripts/check_license_headers.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_license_headers.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/license-header-allowances.txt"

cd "$ROOT_DIR"

HEADER_MARKER='Licensed under the Apache License, Version 2.0'
HEADER_WINDOW=14

status=0

ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d ' \t')"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
fi

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -xF "$1" >/dev/null
}

checked=0
while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    [[ -f "$file" ]] || continue
    if is_allowed "$file"; then
        continue
    fi
    checked=$((checked + 1))
    if ! head -n "$HEADER_WINDOW" "$file" | grep -F "$HEADER_MARKER" >/dev/null; then
        printf '%s: missing the Apache-2.0 licence header in the first %s lines\n' \
            "$file" "$HEADER_WINDOW" >&2
        status=1
    fi
# `--cached --others --exclude-standard` rather than a bare `git ls-files`: the bare form lists
# only *tracked* files, so a brand-new file stays invisible to this guard right up until the
# moment `git add -A` commits it. That is how CJK text reached commit 343f044 past a guard run
# that had just reported success. `--exclude-standard` keeps ignored files out.
done < <(git ls-files --cached --others --exclude-standard -- '*.rs' ':!:target/*' ':!:generated/*' ':!:*/generated/*' 2>/dev/null || true)

if [[ "$checked" -eq 0 ]]; then
    printf 'check_license_headers: no tracked Rust sources to check.\n'
    exit 0
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Prepend the standard header (licence block first, then `//!` module docs):

    // Copyright 2026 RustFS Team
    //
    // Licensed under the Apache License, Version 2.0 (the "License");
    // you may not use this file except in compliance with the License.
    // You may obtain a copy of the License at
    //
    //     http://www.apache.org/licenses/LICENSE-2.0
    //
    // Unless required by applicable law or agreed to in writing, software
    // distributed under the License is distributed on an "AS IS" BASIS,
    // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    // See the License for the specific language governing permissions and
    // limitations under the License.

If the file came from elsewhere, resolve its provenance before merging — see
docs/adr/0001-licensing-and-provenance-boundary.md.
EOF
fi

exit "$status"
