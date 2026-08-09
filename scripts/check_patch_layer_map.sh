#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_patch_layer_map.sh
#
# WHAT THIS CHECKS
#   That the landing table in docs/middleware.md and the tests in
#   crates/gateway/tests/patch_layer_landings.rs name the SAME SET, in both
#   directions:
#
#   1. The table has exactly EXPECTED_ROWS rows (nine, one per RustFS tower
#      patch layer). A row that quietly disappears is a layer nobody has to
#      account for any more.
#   2. Every test name in the table's last column exists as a test function in
#      the landings file. A row pointing at a renamed test is a claim with
#      nothing behind it.
#   3. Every test function in the landings file appears in the table. A test
#      with no row is a landing nobody wrote down, and `P10-06` reads the table.
#
# WHY
#   The claim this project makes about its own value is "six of RustFS's nine
#   tower patch layers disappear, two become a StageFilter and one becomes an
#   OpLayer". That claim is either a machine-checkable list or it is marketing.
#   The table is the acceptance list for deleting those nine layers from the
#   RustFS tree, and without this guard the way it fails is silent: a test gets
#   renamed in a refactor, the row keeps saying what it said, and the deletion
#   goes ahead against a guarantee that stopped existing.
#
# HOW TO EXEMPT
#   Not applicable. A tenth landing means a tenth row and a tenth test; a layer
#   that turns out not to need a landing is a row that says so, not a row that
#   is deleted.
#
# USAGE
#   scripts/check_patch_layer_map.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_patch_layer_map.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

cd "$ROOT_DIR"

DOC_FILE='docs/middleware.md'
TEST_FILE='crates/gateway/tests/patch_layer_landings.rs'
# The nine tower layers in `rustfs/src/server/layer.rs`. The count is pinned
# because a table that lost a row would otherwise still be self-consistent.
EXPECTED_ROWS=9

status=0

report() {
    printf '%s\n' "$1" >&2
    status=1
}

for file in "$DOC_FILE" "$TEST_FILE"; do
    if [[ ! -f "$file" ]]; then
        report "check_patch_layer_map: ${file} does not exist; this guard's input is missing, which is a failure and not a skip"
        exit 1
    fi
done

# -----------------------------------------------------------------------------
# The table's rows. A landing row is a Markdown table row whose first cell is a
# bare number — the layer's index — which is what distinguishes it from the
# decision tree earlier in the same document.
# -----------------------------------------------------------------------------
rows="$(awk -F'|' '
    {
        line = $0
        if (line !~ /^\|/) { next }
        first = $2
        gsub(/[ \t]/, "", first)
        if (first !~ /^[0-9]+$/) { next }
        last = $(NF - 1)
        gsub(/[ \t`]/, "", last)
        print first "\t" last
    }
' "$DOC_FILE")"

row_count="$(printf '%s' "$rows" | grep -c . || true)"
if [[ "$row_count" -ne "$EXPECTED_ROWS" ]]; then
    report "${DOC_FILE}: the landing table has ${row_count} numbered row(s) and must have ${EXPECTED_ROWS}, one per RustFS tower patch layer"
fi

table_tests="$(printf '%s\n' "$rows" | cut -f2 | grep -E '^[a-z_][a-z0-9_]*$' | sort -u)"
if [[ -z "$table_tests" ]]; then
    report "${DOC_FILE}: no test name was read out of the landing table's last column; the guard is checking nothing"
    exit 1
fi

# -----------------------------------------------------------------------------
# The landings file's tests: a `fn name(` preceded by a test attribute.
# -----------------------------------------------------------------------------
file_tests="$(awk '
    /^#\[(tokio::)?test\]/ { pending = 1; next }
    pending == 1 {
        line = $0
        if (match(line, /fn[ \t]+[a-z_][a-z0-9_]*/)) {
            name = substr(line, RSTART + 3, RLENGTH - 3)
            gsub(/[ \t]/, "", name)
            print name
            pending = 0
        }
        next
    }
' "$TEST_FILE" | sort -u)"

if [[ -z "$file_tests" ]]; then
    report "${TEST_FILE}: no test function was found; the guard is checking nothing"
    exit 1
fi

# -----------------------------------------------------------------------------
# Both directions.
# -----------------------------------------------------------------------------
while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if ! printf '%s\n' "$file_tests" | grep -qx -- "$name"; then
        report "${DOC_FILE}: the landing table names '${name}', which is not a test in ${TEST_FILE}; the row is a claim with nothing behind it"
    fi
done <<<"$table_tests"

while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if ! printf '%s\n' "$table_tests" | grep -qx -- "$name"; then
        report "${TEST_FILE}: '${name}' has no row in the ${DOC_FILE} landing table; P10-06 reads the table, so a landing that is not in it is one nobody will account for"
    fi
done <<<"$file_tests"

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Patch-layer landing map is out of step. See rustfs/backlog#1731 (P6-01) and docs/middleware.md.
The table is the acceptance list for deleting RustFS's nine tower patch layers. It is only worth
anything while every row points at a test that exists and every test has a row.
EOF
    exit "$status"
fi

mapped="$(printf '%s\n' "$table_tests" | grep -c . || true)"
printf 'OK: %s/%s patch layers mapped, 0 orphan rows, 0 orphan tests\n' "$mapped" "$EXPECTED_ROWS"
exit 0
