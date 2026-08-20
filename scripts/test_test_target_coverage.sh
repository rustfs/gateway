#!/usr/bin/env bash
set -euo pipefail

# Deterministic mutations for check_test_target_coverage.sh (rustfs/gateway#277).
#
# The sandbox is a skeleton of the real workspace: the root manifest, every member's Cargo.toml,
# and every member's tests/ tree recreated as empty files. The guard reads manifests and directory
# listings and never reads a test's contents, so the skeleton is a faithful subject and each case
# costs milliseconds. A mutation edits the skeleton — or the guard's own tables, which is the only
# way to prove that deleting an exception row goes red.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GUARD=scripts/check_test_target_coverage.sh
SANDBOX=""
cases=0
failures=0

cleanup() {
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX"
    fi
}
trap cleanup EXIT

initialize_sandbox() {
    SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/gateway-coverage-guard.XXXXXX")"
    mkdir -p "$SANDBOX/scripts"
    cp "$REPO_ROOT/$GUARD" "$SANDBOX/scripts/"
    cp "$REPO_ROOT/Cargo.toml" "$SANDBOX/Cargo.toml"
    # Every consolidation guard the coverage table points at, so a row that names a guard which
    # does not exist can be told apart from one whose guard stopped naming its crate.
    for guard in check_test_target_consolidation.sh check_sig_test_target_consolidation.sh \
        check_xtask_test_target_consolidation.sh; do
        cp "$REPO_ROOT/scripts/$guard" "$SANDBOX/scripts/"
    done
    # The member set comes from the real tree rather than a list here: hard-coding it would
    # reproduce inside the self-test the very defect the guard exists to remove.
    while IFS= read -r manifest; do
        member="$(dirname "${manifest#"$REPO_ROOT"/}")"
        mkdir -p "$SANDBOX/$member"
        cp "$manifest" "$SANDBOX/$member/Cargo.toml"
        if [[ -d "$REPO_ROOT/$member/tests" ]]; then
            (cd "$REPO_ROOT/$member/tests" && find . -type d -print0) |
                (cd "$SANDBOX/$member" && mkdir -p tests && xargs -0 -I{} mkdir -p "tests/{}")
            (cd "$REPO_ROOT/$member/tests" && find . -type f -name '*.rs' -print0) |
                (cd "$SANDBOX/$member/tests" && xargs -0 -I{} touch "{}")
        fi
    done < <(find "$REPO_ROOT/crates" "$REPO_ROOT/spikes" "$REPO_ROOT/xtask" \
        -mindepth 1 -maxdepth 2 -name Cargo.toml -print 2>/dev/null | sort)
    git -C "$SANDBOX" init -q
    git -C "$SANDBOX" add -A
    git -C "$SANDBOX" \
        -c user.name='Coverage Guard' \
        -c user.email='coverage-guard@example.invalid' \
        -c commit.gpgsign=false \
        commit -qm baseline
}

reset_sandbox() {
    if [[ -z "$SANDBOX" ]]; then
        initialize_sandbox
        return
    fi
    git -C "$SANDBOX" reset --hard -q HEAD
    git -C "$SANDBOX" clean -fdq
}

run_guard_in_sandbox() {
    local rc=0
    GATEWAY_CHECK_ROOT="$SANDBOX" bash "$SANDBOX/$GUARD" >/dev/null 2>&1 || rc=$?
    printf '%s\n' "$rc"
}

expect_fail() {
    local description="$1" mutation="$2" rc
    cases=$((cases + 1))
    reset_sandbox
    (cd "$SANDBOX" && "$mutation")
    rc="$(run_guard_in_sandbox)"
    reset_sandbox
    if [[ "$rc" -ne 0 ]]; then
        printf '  ok   %s\n' "$description"
    else
        printf '  FAIL %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

# The other direction. A sandbox that could not go green after a revert would make every
# expect_fail above meaningless, because a permanently-red subject fails every mutation.
expect_pass() {
    local description="$1" mutation="$2" rc
    cases=$((cases + 1))
    reset_sandbox
    (cd "$SANDBOX" && "$mutation")
    rc="$(run_guard_in_sandbox)"
    reset_sandbox
    if [[ "$rc" -eq 0 ]]; then
        printf '  ok   %s\n' "$description"
    else
        printf '  FAIL %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

edit_guard() {
    python3 - "$1" "$2" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path("scripts/check_test_target_coverage.sh")
text = path.read_text()
old, new = sys.argv[1:]
if old not in text:
    raise SystemExit(f"missing mutation subject: {old}")
path.write_text(text.replace(old, new, 1))
PYEOF
}

printf 'check_test_target_coverage mutations\n'

if ! bash "$REPO_ROOT/$GUARD" >/dev/null; then
    printf '%s\n' 'test-target coverage positive control failed on the real tree' >&2
    exit 1
fi

initialize_sandbox
if [[ "$(run_guard_in_sandbox)" -ne 0 ]]; then
    printf '%s\n' 'the sandbox skeleton is not a faithful subject: the guard fails on it unmutated' >&2
    GATEWAY_CHECK_ROOT="$SANDBOX" bash "$SANDBOX/$GUARD" >&2 || true
    exit 1
fi
printf '  ok   the unmutated sandbox skeleton passes\n'
cases=$((cases + 1))

# --------------------------------------------------------------------------------------------
# The hole this guard closes: a member arrives with tests and nobody adds it to anything.
# --------------------------------------------------------------------------------------------
mut_new_member_ships_tests_unlisted() {
    mkdir -p crates/latecomer/tests
    printf '[package]\nname = "rustfs-gateway-latecomer"\nversion = "0.0.0"\nedition = "2024"\n' \
        >crates/latecomer/Cargo.toml
    touch crates/latecomer/tests/smoke.rs
}
expect_fail 'a new member shipping tests and named by no table is rejected' \
    mut_new_member_ships_tests_unlisted

# The same member, consolidated but still unlisted, must also be rejected: being in the right
# shape is not the same as being held there, and only a table row names the guard that holds it.
mut_new_member_consolidated_but_unlisted() {
    mkdir -p crates/latecomer/tests
    printf '[package]\nname = "rustfs-gateway-latecomer"\nversion = "0.0.0"\nedition = "2024"\nautotests = false\n\n[[test]]\nname = "integration"\npath = "tests/integration.rs"\n' \
        >crates/latecomer/Cargo.toml
    touch crates/latecomer/tests/integration.rs
}
expect_fail 'a new member consolidated but named by no table is rejected' \
    mut_new_member_consolidated_but_unlisted

# --------------------------------------------------------------------------------------------
# Exception rows are debt records, and every way one can become a lie.
# --------------------------------------------------------------------------------------------
mut_exception_row_deleted() {
    edit_guard '    "crates/http": (
        13,' '    "crates/httpx": (
        13,'
}
expect_fail 'deleting the exception row for an unconsolidated crate is rejected' \
    mut_exception_row_deleted

mut_exception_count_outgrown() {
    touch crates/http/tests/fourteenth_loose_file.rs
}
expect_fail 'a fourteenth loose test file in an excepted crate is rejected' \
    mut_exception_count_outgrown

mut_exception_stale_after_consolidation() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/http/Cargo.toml")
text = path.read_text()
text = text.replace('[package]\n', '[package]\nautotests = false\n', 1)
path.write_text(text + '\n[[test]]\nname = "integration"\npath = "tests/integration.rs"\n')
PYEOF
}
expect_fail 'an exception row left behind after the crate is consolidated is rejected' \
    mut_exception_stale_after_consolidation

mut_exception_reason_is_a_placeholder() {
    edit_guard '"one target; consolidating a single source buys nothing until a second one is added",' \
        '"TODO",'
}
expect_fail 'an exception row whose reason is a placeholder is rejected' \
    mut_exception_reason_is_a_placeholder

mut_exception_loses_its_tracking_issue() {
    edit_guard '        3,
        "rustfs/gateway#277",' '        3,
        "later",'
}
expect_fail 'an exception row with no tracking issue is rejected' \
    mut_exception_loses_its_tracking_issue

# --------------------------------------------------------------------------------------------
# Covered rows are claims about another guard, and a claim that stops being true must say so.
# --------------------------------------------------------------------------------------------
mut_covered_crate_loses_its_consolidated_shape() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/sig/Cargo.toml")
path.write_text(path.read_text().replace("autotests = false\n", "", 1))
PYEOF
}
expect_fail 'a covered crate that stops setting autotests = false is rejected' \
    mut_covered_crate_loses_its_consolidated_shape

mut_covered_guard_deleted() {
    rm scripts/check_sig_test_target_consolidation.sh
}
expect_fail 'a covered row naming a guard that no longer exists is rejected' mut_covered_guard_deleted

mut_covered_guard_stops_naming_its_crate() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/check_sig_test_target_consolidation.sh")
path.write_text(path.read_text().replace("crates/sig", "crates/somewhere-else", 1))
PYEOF
}
expect_fail 'a covered row whose guard no longer names the crate is rejected' \
    mut_covered_guard_stops_naming_its_crate

# --------------------------------------------------------------------------------------------
# Table rows that describe nothing, and inputs that are missing rather than clean.
# --------------------------------------------------------------------------------------------
# These two add a row rather than renaming one. Renaming `crates/types` to `crates/xml` would
# also leave `crates/types` unlisted, and the unlisted check runs first — the case would go red
# without the dead-row branch ever being reached, and that branch would be untested while looking
# covered. Adding a row leaves every real member listed, so only the dead-row branch can fire.
mut_row_names_a_member_without_tests() {
    edit_guard '    "crates/types": (' '    "crates/xml": (
        1,
        "rustfs/gateway#277",
        "a row for a member that ships no integration tests at all",
    ),
    "crates/types": ('
}
expect_fail 'a table row naming a member that ships no tests is rejected' \
    mut_row_names_a_member_without_tests

mut_row_names_something_that_is_not_a_member() {
    edit_guard '    "crates/macros": (' '    "crates/imaginary": (
        1,
        "rustfs/gateway#277",
        "a row for a directory that is not a workspace member",
    ),
    "crates/macros": ('
}
expect_fail 'a table row naming a directory that is not a workspace member is rejected' \
    mut_row_names_something_that_is_not_a_member

mut_member_is_both_covered_and_excepted() {
    edit_guard '    "crates/sig": "check_sig_test_target_consolidation.sh",' \
        '    "crates/sig": "check_sig_test_target_consolidation.sh",
    "crates/http": "check_sig_test_target_consolidation.sh",'
}
expect_fail 'a member listed in both tables at once is rejected' mut_member_is_both_covered_and_excepted

mut_workspace_manifest_missing() {
    rm Cargo.toml
}
expect_fail 'a missing workspace manifest fails closed rather than passing with nothing to check' \
    mut_workspace_manifest_missing

# --------------------------------------------------------------------------------------------
# Green in the other direction: legitimate movement must not be rejected, or the guard becomes a
# reason to route around it.
# --------------------------------------------------------------------------------------------
mut_excepted_crate_sheds_a_target_and_updates_its_row() {
    rm crates/server/tests/tls_h2.rs
    edit_guard '    "crates/server": (
        6,' '    "crates/server": (
        5,'
}
expect_pass 'an excepted crate that sheds a target and updates its row is accepted' \
    mut_excepted_crate_sheds_a_target_and_updates_its_row

mut_member_without_tests_needs_no_row() {
    mkdir -p crates/quiet/src
    printf '[package]\nname = "rustfs-gateway-quiet"\nversion = "0.0.0"\nedition = "2024"\n' \
        >crates/quiet/Cargo.toml
    touch crates/quiet/src/lib.rs
}
expect_pass 'a new member that ships no integration tests needs no row' \
    mut_member_without_tests_needs_no_row

printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
if [[ "$failures" -ne 0 ]]; then
    exit 1
fi
