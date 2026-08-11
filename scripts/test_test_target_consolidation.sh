#!/usr/bin/env bash
set -euo pipefail

# Deterministic mutations for check_test_target_consolidation.sh. This stays separate from the
# legacy aggregate guard self-test so the target-consolidation contract remains below 800 lines.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SANDBOX=""
cases=0
failures=0

cleanup() {
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX"
    fi
}
trap cleanup EXIT

reset_sandbox() {
    cleanup
    SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/gateway-target-guard.XXXXXX")"
    mkdir -p "$SANDBOX/scripts" "$SANDBOX/crates/core" "$SANDBOX/crates/gateway"
    cp "$REPO_ROOT/scripts/check_test_target_consolidation.sh" "$SANDBOX/scripts/"
    cp "$REPO_ROOT/crates/core/Cargo.toml" "$SANDBOX/crates/core/"
    cp "$REPO_ROOT/crates/gateway/Cargo.toml" "$SANDBOX/crates/gateway/"
    cp -R "$REPO_ROOT/crates/core/tests" "$SANDBOX/crates/core/"
    cp -R "$REPO_ROOT/crates/gateway/tests" "$SANDBOX/crates/gateway/"
}

expect_fail() {
    local description="$1" mutation="$2"
    local rc=0
    cases=$((cases + 1))
    reset_sandbox
    (cd "$SANDBOX" && "$mutation")
    GATEWAY_CHECK_ROOT="$SANDBOX" bash "$SANDBOX/scripts/check_test_target_consolidation.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        printf '  ok   %s\n' "$description"
    else
        printf '  FAIL %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

expect_pass() {
    local description="$1" mutation="$2"
    cases=$((cases + 1))
    reset_sandbox
    (cd "$SANDBOX" && "$mutation")
    if GATEWAY_CHECK_ROOT="$SANDBOX" bash "$SANDBOX/scripts/check_test_target_consolidation.sh" \
        >/dev/null 2>&1; then
        printf '  ok   %s\n' "$description"
    else
        printf '  FAIL %s\n' "$description" >&2
        failures=$((failures + 1))
    fi
}

if ! bash "$REPO_ROOT/scripts/check_test_target_consolidation.sh" >/dev/null; then
    printf '%s\n' 'target-consolidation positive control failed' >&2
    exit 1
fi

mut_core_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "acl_contract.rs"]\nmod acl_contract;\n', '', 1))
PYEOF
}
expect_fail 'core harness omission is rejected' mut_core_registration_omitted

mut_core_registration_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/integration.rs")
text = path.read_text()
entry = '#[path = "acl_contract.rs"]\nmod acl_contract;\n'
path.write_text(text.replace(entry, entry + entry, 1))
PYEOF
}
expect_fail 'core harness duplicate is rejected' mut_core_registration_duplicated

mut_core_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail 'restoring core implicit test discovery is rejected' mut_core_autotests_restored

mut_core_source_unregistered() {
    cp crates/core/tests/acl_contract.rs crates/core/tests/unregistered_contract.rs
}
expect_fail 'an unregistered core test source is rejected' mut_core_source_unregistered

mut_core_source_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/acl_contract.rs")
path.write_text("#![cfg(any())]\n" + path.read_text())
PYEOF
}
expect_fail 'a registered core source disabled by file-level cfg is rejected' mut_core_source_disabled_by_cfg

mut_core_source_disabled_by_cfg_attr() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/acl_contract.rs")
path.write_text("#![cfg_attr(all(), cfg(any()))]\n" + path.read_text())
PYEOF
}
expect_fail 'a registered core source disabled by file-level cfg_attr is rejected' mut_core_source_disabled_by_cfg_attr

mut_core_source_symlink_alias() {
    rm crates/core/tests/acl_contract.rs
    ln -s authz_consumption.rs crates/core/tests/acl_contract.rs
}
expect_fail 'a registered core source symlink alias is rejected' mut_core_source_symlink_alias

mut_core_second_trybuild_batch() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
needle = "    let cases = trybuild::TestCases::new();\n"
path.write_text(text.replace(needle, needle + "    let duplicate = trybuild::TestCases::new();\n", 1))
PYEOF
}
expect_fail 'a second core TestCases batch is rejected' mut_core_second_trybuild_batch

mut_core_error_resolution_pair_is_registered() {
    cp crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs \
        crates/core/tests/compile_fail/error_resolution_probe.rs
    cp crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr \
        crates/core/tests/compile_fail/error_resolution_probe.stderr
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
needle = '    cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");\n'
path.write_text(text.replace(needle, needle + '    cases.compile_fail("tests/compile_fail/error_resolution_*.rs");\n', 1))
PYEOF
}
expect_pass 'a paired core error-resolution fixture is registered in the shared batch' mut_core_error_resolution_pair_is_registered

mut_core_error_resolution_pattern_omitted() {
    cp crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs \
        crates/core/tests/compile_fail/error_resolution_probe.rs
    cp crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr \
        crates/core/tests/compile_fail/error_resolution_probe.stderr
}
expect_fail 'an existing core error-resolution pair cannot lose its harness pattern' mut_core_error_resolution_pattern_omitted

mut_core_error_resolution_pair_incomplete() {
    cp crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs \
        crates/core/tests/compile_fail/error_resolution_probe.rs
}
expect_fail 'an unpaired core error-resolution fixture is rejected fail-closed' mut_core_error_resolution_pair_incomplete

mut_core_golden_restore_uses_legacy_target() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/golden.rs")
text = path.read_text()
old = "--test integration golden::the_rendered_route_table_matches_the_golden -- --exact"
path.write_text(text.replace(old, "--test golden", 1))
PYEOF
}
expect_fail 'the route golden restore command returning to a removed target is rejected' mut_core_golden_restore_uses_legacy_target

mut_gateway_pattern_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
path.write_text(text.replace('    cases.compile_fail("tests/compile_fail/azc_*.rs");\n', '', 1))
PYEOF
}
expect_fail 'gateway trybuild pattern omission is rejected' mut_gateway_pattern_omitted

mut_gateway_batch_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
needle = "    let cases = trybuild::TestCases::new();\n"
path.write_text(text.replace(needle, needle + "    let duplicate = trybuild::TestCases::new();\n", 1))
PYEOF
}
expect_fail 'a second gateway TestCases batch is rejected' mut_gateway_batch_duplicated

mut_gateway_extra_trybuild_entry() {
    cat >crates/gateway/tests/duplicate_trybuild.rs <<'RSEOF'
#[test]
fn duplicate_trybuild() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/azc_*.rs");
}
RSEOF
}
expect_fail 'an extra gateway trybuild entry is rejected' mut_gateway_extra_trybuild_entry

mut_gateway_path_reuses_harness() {
    printf '\n#[path = "compile_fail.rs"]\nmod duplicate_compile_fail;\n' >>crates/gateway/tests/facade_probe.rs
}
expect_fail 'a gateway #[path] reuse of the unified harness is rejected' mut_gateway_path_reuses_harness

mut_gateway_include_reuses_harness() {
    printf '\ninclude!("compile_fail.rs");\n' >>crates/gateway/tests/facade_probe.rs
}
expect_fail 'a gateway include reuse of the unified harness is rejected' mut_gateway_include_reuses_harness

mut_gateway_brace_include_reuses_harness() {
    printf '\ninclude! { "compile_fail.rs" }\n' >>crates/gateway/tests/facade_probe.rs
}
expect_fail 'a brace-delimited gateway include reuse is rejected' mut_gateway_brace_include_reuses_harness

mut_gateway_dynamic_include_is_fail_closed() {
    printf '\ninclude! { concat!("compile_", "fail.rs") }\n' >>crates/gateway/tests/facade_probe.rs
}
expect_fail 'a dynamic gateway include is rejected fail-closed' mut_gateway_dynamic_include_is_fail_closed

mut_gateway_symlink_reuses_harness() {
    ln -s compile_fail.rs crates/gateway/tests/duplicate_compile_fail.rs
}
expect_fail 'a gateway symlink reuse of the unified harness is rejected' mut_gateway_symlink_reuses_harness

mut_gateway_target_reuses_harness() {
    cat >>crates/gateway/Cargo.toml <<'TOMLEOF'

[[example]]
name = "duplicate-compile-fail"
path = "tests/compile_fail.rs"
test = true
TOMLEOF
}
expect_fail 'a Cargo target reuse of the unified gateway harness is rejected' mut_gateway_target_reuses_harness

mut_gateway_comment_and_string_decoys() {
    cat >>crates/gateway/tests/facade_probe.rs <<'RSEOF'

// let cases = trybuild::TestCases::new();
// #[path = "compile_fail.rs"] mod duplicate;
const TARGET_CONSOLIDATION_DECOY: &str = r#"include!("compile_fail.rs");"#;
RSEOF
}
expect_pass 'gateway trybuild, path, and include comment/string decoys stay inert' mut_gateway_comment_and_string_decoys

printf '%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
