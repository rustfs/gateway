#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test_sig_case_coverage.sh
#
# WHAT THIS CHECKS
#   That the P2-02 and P2-05 additions to check_sig_case_coverage.sh fail for missing or
#   weakened acceptance evidence. Each mutation runs in a throwaway repository
#   copy; the working tree is never modified.
#
# WHY
#   rustfs/backlog#1679 and rustfs/backlog#1685 add signature-proof case sets. Their guard must
#   fail when the case count, polarity, harness, serde evidence, proof controls,
#   executable guard mappings, or deployment guidance changes.
#
# HOW TO EXEMPT
#   Not applicable. Replace a mutation only with equivalent negative evidence.
#
# USAGE
#   scripts/test_sig_case_coverage.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

failures=0
cases=0
SANDBOX=""

pass_msg() { printf '  ok   %s\n' "$*"; }
fail_msg() {
    printf '  FAIL %s\n' "$*" >&2
    failures=$((failures + 1))
}

make_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        local changed untracked
        changed="$(mktemp "${TMPDIR:-/tmp}/gateway-sig-guard-changed.XXXXXX")"
        untracked="$(mktemp "${TMPDIR:-/tmp}/gateway-sig-guard-untracked.XXXXXX")"
        (
            cd "$SANDBOX"
            git diff --name-only -z HEAD -- >"$changed"
            if [[ -s "$changed" ]]; then
                xargs -0 git reset -q HEAD -- <"$changed" >/dev/null 2>&1
            fi
            git ls-files --others --exclude-standard -z >"$untracked"
            if [[ -s "$untracked" ]]; then
                xargs -0 git clean -fdq -- <"$untracked" >/dev/null 2>&1
            fi
            git diff --name-only -z HEAD -- >"$changed"
            if [[ -s "$changed" ]]; then
                xargs -0 git checkout -f HEAD -- <"$changed" >/dev/null 2>&1
            fi
        )
        rm -f "$changed" "$untracked"
        return
    fi

    local dir list archive
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-sig-guard-test.XXXXXX")"
    list="${dir}.files"
    archive="${dir}.tar"
    if ! (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && tar -xf "$archive"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! rm -f "$list" "$archive"; then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git init -q .); then
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git add -A >/dev/null 2>&1); then
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then
        rm -rf "$dir" || true
        return 1
    fi
    SANDBOX="$dir"
}

cleanup_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX"
    fi
    return 0
}
trap cleanup_sandbox EXIT

expect_fail() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    (cd "$sandbox" && git add -A >/dev/null 2>&1)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}

expect_fail_self_mutation() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    (cd "$sandbox" && git add -A >/dev/null 2>&1)
    GATEWAY_CHECK_ROOT="$sandbox" "$sandbox/scripts/$guard" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches its own mutation: ${desc}"
    else
        fail_msg "${guard} did NOT catch its own mutation: ${desc}"
    fi
}

printf 'Positive control (signature case coverage must be clean)\n'
cases=$((cases + 1))
positive_control_output=""
if positive_control_output="$("${SCRIPT_DIR}/check_sig_case_coverage.sh" 2>&1)"; then
    pass_msg 'check_sig_case_coverage.sh'
else
    # This exit aborts the whole worker that called this suite, so the guard's own
    # message is the only evidence anyone downstream will have. Print it.
    fail_msg 'check_sig_case_coverage.sh fails on the current tree'
    printf '%s\n' "$positive_control_output" | sed 's/^/       /' >&2
    exit 1
fi

printf '\nNegative cases (signature coverage guard must fail)\n'

mut_sig_verification_mapping_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
line = "    'c-sig-0128|negative|crates/gateway/tests/credential_runtime.rs|fn c_sig_0128_request_logs_exclude_credential_material'\n"
if line not in text:
    raise SystemExit("missing P2-02 mapping mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'one of the 28 P2-02 acceptance mappings being deleted' mut_sig_verification_mapping_deleted

mut_sig_verification_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "c-sig-0106|positive|"
if old not in text:
    raise SystemExit("missing P2-02 polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0106|negative|", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'the required 6 positive and 22 negative P2-02 split changing' mut_sig_verification_polarity_changed

mut_sig_verification_harness_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = "#[test]\nfn p2_02_compile_time_boundaries_are_not_openable()"
new = "#[cfg(\n    any()\n)]\n#[test]\nfn p2_02_compile_time_boundaries_are_not_openable()"
if old not in text:
    raise SystemExit("missing P2-02 harness mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled P2-02 trybuild harness being counted as active' \
    mut_sig_verification_harness_disabled

mut_sig_secret_serde_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_0123_*.rs")'
if old not in text:
    raise SystemExit("missing c-sig-0123 harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the core harness no longer executing c-sig-0123' mut_sig_secret_serde_glob_removed

mut_sig_secret_serde_evidence_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0123_secret_bytes_serialize.rs")
text = path.read_text()
old = "    let _ = serde_json::to_string(&secret);"
new = "    #[cfg(\n        any()\n    )]\n    let _ = serde_json::to_string(&secret);"
if old not in text:
    raise SystemExit("missing c-sig-0123 evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0123 evidence being disabled at its statement boundary' mut_sig_secret_serde_evidence_disabled

mut_sig_proof_clone_control_removed() {
    rm crates/sig/tests/compile_fail/p2_02_signature_match_cannot_clone.rs
}
expect_fail check_sig_case_coverage.sh \
    'the SignatureMatch no-Clone control being deleted' mut_sig_proof_clone_control_removed

mut_sig_verification_guard_function_renamed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = "mut_c_sig_0126_derived_signature() {"
if old not in text:
    raise SystemExit("missing c-sig-0126 mutation subject")
path.write_text(text.replace(old, "renamed_c_sig_0126_derived_signature() {", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0126 losing its executable guard mutation' mut_sig_verification_guard_function_renamed

mut_sig_readme_debug_warning_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("README.md")
text = path.read_text()
old = "Never run a debug build of `rustfs-gateway-sig` in production"
if old not in text:
    raise SystemExit("missing README warning mutation subject")
path.write_text(text.replace(old, "Debug builds are acceptable in production", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the production debug-build warning being weakened' mut_sig_readme_debug_warning_removed

mut_sig_security_model_t1_statement_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("docs/security-model.md")
text = path.read_text()
old = "known key with a wrong signature answers `SignatureDoesNotMatch`"
if old not in text:
    raise SystemExit("missing security-model T1 mutation subject")
path.write_text(text.replace(old, "known key returns the same code", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the security model losing the T1 error-code distinction' mut_sig_security_model_t1_statement_removed

mut_sig_log_capture_replaced_by_formatting_proxy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/credential_runtime.rs")
text = path.read_text()
old = "    let clean = run_log_capture_child(false);"
new = '    let clean = std::process::Command::new("true").output().expect("proxy");'
if old not in text:
    raise SystemExit("missing c-sig-0128 request-capture mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0128 replacing the real request-path capture with a formatting proxy' \
    mut_sig_log_capture_replaced_by_formatting_proxy

mut_sig_log_capture_poison_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/credential_runtime.rs")
text = path.read_text()
old = 'eprintln!("Authorization: capture-control-without-credential-material");'
if old not in text:
    raise SystemExit("missing c-sig-0128 poison mutation subject")
path.write_text(text.replace(old, 'eprintln!("poison removed");', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0128 losing the observable poison direction' mut_sig_log_capture_poison_removed

mut_sig_p2_05_manifest_removed() {
    rm scripts/sig-case-coverage-p2-05.txt
}
expect_fail check_sig_case_coverage.sh \
    'the P2-05 acceptance manifest being removed' mut_sig_p2_05_manifest_removed

mut_sig_p2_05_mapping_deleted() {
    sed -i.bak '/^c-sig-0432|/d' scripts/sig-case-coverage-p2-05.txt
}
expect_fail check_sig_case_coverage.sh \
    'one of the sixteen P2-05 mappings being deleted' mut_sig_p2_05_mapping_deleted

mut_sig_p2_05_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-05.txt")
text = path.read_text()
old = "c-sig-0417|positive|"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0417|negative|", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-05 positive and negative split changing' mut_sig_p2_05_polarity_changed

mut_sig_p2_05_evidence_reused() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/sig-case-coverage-p2-05.txt")
text = path.read_text()
old = "fn c_sig_0418_case_only_duplicate_fields_are_rejected"
new = "fn c_sig_0417_valid_policy_produces_a_proof_and_final_receipt"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 evidence-reuse mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'two P2-05 cases reusing one named test' mut_sig_p2_05_evidence_reused

mut_sig_p2_05_nested_test_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/src/post_policy.rs")
text = path.read_text()
old = "#[test]\n    fn c_sig_0418_case_only_duplicate_fields_are_rejected()"
new = "#[cfg(any())]\n    #[test]\n    fn c_sig_0418_case_only_duplicate_fields_are_rejected()"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 nested-test mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a P2-05 nested test being disabled by cfg' mut_sig_p2_05_nested_test_disabled

mut_sig_p2_05_test_module_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/src/post_policy.rs")
text = path.read_text()
old = "#[cfg(test)]\nmod tests {"
new = "#[cfg(any())]\nmod tests {"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 test-module mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the P2-05 test module being disabled by cfg' mut_sig_p2_05_test_module_disabled

mut_sig_p2_05_primary_assertion_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/src/post_policy.rs")
text = path.read_text()
old = "assert!(policy.verify(&key).is_ok());"
new = "assert!(policy.final_key().starts_with(\"uploads/\"));"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 primary-assertion mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0417 losing its signature-proof assertion' mut_sig_p2_05_primary_assertion_removed

mut_sig_p2_05_second_size_direction_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/src/post_policy.rs")
text = path.read_text()
old = "Some(PostPolicyError::EntityTooLarge)"
if text.count(old) != 1:
    raise SystemExit("missing P2-05 upper-size mutation subject")
path.write_text(text.replace(old, "Some(PostPolicyError::EntityTooSmall)", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0427 losing the upper size-bound direction' mut_sig_p2_05_second_size_direction_removed

mut_sig_0429_test_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/pipeline.rs")
text = path.read_text()
old = "#[tokio::test]\nasync fn c_sig_0429_presigned_body_matching_its_signed_digest_is_accepted()"
new = "#[cfg(any())]\n#[tokio::test]\nasync fn c_sig_0429_presigned_body_matching_its_signed_digest_is_accepted()"
if text.count(old) != 1:
    raise SystemExit("missing c-sig-0429 active-test mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0429 being disabled by cfg' mut_sig_0429_test_disabled

mutate_p2_05_pipeline_test() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
from pathlib import Path
import sys

name, old, new = sys.argv[1:]
path = Path("crates/gateway/tests/pipeline.rs")
text = path.read_text()
start = text.find(f"async fn {name}()")
if start == -1:
    raise SystemExit(f"missing P2-05 pipeline test {name}")
end = text.find("\n///", start)
if end == -1:
    end = len(text)
body = text[start:end]
if body.count(old) != 1:
    raise SystemExit(f"missing unique P2-05 mutation subject in {name}: {old}")
path.write_text(text[:start] + body.replace(old, new, 1) + text[end:])
PYEOF
}

mut_sig_0429_status_removed() {
    mutate_p2_05_pipeline_test c_sig_0429_presigned_body_matching_its_signed_digest_is_accepted \
        'http::StatusCode::OK' 'http::StatusCode::CREATED'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0429 losing its accepted-status assertion' mut_sig_0429_status_removed

mut_sig_0429_handler_count_removed() {
    mutate_p2_05_pipeline_test c_sig_0429_presigned_body_matching_its_signed_digest_is_accepted \
        'reached.load(Ordering::SeqCst), 1' 'reached.load(Ordering::SeqCst), 0'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0429 losing its one-handler assertion' mut_sig_0429_handler_count_removed

mut_sig_0430_status_removed() {
    mutate_p2_05_pipeline_test c_sig_0430_tampered_presigned_body_is_refused_before_the_handler \
        'http::StatusCode::BAD_REQUEST' 'http::StatusCode::FORBIDDEN'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0430 losing its mismatch-status assertion' mut_sig_0430_status_removed

mut_sig_0430_zero_commit_removed() {
    mutate_p2_05_pipeline_test c_sig_0430_tampered_presigned_body_is_refused_before_the_handler \
        'reached.load(Ordering::SeqCst), 0' 'reached.load(Ordering::SeqCst), 1'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0430 losing its zero-handler assertion' mut_sig_0430_zero_commit_removed

mut_sig_0431_status_removed() {
    mutate_p2_05_pipeline_test c_sig_0431_missing_presigned_body_is_refused_before_the_handler \
        'http::StatusCode::BAD_REQUEST' 'http::StatusCode::FORBIDDEN'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0431 losing its missing-body status assertion' mut_sig_0431_status_removed

mut_sig_0431_zero_commit_removed() {
    mutate_p2_05_pipeline_test c_sig_0431_missing_presigned_body_is_refused_before_the_handler \
        'reached.load(Ordering::SeqCst), 0' 'reached.load(Ordering::SeqCst), 1'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0431 losing its zero-handler assertion' mut_sig_0431_zero_commit_removed

mut_sig_0432_status_removed() {
    mutate_p2_05_pipeline_test c_sig_0432_streaming_presigned_body_is_not_implemented \
        'http::StatusCode::NOT_IMPLEMENTED' 'http::StatusCode::BAD_REQUEST'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0432 losing its unsupported-status assertion' mut_sig_0432_status_removed

mut_sig_0432_zero_commit_removed() {
    mutate_p2_05_pipeline_test c_sig_0432_streaming_presigned_body_is_not_implemented \
        'reached.load(Ordering::SeqCst), 0' 'reached.load(Ordering::SeqCst), 1'
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0432 losing its zero-handler assertion' mut_sig_0432_zero_commit_removed

printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
