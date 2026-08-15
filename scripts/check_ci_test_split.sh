#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Workspace tests, the official signing suite, guard mutations, target-consolidation mutations,
#   quirk-ledger mutations and TSAN run on separate CI runners, while the branch-protected Test
#   check waits for every worker. This
#   keeps the gate wall time below ten
#   minutes as coverage grows.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WORKFLOW="$ROOT/.github/workflows/ci.yml"
GUARD_SELF_TEST="$ROOT/scripts/test_guard_scripts.sh"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -f "$WORKFLOW" ]] || fail '.github/workflows/ci.yml is missing'
[[ -f "$GUARD_SELF_TEST" ]] || fail 'scripts/test_guard_scripts.sh is missing'

ruby -ryaml - "$WORKFLOW" <<'RUBY' || exit 1
workflow = YAML.load_file(ARGV.fetch(0))
jobs = workflow.fetch("jobs")

def require_equal(actual, expected, message)
  abort("ERROR: #{message}") unless actual == expected
end

abort("ERROR: workflow defaults may not override split-job failure propagation") if workflow.key?("defaults")
workflow_env_keys = [
  "CARGO_TERM_COLOR",
  "CARGO_SEMVER_CHECKS_TOOL",
  "CARGO_HACK_TOOL",
  "CARGO_LLVM_COV_TOOL",
  "CARGO_DENY_TOOL",
  "CARGO_PUBLIC_API_TOOL",
  "CARGO_FUZZ_TOOL"
]
require_equal(workflow.fetch("env", {}).keys, workflow_env_keys,
              "workflow environment may not override split-job commands")

workspace = jobs.fetch("workspace-tests")
signing_suite = jobs.fetch("signing-suite")
guard = jobs.fetch("guard-self-test")
target = jobs.fetch("target-consolidation-self-test")
quirk_ledger = jobs.fetch("quirk-ledger-self-test")
dto_compiler = jobs.fetch("dto-compiler-self-test")
build_guard = jobs.fetch("build-guard-self-test")
aggregate = jobs.fetch("test")

worker_keys = ["name", "runs-on", "timeout-minutes", "steps"]
require_equal(workspace.keys, worker_keys, "workspace-tests changed its parallel nine-minute contract")
require_equal(guard.keys, worker_keys, "guard-self-test changed its parallel nine-minute contract")
require_equal(workspace.values_at("name", "runs-on", "timeout-minutes"),
              ["Workspace tests", "ubuntu-latest", 9], "workspace-tests identity or budget changed")
require_equal(signing_suite.keys, worker_keys, "signing-suite changed its parallel four-minute contract")
require_equal(signing_suite.values_at("name", "runs-on", "timeout-minutes"),
              ["Official signing suite", "ubuntu-latest", 4], "signing-suite identity or budget changed")
require_equal(guard.values_at("name", "runs-on", "timeout-minutes"),
              ["Guard self-test", "ubuntu-latest", 9], "guard-self-test identity or budget changed")
require_equal(target.keys, worker_keys,
              "target-consolidation-self-test changed its parallel three-minute contract")
require_equal(target.values_at("name", "runs-on", "timeout-minutes"),
              ["Target consolidation self-test", "ubuntu-latest", 3],
              "target-consolidation-self-test identity or budget changed")
require_equal(quirk_ledger.keys, worker_keys,
              "quirk-ledger-self-test changed its parallel two-minute contract")
require_equal(quirk_ledger.values_at("name", "runs-on", "timeout-minutes"),
              ["Quirk ledger self-test", "ubuntu-latest", 2],
              "quirk-ledger-self-test identity or budget changed")
require_equal(dto_compiler.keys, worker_keys,
              "dto-compiler-self-test changed its parallel two-minute contract")
require_equal(dto_compiler.values_at("name", "runs-on", "timeout-minutes"),
              ["DTO compiler self-test", "ubuntu-latest", 2],
              "dto-compiler-self-test identity or budget changed")
require_equal(build_guard.keys, worker_keys,
              "build-guard-self-test changed its parallel three-minute contract")
require_equal(build_guard.values_at("name", "runs-on", "timeout-minutes"),
              ["Build guard self-test", "ubuntu-latest", 5],
              "build-guard-self-test identity or budget changed")

[workspace, guard].each do |job|
  steps = job.fetch("steps")
  require_equal(steps.length, 4, "a split worker changed its setup or command step count")
  expected_setup = [
    "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
    "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
    "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
  ]
  require_equal(steps.first(3).map { |step| step.fetch("uses") }, expected_setup,
                "a split worker setup action or pin changed")
  require_equal(steps.last.keys, ["name", "run"], "a split worker command can skip or hide failure")
end

require_equal(workspace.fetch("steps").first(3).map(&:keys), [["uses"], ["uses"], ["uses"]],
              "workspace-tests setup gained executable control")
signing_suite_steps = signing_suite.fetch("steps")
require_equal(signing_suite_steps.length, 4, "signing-suite changed its setup or command step count")
require_equal(signing_suite_steps.first(3).map { |step| step.fetch("uses") }, [
  "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
  "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
  "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
], "signing-suite setup action or pin changed")
require_equal(signing_suite_steps.first(3).map(&:keys), [["uses"], ["uses"], ["uses"]],
              "signing-suite setup gained executable control")
require_equal(signing_suite_steps.last.keys, ["name", "run"],
              "signing-suite command can skip or hide failure")
guard_steps = guard.fetch("steps")
require_equal(guard_steps.first(3).map(&:keys), [["uses", "with"], ["uses"], ["uses"]],
              "guard-self-test setup changed its parent-fetch contract")
require_equal(guard_steps.first.fetch("with"), {"fetch-depth" => 0},
              "guard-self-test cannot resolve the branch merge base")
target_steps = target.fetch("steps")
require_equal(target_steps.length, 2,
              "target-consolidation-self-test changed its setup or command step count")
require_equal(target_steps.first,
              {"uses" => "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"},
              "target-consolidation-self-test checkout action or pin changed")
require_equal(target_steps.last.keys, ["name", "run"],
              "target-consolidation-self-test command can skip or hide failure")
quirk_ledger_steps = quirk_ledger.fetch("steps")
require_equal(quirk_ledger_steps.length, 2,
              "quirk-ledger-self-test changed its setup or command step count")
require_equal(quirk_ledger_steps.first,
              {"uses" => "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"},
              "quirk-ledger-self-test checkout action or pin changed")
require_equal(quirk_ledger_steps.last.keys, ["name", "run"],
              "quirk-ledger-self-test command can skip or hide failure")
dto_compiler_steps = dto_compiler.fetch("steps")
require_equal(dto_compiler_steps.length, 4,
              "dto-compiler-self-test changed its setup or command step count")
require_equal(dto_compiler_steps.first(3).map { |step| step.fetch("uses") }, [
  "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
  "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
  "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
], "dto-compiler-self-test setup action or pin changed")
require_equal(dto_compiler_steps.first(3).map(&:keys), [["uses"], ["uses"], ["uses"]],
              "dto-compiler-self-test setup gained executable control")
require_equal(dto_compiler_steps.last.keys, ["name", "run"],
              "dto-compiler-self-test command can skip or hide failure")
build_guard_steps = build_guard.fetch("steps")
require_equal(build_guard_steps.length, 4,
              "build-guard-self-test changed its setup or command step count")
require_equal(build_guard_steps.first(3).map { |step| step.fetch("uses") }, [
  "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
  "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
  "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
], "build-guard-self-test setup action or pin changed")
require_equal(build_guard_steps.first(3).map(&:keys), [["uses"], ["uses"], ["uses"]],
              "build-guard-self-test setup gained executable control")
require_equal(build_guard_steps.last.keys, ["name", "run"],
              "build-guard-self-test command can skip or hide failure")

workspace_run = <<~'RUN'
  started="$(date +%s)"
  timeout 480s cargo test --workspace
  timeout 30s scripts/test_handlers_facade_fixture.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "workspace tests completed in ${elapsed}s"
RUN
signing_suite_run = <<~'RUN'
  timeout 90s cargo build --package xtask --bin xtask
  timeout 60s target/debug/xtask sigsuite fetch
  timeout 60s target/debug/xtask sigsuite run
RUN
guard_run = <<~'RUN'
  started="$(date +%s)"
  timeout 480s bash scripts/test_guard_scripts.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "guard mutations completed in ${elapsed}s"
RUN
target_run = <<~'RUN'
  started="$(date +%s)"
  timeout 120s bash scripts/test_test_target_consolidation.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "target consolidation self-test completed in ${elapsed}s"
RUN
quirk_ledger_run = <<~'RUN'
  started="$(date +%s)"
  timeout 60s env GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 bash scripts/test_guard_scripts.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "quirk ledger self-test completed in ${elapsed}s"
RUN
dto_compiler_run = <<~'RUN'
  started="$(date +%s)"
  timeout 90s env GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "DTO compiler self-test completed in ${elapsed}s"
RUN
build_guard_run = <<~'RUN'
  started="$(date +%s)"
  timeout 270s env GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 bash scripts/test_guard_scripts.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "build-backed guards completed in ${elapsed}s"
RUN
require_equal(workspace.fetch("steps").last.fetch("run"), workspace_run,
              "workspace-tests command changed or can hide a failure")
require_equal(signing_suite_steps.last.fetch("run"), signing_suite_run,
              "signing-suite command changed or can hide a failure")
require_equal(guard.fetch("steps").last.fetch("run"), guard_run,
              "guard-self-test command changed or can hide a failure")
require_equal(target.fetch("steps").last.fetch("run"), target_run,
              "target-consolidation-self-test command changed or can hide a failure")
require_equal(quirk_ledger.fetch("steps").last.fetch("run"), quirk_ledger_run,
              "quirk-ledger-self-test command changed or can hide a failure")
require_equal(dto_compiler.fetch("steps").last.fetch("run"), dto_compiler_run,
              "dto-compiler-self-test command changed or can hide a failure")
require_equal(build_guard.fetch("steps").last.fetch("run"), build_guard_run,
              "build-guard-self-test command changed or can hide a failure")

aggregate_keys = ["name", "needs", "if", "runs-on", "timeout-minutes", "steps"]
require_equal(aggregate.keys, aggregate_keys, "the Test job changed its dependency, failure, or budget contract")
require_equal(aggregate.values_at("name", "needs", "if", "runs-on", "timeout-minutes"),
              ["Test", ["workspace-tests", "signing-suite", "guard-self-test", "target-consolidation-self-test", "quirk-ledger-self-test", "dto-compiler-self-test", "build-guard-self-test", "gateway-tsan"], "always()", "ubuntu-latest", 1],
              "the Test job no longer aggregates all eight workers within the budget")
steps = aggregate.fetch("steps")
require_equal(steps.length, 1, "the Test job must have exactly one result-checking step")
require_equal(steps.first.keys, ["name", "env", "run"], "the Test comparison step can be skipped or hidden")
expected_env = {
  "WORKSPACE_RESULT" => "${{ needs.workspace-tests.result }}",
  "SIGNING_SUITE_RESULT" => "${{ needs.signing-suite.result }}",
  "GUARD_RESULT" => "${{ needs.guard-self-test.result }}",
  "TARGET_CONSOLIDATION_RESULT" => "${{ needs.target-consolidation-self-test.result }}",
  "QUIRK_LEDGER_RESULT" => "${{ needs.quirk-ledger-self-test.result }}",
  "DTO_COMPILER_RESULT" => "${{ needs.dto-compiler-self-test.result }}",
  "BUILD_GUARD_RESULT" => "${{ needs.build-guard-self-test.result }}",
  "TSAN_RESULT" => "${{ needs.gateway-tsan.result }}"
}
require_equal(steps.first.fetch("env"), expected_env, "the Test step does not bind all worker results")
expected_run = <<~'RUN'
  test "$WORKSPACE_RESULT" = success
  test "$SIGNING_SUITE_RESULT" = success
  test "$GUARD_RESULT" = success
  test "$TARGET_CONSOLIDATION_RESULT" = success
  test "$QUIRK_LEDGER_RESULT" = success
  test "$DTO_COMPILER_RESULT" = success
  test "$BUILD_GUARD_RESULT" = success
  test "$TSAN_RESULT" = success
RUN
require_equal(steps.first.fetch("run"), expected_run, "the Test step does not execute all comparisons")
RUBY
if grep -F 'cargo xtask verify --all' "$WORKFLOW" >/dev/null; then
    fail 'CI still serializes workspace tests and guard mutations through verify --all'
fi
if grep -E '^if "\$\{SCRIPT_DIR\}/test_test_target_consolidation\.sh"; then$' \
    "$GUARD_SELF_TEST" >/dev/null; then
    fail 'guard-self-test still serializes target-consolidation mutations'
fi
python3 - "$GUARD_SELF_TEST" <<'PY' || exit 1
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
start = text.find('if [[ "$QUIRK_LEDGER_ONLY" == 1 ]]; then')
first_case = text.find("expect_fail check_quirk_ledger.sh")
end = text.find("\nfi\n", first_case)
if start < 0 or first_case < start or end < first_case:
    raise SystemExit("ERROR: guard-self-test still serializes or omits quirk-ledger mutations")
PY
if ! grep -F 'if [[ "$DTO_COMPILER_ONLY" == 1 ]]; then' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'expect_rustc_test_fail_with_diagnostic crates/types/tests/semver_policy.rs' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'expect_cargo_test_fail_with_diagnostic rustfs-gateway-core integration' "$GUARD_SELF_TEST" >/dev/null; then
    fail 'dto-compiler-self-test omits a DTO compiler mutation'
fi
python3 - "$GUARD_SELF_TEST" <<'PY' || fail 'build-guard-self-test omits a build-backed control or mutation'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
marker = 'if [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then'
start = text.index("for guard in \\\n", text.index(marker))
end = text.index("; do", start)
actual = re.findall(r"check_[a-z0-9_]+\.sh", text[start:end])
expected = [
    "check_case_keys_honoured.sh",
    "check_macro_governance.sh",
    "check_monomorphic_dispatch.sh",
    "check_verify_map_generated.sh",
]
if actual != expected:
    raise SystemExit(1)
PY
if ! grep -F 'if [[ "$BUILD_GUARDS_ONLY" == 1 ]]; then' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'mut_build_monomorphic_handler_is_indirect' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'mut_build_unread_schema_key' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'mut_build_verify_map_edited' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'expect_fail_and_missing_cargo check_operation_spec_builder.sh' "$GUARD_SELF_TEST" >/dev/null ||
    ! grep -F 'scanner_budget_case check_single_normalization.sh 21 within' "$GUARD_SELF_TEST" >/dev/null; then
    fail 'build-guard-self-test omits a build-backed control or mutation'
fi

printf 'OK: workspace, signing suite, guard, target-consolidation, quirk-ledger, DTO compiler, build guard and TSAN workers are parallel behind Test\n'
