#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Workspace tests, the official signing suite, guard mutations split over four runners,
#   build-backed mutations split over three runners, target-consolidation mutations, quirk-ledger
#   mutations, error-status mutations and TSAN run on separate CI runners, while the
#   branch-protected Test check waits for every worker. This keeps the gate wall time below ten
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

workspace_ids = ["workspace-tests", "workspace-tests-2"]
workspaces = workspace_ids.map { |job_id| jobs.fetch(job_id) }
signing_suite = jobs.fetch("signing-suite")
guard = jobs.fetch("guard-self-test")
guard_group_ids = ["guard-self-test", "guard-self-test-2", "guard-self-test-3", "guard-self-test-4"]
guard_groups = guard_group_ids.map { |job_id| jobs.fetch(job_id) }
target = jobs.fetch("target-consolidation-self-test")
quirk_ledger = jobs.fetch("quirk-ledger-self-test")
dto_compiler = jobs.fetch("dto-compiler-self-test")
build_guard_ids = ["build-guard-self-test", "build-guard-self-test-2", "build-guard-self-test-3"]
build_guards = build_guard_ids.map { |job_id| jobs.fetch(job_id) }
error_status = jobs.fetch("error-status-self-test")
aggregate = jobs.fetch("test")

worker_keys = ["name", "runs-on", "timeout-minutes", "steps"]
workspaces.each_with_index do |job, index|
  require_equal(job.keys, worker_keys,
                "#{workspace_ids[index]} changed its parallel nine-minute contract")
  require_equal(job.values_at("name", "runs-on", "timeout-minutes"),
                ["Workspace tests #{index + 1}", "ubuntu-latest", 9],
                "#{workspace_ids[index]} identity or budget changed")
end
guard_groups.each_with_index do |job, index|
  require_equal(job.keys, worker_keys,
                "#{guard_group_ids[index]} changed its parallel six-minute contract")
end
require_equal(signing_suite.keys, worker_keys, "signing-suite changed its parallel four-minute contract")
require_equal(signing_suite.values_at("name", "runs-on", "timeout-minutes"),
              ["Official signing suite", "ubuntu-latest", 4], "signing-suite identity or budget changed")
# Four runners, one per quarter of the case ordinals. Six minutes each keeps the longest
# dependency path (a guard runner plus the one-minute Test aggregate) at seven of the ten.
guard_groups.each_with_index do |job, index|
  expected_name = index.zero? ? "Guard self-test" : "Guard self-test #{index + 1}"
  require_equal(job.values_at("name", "runs-on", "timeout-minutes"),
                [expected_name, "ubuntu-latest", 6],
                "#{guard_group_ids[index]} identity or budget changed")
end
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
build_guards.each_with_index do |job, index|
  require_equal(job.keys, worker_keys,
                "#{build_guard_ids[index]} changed its parallel five-minute contract")
  require_equal(job.values_at("name", "runs-on", "timeout-minutes"),
                ["Build guard self-test #{index + 1}", "ubuntu-latest", 5],
                "#{build_guard_ids[index]} identity or budget changed")
end
require_equal(error_status.keys, worker_keys,
              "error-status-self-test changed its parallel two-minute contract")
require_equal(error_status.values_at("name", "runs-on", "timeout-minutes"),
              ["Error status self-test", "ubuntu-latest", 2],
              "error-status-self-test identity or budget changed")

(workspaces + guard_groups).each do |job|
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

workspaces.each_with_index do |job, index|
  require_equal(job.fetch("steps").first(3).map(&:keys), [["uses"], ["uses", "with"], ["uses"]],
                "#{workspace_ids[index]} setup gained executable control")
end
signing_suite_steps = signing_suite.fetch("steps")
require_equal(signing_suite_steps.length, 4, "signing-suite changed its setup or command step count")
require_equal(signing_suite_steps.first(3).map { |step| step.fetch("uses") }, [
  "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
  "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
  "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
], "signing-suite setup action or pin changed")
require_equal(signing_suite_steps.first(3).map(&:keys), [["uses"], ["uses", "with"], ["uses"]],
              "signing-suite setup gained executable control")
require_equal(signing_suite_steps.last.keys, ["name", "run"],
              "signing-suite command can skip or hide failure")
guard_groups.each_with_index do |job, index|
  steps = job.fetch("steps")
  require_equal(steps.first(3).map(&:keys), [["uses", "with"], ["uses", "with"], ["uses"]],
                "#{guard_group_ids[index]} setup changed its parent-fetch contract")
  require_equal(steps.first.fetch("with"), {"fetch-depth" => 0},
                "#{guard_group_ids[index]} cannot resolve the branch merge base")
end
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
require_equal(dto_compiler_steps.first(3).map(&:keys), [["uses"], ["uses", "with"], ["uses"]],
              "dto-compiler-self-test setup gained executable control")
require_equal(dto_compiler_steps.last.keys, ["name", "run"],
              "dto-compiler-self-test command can skip or hide failure")
build_guards.each_with_index do |job, index|
  steps = job.fetch("steps")
  require_equal(steps.length, 4,
                "#{build_guard_ids[index]} changed its setup or command step count")
  require_equal(steps.first(3).map { |step| step.fetch("uses") }, [
    "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
    "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
    "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
  ], "#{build_guard_ids[index]} setup action or pin changed")
  require_equal(steps.first(3).map(&:keys), [["uses"], ["uses", "with"], ["uses"]],
                "#{build_guard_ids[index]} setup gained executable control")
  require_equal(steps.last.keys, ["name", "run"],
                "#{build_guard_ids[index]} command can skip or hide failure")
end
error_status_steps = error_status.fetch("steps")
require_equal(error_status_steps.length, 2,
              "error-status-self-test changed its setup or command step count")
require_equal(error_status_steps.first,
              {"uses" => "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"},
              "error-status-self-test checkout action or pin changed")
require_equal(error_status_steps.last.keys, ["name", "run"],
              "error-status-self-test command can skip or hide failure")

workspace_runs = [<<~'RUN', <<~'RUN']
  scripts/ci_budget.sh 480 "workspace tests 1/2" cargo test --workspace --exclude rustfs-gateway-conformance
  scripts/ci_budget.sh 30 "handlers facade fixture" scripts/test_handlers_facade_fixture.sh
RUN
  scripts/ci_budget.sh 480 "workspace tests 2/2" cargo test --package rustfs-gateway-conformance
RUN
signing_suite_run = <<~'RUN'
  scripts/ci_budget.sh 90 "signing suite build" cargo build --package xtask --bin xtask
  scripts/ci_budget.sh 60 "signing suite fetch" target/debug/xtask sigsuite fetch
  scripts/ci_budget.sh 60 "signing suite run" target/debug/xtask sigsuite run
RUN
# Every runner declares the same budget it is given, so an overrun stops itself with a
# diagnosis instead of being killed at exit 124 with every case still printing ok.
guard_runs = (0...4).map do |group|
  <<~RUN
    scripts/ci_budget.sh 300 "guard mutations #{group + 1}/4" env GATEWAY_GUARD_BUDGET_SECONDS=300 GATEWAY_GUARD_SHARD_GROUPS=4 GATEWAY_GUARD_SHARD_GROUP=#{group} bash scripts/test_guard_scripts.sh
  RUN
end
# Two suites, two budgets, one runner. They share a runner because the pair costs about twenty
# seconds of a three-minute job and a second runner would cost more in spin-up than it saves; they
# keep separate ci_budget.sh lines because a shared budget reports one margin for two suites and
# hides which of them is the one growing. 120 + 45 stays inside the job's own three-minute timeout,
# so an overrun is diagnosed by ci_budget.sh rather than killed at exit 124.
target_run = <<~'RUN'
  scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh
  scripts/ci_budget.sh 45 "test target coverage self-test" bash scripts/test_test_target_coverage.sh
RUN
quirk_ledger_run = <<~'RUN'
  scripts/ci_budget.sh 60 "quirk ledger self-test" env GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 bash scripts/test_guard_scripts.sh
RUN
dto_compiler_run = <<~'RUN'
  scripts/ci_budget.sh 90 "DTO compiler self-test" env GATEWAY_GUARD_DTO_COMPILER_ONLY=1 bash scripts/test_guard_scripts.sh
RUN
build_guard_runs = (0...3).map do |group|
  <<~RUN
    scripts/ci_budget.sh 270 "build-backed guards #{group + 1}/3" env GATEWAY_GUARD_BUDGET_SECONDS=270 GATEWAY_GUARD_BUILD_GUARDS_ONLY=1 GATEWAY_GUARD_SHARD_GROUPS=3 GATEWAY_GUARD_SHARD_GROUP=#{group} bash scripts/test_guard_scripts.sh
  RUN
end
workspaces.each_with_index do |job, index|
  require_equal(job.fetch("steps").last.fetch("run"), workspace_runs.fetch(index),
                "#{workspace_ids[index]} command changed, lost its shard, or can hide a failure")
end
require_equal(workspace_runs.uniq.length, 2,
              "the workspace test runners do not cover two distinct shards")
require_equal(signing_suite_steps.last.fetch("run"), signing_suite_run,
              "signing-suite command changed or can hide a failure")
guard_groups.each_with_index do |job, index|
  require_equal(job.fetch("steps").last.fetch("run"), guard_runs.fetch(index),
                "#{guard_group_ids[index]} command changed, lost its shard, or can hide a failure")
end
# The four groups must be the four distinct quarters of one split, or a quarter of the
# suite silently never runs while all four jobs report success.
require_equal(guard_runs.uniq.length, 4, "the guard runners do not cover four distinct shards")
require_equal(target.fetch("steps").last.fetch("run"), target_run,
              "target-consolidation-self-test command changed or can hide a failure")
require_equal(quirk_ledger.fetch("steps").last.fetch("run"), quirk_ledger_run,
              "quirk-ledger-self-test command changed or can hide a failure")
require_equal(dto_compiler.fetch("steps").last.fetch("run"), dto_compiler_run,
              "dto-compiler-self-test command changed or can hide a failure")
error_status_run = <<~'RUN'
  scripts/ci_budget.sh 60 "error status self-test" env GATEWAY_GUARD_ERROR_STATUS_ONLY=1 bash scripts/test_guard_scripts.sh
RUN
build_guards.each_with_index do |job, index|
  require_equal(job.fetch("steps").last.fetch("run"), build_guard_runs.fetch(index),
                "#{build_guard_ids[index]} command changed, lost its shard, or can hide a failure")
end
require_equal(build_guard_runs.uniq.length, 3,
              "the build-backed guard runners do not cover three distinct shards")
require_equal(error_status.fetch("steps").last.fetch("run"), error_status_run,
              "error-status-self-test command changed or can hide a failure")

# Every timed command behind the Test aggregate must report the margin it had left.
#
# rustfs/gateway#188 and #217 are the same failure twice. A job grows with every merge until it
# crosses its hard `timeout`, and what CI prints is `exit code 124` after every case has said ok
# — no failing assertion, nothing naming the clock — on whichever branch happened to be next
# through the gate. Both times the margin had been shrinking for weeks and nothing reported it,
# because a bare `timeout` is silent right up until the moment it is fatal.
#
# So a bare `timeout` is no longer allowed in these jobs. The budget goes through
# scripts/ci_budget.sh, which prints the margin on every run, raises a ::warning:: annotation
# past 80% of budget while there is still room to act cheaply, and turns an overrun into an
# explicit OUT OF TIME diagnosis instead of an opaque 124. A new job cannot be added to the
# gate without one.
aggregate.fetch("needs").each do |job_id|
  budgeted = 0
  jobs.fetch(job_id).fetch("steps").each do |step|
    run = step["run"]
    next if run.nil?
    run.each_line do |line|
      command = line.strip
      next if command.empty?
      if command.match?(/(\A|\s)timeout\s+[0-9]+s?\s/)
        abort("ERROR: #{job_id} runs a bare `timeout`, so an overrun reads as an opaque exit 124 " \
              "instead of naming the budget it exhausted: #{command}")
      end
      budgeted += 1 if command.start_with?("scripts/ci_budget.sh ")
    end
  end
  if budgeted.zero?
    abort("ERROR: #{job_id} is behind the Test gate but declares no wall-clock budget through " \
          "scripts/ci_budget.sh, so nothing would report its margin until it fails")
  end
end

aggregate_keys = ["name", "needs", "if", "runs-on", "timeout-minutes", "steps"]
require_equal(aggregate.keys, aggregate_keys, "the Test job changed its dependency, failure, or budget contract")
require_equal(aggregate.values_at("name", "needs", "if", "runs-on", "timeout-minutes"),
              ["Test", ["workspace-tests", "workspace-tests-2", "signing-suite", "guard-self-test", "guard-self-test-2", "guard-self-test-3", "guard-self-test-4", "target-consolidation-self-test", "quirk-ledger-self-test", "dto-compiler-self-test", "build-guard-self-test", "build-guard-self-test-2", "build-guard-self-test-3", "error-status-self-test", "gateway-tsan"], "always()", "ubuntu-latest", 1],
              "the Test job no longer aggregates all fifteen workers within the budget")
steps = aggregate.fetch("steps")
require_equal(steps.length, 1, "the Test job must have exactly one result-checking step")
require_equal(steps.first.keys, ["name", "env", "run"], "the Test comparison step can be skipped or hidden")
expected_env = {
  "WORKSPACE_RESULT" => "${{ needs.workspace-tests.result }}",
  "WORKSPACE_2_RESULT" => "${{ needs.workspace-tests-2.result }}",
  "SIGNING_SUITE_RESULT" => "${{ needs.signing-suite.result }}",
  "GUARD_RESULT" => "${{ needs.guard-self-test.result }}",
  "GUARD_2_RESULT" => "${{ needs.guard-self-test-2.result }}",
  "GUARD_3_RESULT" => "${{ needs.guard-self-test-3.result }}",
  "GUARD_4_RESULT" => "${{ needs.guard-self-test-4.result }}",
  "TARGET_CONSOLIDATION_RESULT" => "${{ needs.target-consolidation-self-test.result }}",
  "QUIRK_LEDGER_RESULT" => "${{ needs.quirk-ledger-self-test.result }}",
  "DTO_COMPILER_RESULT" => "${{ needs.dto-compiler-self-test.result }}",
  "BUILD_GUARD_RESULT" => "${{ needs.build-guard-self-test.result }}",
  "BUILD_GUARD_2_RESULT" => "${{ needs.build-guard-self-test-2.result }}",
  "BUILD_GUARD_3_RESULT" => "${{ needs.build-guard-self-test-3.result }}",
  "ERROR_STATUS_RESULT" => "${{ needs.error-status-self-test.result }}",
  "TSAN_RESULT" => "${{ needs.gateway-tsan.result }}"
}
require_equal(steps.first.fetch("env"), expected_env, "the Test step does not bind all worker results")
expected_run = <<~'RUN'
  test "$WORKSPACE_RESULT" = success
  test "$WORKSPACE_2_RESULT" = success
  test "$SIGNING_SUITE_RESULT" = success
  test "$GUARD_RESULT" = success
  test "$GUARD_2_RESULT" = success
  test "$GUARD_3_RESULT" = success
  test "$GUARD_4_RESULT" = success
  test "$TARGET_CONSOLIDATION_RESULT" = success
  test "$QUIRK_LEDGER_RESULT" = success
  test "$DTO_COMPILER_RESULT" = success
  test "$BUILD_GUARD_RESULT" = success
  test "$BUILD_GUARD_2_RESULT" = success
  test "$BUILD_GUARD_3_RESULT" = success
  test "$ERROR_STATUS_RESULT" = success
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

start = text.find('if [[ "$ERROR_STATUS_ONLY" == 1 ]]; then')
first_case = text.find("expect_fail check_error_status_total.sh")
end = text.find("\nfi\n", first_case)
if start < 0 or first_case < start or end < first_case:
    raise SystemExit("ERROR: guard-self-test still serializes or omits error-status mutations")
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

# The guard self-test stops itself just before the CI `timeout` would kill it, so that an
# overrun reads as "the suite ran out of time" instead of an unexplained exit 124. That only
# works while the budget the script defends and the timeout CI enforces are the same number.
python3 - "$WORKFLOW" "$GUARD_SELF_TEST" <<'PY' || exit 1
import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text()
suite = Path(sys.argv[2]).read_text()

if re.search(r'^GUARD_BUDGET_SECONDS="\$\{GATEWAY_GUARD_BUDGET_SECONDS:-[0-9]+\}"$', suite,
             re.MULTILINE) is None:
    raise SystemExit(
        "ERROR: the guard self-test no longer reads the wall-clock budget it must defend"
    )
invocations = re.findall(
    r'scripts/ci_budget\.sh ([0-9]+) "[^"]*" env ([^\n]*?) bash scripts/test_guard_scripts\.sh',
    workflow,
)
regular_shards = [
    (int(seconds), env) for seconds, env in invocations
    if "GATEWAY_GUARD_SHARD_GROUP=" in env and "GATEWAY_GUARD_BUILD_GUARDS_ONLY=1" not in env
]
build_shards = [
    (int(seconds), env) for seconds, env in invocations
    if "GATEWAY_GUARD_SHARD_GROUP=" in env and "GATEWAY_GUARD_BUILD_GUARDS_ONLY=1" in env
]
if len(regular_shards) != 4:
    raise SystemExit(
        f"ERROR: expected four guard shard invocations in CI, found {len(regular_shards)}"
    )
if len(build_shards) != 3:
    raise SystemExit(
        f"ERROR: expected three build-backed guard shard invocations in CI, found {len(build_shards)}"
    )
for seconds, env in regular_shards + build_shards:
    declared = re.search(r"GATEWAY_GUARD_BUDGET_SECONDS=([0-9]+)", env)
    if declared is None:
        raise SystemExit(
            "ERROR: a guard shard runs without declaring the budget it must stop inside, so an "
            "overrun would be killed at exit 124 before the suite could say it ran out of time"
        )
    if int(declared.group(1)) != seconds:
        raise SystemExit(
            f"ERROR: a guard shard defends {declared.group(1)}s but CI enforces {seconds}s; "
            "an overrun would be killed at exit 124 before the suite could diagnose itself"
        )
regular_groups = sorted(
    int(re.search(r"GATEWAY_GUARD_SHARD_GROUP=([0-9]+)", env).group(1))
    for _, env in regular_shards
)
if regular_groups != [0, 1, 2, 3]:
    raise SystemExit(
        f"ERROR: the guard shards cover groups {regular_groups}, not every quarter of the suite"
    )
build_groups = sorted(
    int(re.search(r"GATEWAY_GUARD_SHARD_GROUP=([0-9]+)", env).group(1))
    for _, env in build_shards
)
if build_groups != [0, 1, 2]:
    raise SystemExit(
        f"ERROR: the build-backed guard shards cover groups {build_groups}, not every third"
    )
PY

printf 'OK: two workspace shards, signing suite, four guard shards, target-consolidation, quirk-ledger, DTO compiler, three build guard shards, error-status and TSAN workers are parallel behind Test\n'
