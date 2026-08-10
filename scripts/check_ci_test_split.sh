#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Workspace tests, guard mutations and TSAN run on separate CI runners, while the
#   branch-protected Test check waits for all three. This keeps the gate wall time below ten
#   minutes as coverage grows.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WORKFLOW="$ROOT/.github/workflows/ci.yml"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -f "$WORKFLOW" ]] || fail '.github/workflows/ci.yml is missing'

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
guard = jobs.fetch("guard-self-test")
aggregate = jobs.fetch("test")

worker_keys = ["name", "runs-on", "timeout-minutes", "steps"]
require_equal(workspace.keys, worker_keys, "workspace-tests changed its parallel nine-minute contract")
require_equal(guard.keys, worker_keys, "guard-self-test changed its parallel nine-minute contract")
require_equal(workspace.values_at("name", "runs-on", "timeout-minutes"),
              ["Workspace tests", "ubuntu-latest", 9], "workspace-tests identity or budget changed")
require_equal(guard.values_at("name", "runs-on", "timeout-minutes"),
              ["Guard self-test", "ubuntu-latest", 9], "guard-self-test identity or budget changed")

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
guard_steps = guard.fetch("steps")
require_equal(guard_steps.first(3).map(&:keys), [["uses", "with"], ["uses"], ["uses"]],
              "guard-self-test setup changed its parent-fetch contract")
require_equal(guard_steps.first.fetch("with"), {"fetch-depth" => 2},
              "guard-self-test cannot read the baseline parent commit")

workspace_run = <<~'RUN'
  started="$(date +%s)"
  timeout 480s cargo test --workspace
  elapsed="$(( $(date +%s) - started ))"
  echo "workspace tests completed in ${elapsed}s"
RUN
guard_run = <<~'RUN'
  started="$(date +%s)"
  timeout 480s bash scripts/test_guard_scripts.sh
  elapsed="$(( $(date +%s) - started ))"
  echo "guard mutations completed in ${elapsed}s"
RUN
require_equal(workspace.fetch("steps").last.fetch("run"), workspace_run,
              "workspace-tests command changed or can hide a failure")
require_equal(guard.fetch("steps").last.fetch("run"), guard_run,
              "guard-self-test command changed or can hide a failure")

aggregate_keys = ["name", "needs", "if", "runs-on", "timeout-minutes", "steps"]
require_equal(aggregate.keys, aggregate_keys, "the Test job changed its dependency, failure, or budget contract")
require_equal(aggregate.values_at("name", "needs", "if", "runs-on", "timeout-minutes"),
              ["Test", ["workspace-tests", "guard-self-test", "gateway-tsan"], "always()", "ubuntu-latest", 1],
              "the Test job no longer aggregates all three workers within the budget")
steps = aggregate.fetch("steps")
require_equal(steps.length, 1, "the Test job must have exactly one result-checking step")
require_equal(steps.first.keys, ["name", "env", "run"], "the Test comparison step can be skipped or hidden")
expected_env = {
  "WORKSPACE_RESULT" => "${{ needs.workspace-tests.result }}",
  "GUARD_RESULT" => "${{ needs.guard-self-test.result }}",
  "TSAN_RESULT" => "${{ needs.gateway-tsan.result }}"
}
require_equal(steps.first.fetch("env"), expected_env, "the Test step does not bind all worker results")
expected_run = <<~'RUN'
  test "$WORKSPACE_RESULT" = success
  test "$GUARD_RESULT" = success
  test "$TSAN_RESULT" = success
RUN
require_equal(steps.first.fetch("run"), expected_run, "the Test step does not execute all comparisons")
RUBY
if grep -F 'cargo xtask verify --all' "$WORKFLOW" >/dev/null; then
    fail 'CI still serializes workspace tests and guard mutations through verify --all'
fi

printf 'OK: workspace tests, guard mutations and TSAN are parallel behind the required Test check\n'
