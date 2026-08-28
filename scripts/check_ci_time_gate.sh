#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Every pull-request CI job has a bounded timeout, every dependency path stays
#   within ten minutes, and the three branch-protected checks keep their exact
#   identity, commands, failure propagation, permissions, and action pins.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WORKFLOW="$ROOT/.github/workflows/ci.yml"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -f "$WORKFLOW" ]] || fail '.github/workflows/ci.yml is missing'

ruby -ryaml - "$WORKFLOW" <<'RUBY'
workflow = YAML.load_file(ARGV.fetch(0))
abort("ERROR: workflow must be a YAML mapping") unless workflow.is_a?(Hash)

def require_equal(actual, expected, message)
  abort("ERROR: #{message}") unless actual == expected
end

require_equal(workflow.fetch("permissions", nil), {"contents" => "read"},
              "workflow permissions must remain contents: read")
require_equal(workflow.fetch("concurrency", nil), {
                "group" => "${{ github.workflow }}-${{ github.ref }}",
                "cancel-in-progress" => true
              }, "workflow concurrency must cancel superseded branch runs")
abort("ERROR: workflow defaults may not override command failure propagation") if workflow.key?("defaults")
workflow_env_keys = %w[
  CARGO_TERM_COLOR
  CARGO_SEMVER_CHECKS_TOOL
  CARGO_HACK_TOOL
  CARGO_LLVM_COV_TOOL
  CARGO_DENY_TOOL
  CARGO_PUBLIC_API_TOOL
  CARGO_FUZZ_TOOL
]
require_equal(workflow.fetch("env", {}).keys, workflow_env_keys,
              "workflow environment may not override required commands")

jobs = workflow.fetch("jobs", nil)
abort("ERROR: workflow jobs must be a YAML mapping") unless jobs.is_a?(Hash)

mandatory_jobs = %w[
  static
  clippy
  docs
  bootstrap
  feedback-loop
  workspace-tests
  gateway-tsan
  guard-self-test
  test
]
missing_jobs = mandatory_jobs - jobs.keys
abort("ERROR: required PR jobs are missing: #{missing_jobs.join(', ')}") unless missing_jobs.empty?

required_contexts = {
  "static" => "Static checks",
  "clippy" => "Clippy",
  "test" => "Test"
}
required_contexts.each do |job_id, context|
  require_equal(jobs.fetch(job_id).fetch("name", nil), context,
                "#{job_id} must keep the branch-protected #{context} check name")
  count = jobs.values.count { |job| job.is_a?(Hash) && job["name"] == context }
  require_equal(count, 1, "branch-protected check name #{context} must occur exactly once")
end

exact_commands = {
  "static" => "cargo fmt --all --check",
  "clippy" => "cargo clippy --workspace --all-targets -- -D warnings"
}
all_runs = []
jobs.each do |job_id, job|
  abort("ERROR: job #{job_id} must be a YAML mapping") unless job.is_a?(Hash)
  steps = job.fetch("steps", nil)
  abort("ERROR: job #{job_id} must declare a steps list") unless steps.is_a?(Array)
  all_runs.concat(steps.map { |step| step["run"] if step.is_a?(Hash) }.compact)
end
exact_commands.each do |job_id, command|
  runs = jobs.fetch(job_id).fetch("steps").map { |step| step["run"] }.compact
  require_equal(runs.count(command), 1, "#{job_id} must run its exact gate command once")
  require_equal(all_runs.count(command), 1, "#{command} must have one authoritative CI execution")
  command_step = jobs.fetch(job_id).fetch("steps").find { |step| step["run"] == command }
  require_equal(command_step.keys, ["run"], "#{job_id} command step may not alter execution")
end

feedback_steps = jobs.fetch("feedback-loop").fetch("steps")
feedback_prebuild = feedback_steps.find { |step| step["name"] == "Prebuild operation verification targets" }
expected_feedback_prebuild = <<~SHELL
  cargo build -p rustfs-gateway-conformance --bin rustfs-gateway-conformance
  cargo test -p xtask --bin xtask --no-run
  cargo build -p xtask --no-default-features
  cargo build -p xtask-launcher
  cargo build -p xtask --features full
SHELL
require_equal(feedback_prebuild&.fetch("run", nil), expected_feedback_prebuild,
              "operation verification must prebuild every exact runner and leave the full xtask feature graph warm")

static_steps = jobs.fetch("static").fetch("steps")
require_equal(static_steps.first(3).map(&:keys), [["uses", "with"], ["uses", "with"], ["run"]],
              "static setup or command order changed")
require_equal(static_steps.first(2).map { |step| step.fetch("uses") }, [
                "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
                "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"
              ], "static setup action or pin changed")
require_equal(static_steps.first.fetch("with"), {"fetch-depth" => 0},
              "static must retain the branch graph for merge-base guards")

clippy_steps = jobs.fetch("clippy").fetch("steps")
require_equal(clippy_steps.map(&:keys), [["uses"], ["uses", "with"], ["uses"], ["run"]],
              "clippy setup or command can alter failure propagation")
require_equal(clippy_steps.first(3).map { |step| step.fetch("uses") }, [
                "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
                "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
                "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"
              ], "clippy setup action or pin changed")

%w[static clippy].each do |job_id|
  job = jobs.fetch(job_id)
  require_equal(job.keys, ["name", "runs-on", "timeout-minutes", "steps"],
                "#{job_id} changed its required gate shape")
  require_equal(job.fetch("runs-on", nil), "ubuntu-latest",
                "#{job_id} must run on the expected hosted runner")
  abort("ERROR: #{job_id} must remain an independent parallel job") if job.key?("needs")
  abort("ERROR: #{job_id} may not conditionally skip") if job.key?("if")
  require_equal(job.fetch("timeout-minutes", nil), 9,
                "#{job_id} must retain its explicit nine-minute upper bound")
end

walk = lambda do |value, path|
  case value
  when Hash
    value.each do |key, child|
      child_path = path + [key]
      if key == "continue-on-error"
        abort("ERROR: #{child_path.join('.')} may hide a failed gate")
      end
      if key == "shell"
        abort("ERROR: #{child_path.join('.')} may override fail-fast shell behavior")
      end
      if key == "uses" && !(child.is_a?(String) && child.match?(/\A[^@\s]+@[0-9a-f]{40}\z/))
        abort("ERROR: #{child_path.join('.')} must pin an action to a full commit SHA")
      end
      walk.call(child, child_path)
    end
  when Array
    value.each_with_index { |child, index| walk.call(child, path + [index]) }
  end
end
walk.call(workflow, [])

jobs.each do |job_id, job|
  %w[permissions concurrency strategy defaults].each do |key|
    abort("ERROR: job #{job_id} may not declare #{key}") if job.key?(key)
  end
  if job.key?("if")
    require_equal([job_id, job["if"]], ["test", "always()"],
                  "only the Test aggregate may use the always() job condition")
  end
  job.fetch("steps").each_with_index do |step, index|
    abort("ERROR: job #{job_id} step #{index + 1} may not conditionally skip") if step.key?("if")
  end
end

timeouts = {}
dependencies = {}
jobs.each do |job_id, job|
  timeout = job.fetch("timeout-minutes", nil)
  unless timeout.is_a?(Integer) && timeout.positive?
    abort("ERROR: job #{job_id} must declare a positive integer timeout-minutes")
  end
  timeouts[job_id] = timeout

  needs = job.fetch("needs", [])
  needs = [needs] if needs.is_a?(String)
  abort("ERROR: job #{job_id} needs must be a string or list") unless needs.is_a?(Array)
  needs.each do |dependency|
    abort("ERROR: job #{job_id} depends on missing job #{dependency}") unless jobs.key?(dependency)
  end
  dependencies[job_id] = needs
end

memo = {}
visiting = {}
longest_path = lambda do |job_id|
  return memo.fetch(job_id) if memo.key?(job_id)
  abort("ERROR: CI dependency graph contains a cycle at #{job_id}") if visiting[job_id]

  visiting[job_id] = true
  parent_budget = dependencies.fetch(job_id).map { |dependency| longest_path.call(dependency) }.max || 0
  visiting.delete(job_id)
  memo[job_id] = parent_budget + timeouts.fetch(job_id)
end

jobs.each_key do |job_id|
  budget = longest_path.call(job_id)
  abort("ERROR: CI path ending at #{job_id} permits #{budget} minutes (maximum 10)") if budget > 10
end
RUBY

printf 'OK: required CI checks and every dependency path are bounded by ten minutes\n'
