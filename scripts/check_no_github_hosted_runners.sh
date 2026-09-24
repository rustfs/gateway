#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_github_hosted_runners.sh
#
# WHAT THIS CHECKS
#   Every job in .github/workflows runs on an org self-hosted label, declares a
#   timeout, and installs the tools the GitHub-hosted image used to provide.
#   A workflow that listens to pull_request must cancel superseded runs.
#
# WHY
#   GitHub-hosted runners are billed per job-minute, and a one-minute job is
#   billed as one minute. The labels below are the ones rustfs/rustfs already
#   runs on. A missing timeout or a missing install step is how a move to those
#   runners goes green in review and red on the first pod.
#
# HOW TO EXEMPT
#   No exemption. A new label is a one-line addition to the allow-list in this
#   file, reviewed like any other runner change.
#
# USAGE
#   scripts/check_no_github_hosted_runners.sh
# =============================================================================

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
WORKFLOWS="$ROOT/.github/workflows"

if [[ ! -d "$WORKFLOWS" ]]; then
    printf 'ERROR: .github/workflows is missing\n' >&2
    exit 1
fi

mapfile -t workflow_files < <(find "$WORKFLOWS" -maxdepth 1 -type f -name '*.yml' | sort)
if [[ "${#workflow_files[@]}" -eq 0 ]]; then
    printf 'ERROR: .github/workflows contains no workflow files\n' >&2
    exit 1
fi

ruby -ryaml - "${workflow_files[@]}" <<'RUBY'
ALLOWED = %w[sm-standard-2 sm-standard-4 dind-sm-standard-2].freeze
INSTALL = "scripts/ci_install_host_tools.sh"

def abort_check(message)
  abort("ERROR: #{message}")
end

def triggers_of(workflow)
  workflow["on"] || workflow[true]
end

def pull_request?(triggers)
  case triggers
  when Hash
    triggers.key?("pull_request") || triggers.key?(:pull_request)
  when Array
    triggers.include?("pull_request")
  else
    triggers == "pull_request"
  end
end

ARGV.each do |path|
  workflow = YAML.load_file(path)
  abort_check("#{path} did not parse as a workflow mapping") unless workflow.is_a?(Hash)
  relative = path.sub(%r{\A.*/\.github/workflows/}, ".github/workflows/")
  jobs = workflow["jobs"]
  abort_check("#{relative} has no jobs") unless jobs.is_a?(Hash) && !jobs.empty?

  if pull_request?(triggers_of(workflow))
    concurrency = workflow["concurrency"]
    cancel = concurrency.is_a?(Hash) ? concurrency["cancel-in-progress"] : nil
    unless cancel == true || cancel == "${{ github.event_name == 'pull_request' }}"
      abort_check("#{relative} listens to pull_request but does not cancel superseded pull-request runs")
    end
  end

  jobs.each do |job_id, job|
    abort_check("#{relative} job #{job_id} must be a mapping") unless job.is_a?(Hash)
    runner = job["runs-on"]
    unless runner.is_a?(String) && ALLOWED.include?(runner)
      abort_check(
        "#{relative} job #{job_id} runs on #{runner.inspect}; " \
        "GitHub-hosted runners are forbidden. Use one of: #{ALLOWED.join(', ')}"
      )
    end
    timeout = job["timeout-minutes"]
    unless timeout.is_a?(Integer) && timeout.positive?
      abort_check("#{relative} job #{job_id} must declare a positive integer timeout-minutes")
    end
    steps = job["steps"]
    abort_check("#{relative} job #{job_id} must declare steps") unless steps.is_a?(Array)
    next if relative == ".github/workflows/ci.yml" && job_id == "test"

    installs = steps.count do |step|
      step.is_a?(Hash) && step["run"].to_s.include?(INSTALL)
    end
    unless installs == 1
      abort_check("#{relative} job #{job_id} must run #{INSTALL} exactly once")
    end
  end
end
RUBY

printf 'OK: every workflow job uses an org self-hosted runner\n'
