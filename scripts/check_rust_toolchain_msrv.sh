#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keep the Cargo MSRV, exact development toolchain, documentation and the CI workflow
#       aligned -- including that every CI job installs the compiler rust-toolchain.toml names.
# WHY:  rustfs/backlog#1713 makes the compiler floor and build toolchain reviewable inputs.
#       dtolnay/rust-toolchain does not read rust-toolchain.toml: its `toolchain` input defaults
#       to `stable`. A comment in ci.yml claimed the opposite, nothing enforced it, and when
#       rustc 1.98.0 shipped on 2026-08-20 every cache-backed job on main went red at once.
#       So the workflow names the compiler exactly once, in RUST_TOOLCHAIN, and this guard binds
#       that name to rust-toolchain.toml and to every toolchain step in the workflow.
# HOW TO EXEMPT: There are no exemptions; change all compiler contracts in one reviewed PR.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_rust_toolchain_msrv)" || exit 1
if ! command -v ruby >/dev/null 2>&1; then
    printf 'check_rust_toolchain_msrv: required command is missing: ruby\n' >&2
    exit 1
fi

TOOLCHAIN_CONTRACT="$("$PYTHON" - "$REPO_ROOT" <<'PY'
from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1])
paths = {
    "Cargo.toml": root / "Cargo.toml",
    "rdma/Cargo.toml": root / "rdma/Cargo.toml",
    "scripts/build-rdma.sh": root / "scripts/build-rdma.sh",
    "rust-toolchain.toml": root / "rust-toolchain.toml",
    "README.md": root / "README.md",
    "docs/msrv.md": root / "docs/msrv.md",
    ".github/workflows/ci.yml": root / ".github/workflows/ci.yml",
}
for name, path in paths.items():
    if not path.is_file():
        raise SystemExit(f"check_rust_toolchain_msrv: required input is missing: {name}")

try:
    cargo = tomllib.loads(paths["Cargo.toml"].read_text())
    rdma_cargo = tomllib.loads(paths["rdma/Cargo.toml"].read_text())
    toolchain = tomllib.loads(paths["rust-toolchain.toml"].read_text())
except tomllib.TOMLDecodeError as error:
    raise SystemExit(f"check_rust_toolchain_msrv: invalid TOML: {error}") from error

msrv = cargo.get("workspace", {}).get("package", {}).get("rust-version")
if not isinstance(msrv, str) or re.fullmatch(r"1\.[0-9]+\.[0-9]+", msrv) is None:
    raise SystemExit("check_rust_toolchain_msrv: workspace rust-version must be an exact stable release")

rdma_msrv = rdma_cargo.get("package", {}).get("rust-version")
if rdma_msrv != msrv:
    raise SystemExit(
        f"check_rust_toolchain_msrv: rdma/Cargo.toml rust-version {rdma_msrv!r} must match workspace rust-version {msrv!r}"
    )

build_rdma = paths["scripts/build-rdma.sh"].read_text()
if f"RUSTFS_RDMA_TOOLCHAIN:-{msrv}" not in build_rdma:
    raise SystemExit(
        f"check_rust_toolchain_msrv: scripts/build-rdma.sh default toolchain must match workspace rust-version {msrv!r}"
    )

channel = toolchain.get("toolchain", {}).get("channel")
if channel != msrv:
    raise SystemExit(
        f"check_rust_toolchain_msrv: toolchain channel {channel!r} must exactly match workspace rust-version {msrv!r}"
    )

expected_components = {"rustfmt", "clippy", "rust-src", "rust-analyzer"}
components = toolchain.get("toolchain", {}).get("components")
if not isinstance(components, list) or set(components) != expected_components or len(components) != len(expected_components):
    raise SystemExit("check_rust_toolchain_msrv: rust-toolchain components drifted")

readme = paths["README.md"].read_text()
for fact in (f"MSRV-{msrv}", f"**MSRV: {msrv}.**", f"**Development toolchain: {msrv}**"):
    if fact not in readme:
        raise SystemExit(f"check_rust_toolchain_msrv: README is missing {fact!r}")

msrv_doc = paths["docs/msrv.md"].read_text()
if f"**MSRV = {msrv}**" not in msrv_doc or f"The workspace pins Rust {msrv} for development" not in msrv_doc:
    raise SystemExit("check_rust_toolchain_msrv: docs/msrv.md does not match the compiler contracts")
print(msrv, ",".join(components))
PY
)"
MSRV="${TOOLCHAIN_CONTRACT%% *}"
TOOLCHAIN_COMPONENTS="${TOOLCHAIN_CONTRACT#* }"

ruby -ryaml - "$REPO_ROOT/.github/workflows" "$MSRV" "$TOOLCHAIN_COMPONENTS" <<'RUBY'
begin
  workflows_dir = ARGV.fetch(0)
  ci_path = File.join(workflows_dir, "ci.yml")
  workflow = YAML.safe_load(File.read(ci_path), permitted_classes: [], permitted_symbols: [], aliases: false)
  abort("check_rust_toolchain_msrv: CI workflow must be a mapping") unless workflow.is_a?(Hash)
  jobs = workflow.fetch("jobs")
  abort("check_rust_toolchain_msrv: CI jobs must be a mapping") unless jobs.is_a?(Hash)
  job = jobs.fetch("msrv")
  abort("check_rust_toolchain_msrv: CI msrv job must be a mapping") unless job.is_a?(Hash)

  forbidden = ["if", "continue-on-error"]
  abort("check_rust_toolchain_msrv: CI msrv job must always run and fail closed") unless (job.keys & forbidden).empty?

  steps = job.fetch("steps")
  abort("check_rust_toolchain_msrv: CI msrv steps must be a sequence") unless steps.is_a?(Array)
  abort("check_rust_toolchain_msrv: every CI msrv step must be a mapping") unless steps.all? { |step| step.is_a?(Hash) }

  toolchain_steps = steps.select { |step| step.fetch("uses", "").match?(%r{\Adtolnay/rust-toolchain@}) }
  abort("check_rust_toolchain_msrv: CI msrv job must have exactly one rust-toolchain step") unless toolchain_steps.length == 1
  check_steps = steps.select { |step| step["run"] == "cargo check --workspace --all-targets" }
  abort("check_rust_toolchain_msrv: CI msrv job must compile the whole workspace exactly once") unless check_steps.length == 1

  (toolchain_steps + check_steps).each do |step|
    abort("check_rust_toolchain_msrv: critical CI msrv steps must always run and fail closed") unless (step.keys & forbidden).empty?
  end

  # rust-toolchain.toml is the one authority; the workflow repeats the number per job because a
  # workflow `env:` var whose name begins with CARGO/CC/CFLAGS/CXX/CMAKE/RUST is hashed into
  # Swatinem/rust-cache's restore key, and moving that key costs every job a cold rebuild.
  # The repetition cannot drift because this guard compares every one of them to the file.
  reference = ARGV.fetch(1)
  development_components = ARGV.fetch(2).split(",").join(", ")

  with = toolchain_steps.first.fetch("with")
  abort("check_rust_toolchain_msrv: rust-toolchain inputs must be a mapping") unless with.is_a?(Hash)
  abort("check_rust_toolchain_msrv: CI msrv job does not install the exact workspace MSRV") unless with["toolchain"] == reference

  # Bootstrap owns fresh-checkout preparation after the compiler and its declared development
  # components exist. If this action installs only the minimal compiler, the first measured Cargo
  # invocation downloads rustfmt, clippy, rust-src, and rust-analyzer inside the five-minute budget.
  bootstrap_steps = jobs.fetch("bootstrap").fetch("steps")
  bootstrap_toolchain_index = bootstrap_steps.index do |step|
    step.is_a?(Hash) && step.fetch("uses", "").match?(%r{\Adtolnay/rust-toolchain@})
  end
  # The wrapper is scripts/ci_budget.sh, not a bare `timeout`: `cargo xtask bootstrap` defends the
  # five-minute promise itself and reports the seconds it took, and a `timeout 300s` around a 300s
  # contract kills the command before that verdict can reach the log.
  bootstrap_command_index = bootstrap_steps.index do |step|
    step.is_a?(Hash) &&
      step.fetch("run", "").match?(%r{^\s*scripts/ci_budget\.sh \d+ "[^"]+" cargo xtask bootstrap\s*$})
  end
  unless bootstrap_toolchain_index && bootstrap_command_index &&
         bootstrap_toolchain_index < bootstrap_command_index
    abort("check_rust_toolchain_msrv: bootstrap must provision its pinned toolchain before the measured command")
  end
  bootstrap_inputs = bootstrap_steps.fetch(bootstrap_toolchain_index).fetch("with", nil)
  unless bootstrap_inputs == {
           "toolchain" => reference,
           "components" => development_components
         }
    abort("check_rust_toolchain_msrv: bootstrap must provision every rust-toolchain.toml component before measurement")
  end

  # The defect this guard exists to make impossible: a job that installs `stable` -- by naming it,
  # or by omitting `with:` and taking the action's default -- while rust-toolchain.toml names an
  # exact release. Both compilers then exist on the runner, the rustup default is the wrong one,
  # and any cargo invocation that does not resolve the directory override builds against it.
  # The ThreadSanitizer job is the one declared exception: -Zbuild-std is unstable, so it pins a
  # dated nightly, which is still an exact compiler rather than a moving channel.
  #
  # A job that runs cargo must install exactly one toolchain, so dropping or renaming the step
  # cannot leave this loop with nothing to inspect and still read green.
  nightly_only = "gateway-tsan"
  installed = 0
  jobs.each do |job_id, job|
    next unless job.is_a?(Hash)
    steps = job["steps"]
    next unless steps.is_a?(Array)
    steps = steps.select { |step| step.is_a?(Hash) }
    toolchain_steps = steps.select { |step| step.fetch("uses", "").match?(%r{\Adtolnay/rust-toolchain@}) }
    if steps.any? { |step| step["run"].to_s.include?("cargo") } && toolchain_steps.length != 1
      abort("check_rust_toolchain_msrv: CI job #{job_id} runs cargo but installs " \
            "#{toolchain_steps.length} toolchains, so the compiler it uses is not declared")
    end
    toolchain_steps.each do |step|
      installed += 1
      inputs = step["with"]
      unless inputs.is_a?(Hash) && inputs.key?("toolchain")
        abort("check_rust_toolchain_msrv: CI job #{job_id} installs a rust toolchain without " \
              "naming one, so it takes the action's moving `stable` default")
      end
      requested = inputs.fetch("toolchain")
      if job_id == nightly_only
        unless requested.is_a?(String) && requested.match?(/\Anightly-[0-9]{4}-[0-9]{2}-[0-9]{2}\z/)
          abort("check_rust_toolchain_msrv: CI job #{job_id} must pin a dated nightly, found " \
                "#{requested.inspect}")
        end
      elsif requested != reference
        abort("check_rust_toolchain_msrv: CI job #{job_id} installs #{requested.inspect} instead " \
              "of the pinned #{reference.inspect} in rust-toolchain.toml")
      end
    end
  end
  abort("check_rust_toolchain_msrv: CI installs no rust toolchain at all") if installed.zero?

  # Enforce the exact same no-moving-toolchain and consistent-action-SHA contract across EVERY
  # workflow under .github/workflows/ (rustfs/gateway#1634).
  workflow_files = Dir.glob(File.join(workflows_dir, "*.yml")).sort
  abort("check_rust_toolchain_msrv: no workflow files found under .github/workflows") if workflow_files.empty?

  action_pins = Hash.new { |h, k| h[k] = Hash.new { |h2, k2| h2[k2] = [] } }
  workflow_files.each do |wf_path|
    wf_name = File.basename(wf_path)
    wf = YAML.safe_load(File.read(wf_path), permitted_classes: [], permitted_symbols: [], aliases: false)
    abort("check_rust_toolchain_msrv: #{wf_name} must be a mapping") unless wf.is_a?(Hash)
    wf_env = wf["env"].is_a?(Hash) ? wf["env"] : {}
    wf_jobs = wf["jobs"]
    abort("check_rust_toolchain_msrv: #{wf_name} jobs must be a mapping") unless wf_jobs.is_a?(Hash)

    wf_jobs.each do |job_id, job|
      next unless job.is_a?(Hash)
      steps = job["steps"]
      next unless steps.is_a?(Array)
      steps.each do |step|
        next unless step.is_a?(Hash)
        uses = step["uses"]
        if uses.is_a?(String)
          m = uses.match(%r{\A([^@\s]+)@([0-9a-f]{40})\z})
          unless m
            abort("check_rust_toolchain_msrv: #{wf_name} job #{job_id} uses unpinned action #{uses.inspect}")
          end
          action_ref, sha = m[1], m[2]
          repo = action_ref.split("/", 3)[0, 2].join("/")
          action_pins[repo][sha] << "#{wf_name}:#{job_id}"
        end

        next if wf_name == "ci.yml"
        next unless uses.is_a?(String) && uses.match?(%r{\Adtolnay/rust-toolchain@})

        inputs = step["with"]
        unless inputs.is_a?(Hash) && inputs.key?("toolchain")
          abort("check_rust_toolchain_msrv: #{wf_name} job #{job_id} installs a rust toolchain without " \
                "naming one, so it takes the action's moving `stable` default")
        end
        requested = inputs.fetch("toolchain").to_s
        if (m_env = requested.match(/\A\$\{\{\s*env\.([A-Z0-9_]+)\s*\}\}\z/))
          env_key = m_env[1]
          requested = wf_env.fetch(env_key).to_s
        end
        if wf_name == "fuzz-nightly.yml" && job_id == "fuzz"
          unless requested.match?(/\Anightly-[0-9]{4}-[0-9]{2}-[0-9]{2}\z/)
            abort("check_rust_toolchain_msrv: #{wf_name} job #{job_id} must pin a dated nightly, found #{requested.inspect}")
          end
        elsif requested != reference
          abort("check_rust_toolchain_msrv: #{wf_name} job #{job_id} installs #{requested.inspect} instead " \
                "of the pinned #{reference.inspect} in rust-toolchain.toml")
        end
      end
    end
  end

  action_pins.each do |repo, sha_map|
    next if sha_map.length <= 1
    details = sha_map.map { |sha, locs| "#{sha[0, 12]} (#{locs.first})" }.join(", ")
    abort("check_rust_toolchain_msrv: GitHub Action #{repo} pins drifted across workflows: #{details}")
  end
rescue KeyError, Psych::Exception => error
  abort("check_rust_toolchain_msrv: invalid CI workflow: #{error.message}")
end
RUBY
