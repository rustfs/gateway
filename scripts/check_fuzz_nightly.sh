#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_fuzz_nightly.sh
#
# WHAT THIS CHECKS
#   1. The long-run fuzz lane (.github/workflows/fuzz-nightly.yml) fuzzes
#      exactly the targets fuzz/Cargo.toml registers, with the cargo-fuzz
#      version and nightly toolchain ci.yml pins, on a runner given a C++
#      compiler, and never on a pull request or push.
#   2. The companion `rustfs-endpoint-replay` job replays both `decode_diff`
#      and `encode_diff` corpora out-of-process over `--endpoint` against a
#      live RustFS candidate (never in-process), restores both cached corpora,
#      and uploads crash artifacts on failure (rustfs/backlog#2781).
#
# WHY
#   rustfs/backlog#1766 a-pf-0008 and rustfs/backlog#2781. A target added to
#   fuzz/Cargo.toml but not to the matrix is never fuzzed for longer than its
#   seed replay, and nothing would say so; a second, drifting cargo-fuzz pin is
#   the moving install check_tool_versions_pinned.sh exists to prevent.
#   libfuzzer-sys compiles libFuzzer's C++ sources and the org runner image
#   ships no `c++`: without `--with-cxx` every target fails to build (run
#   36511088057). Without the endpoint-replay guard, the candidate replay job
#   could quietly lose `--endpoint`, drop one of the two diff targets, or omit
#   crash artifact upload.
#
# HOW TO EXEMPT
#   There is no exemption. Add the target to the matrix, keep both pins aligned,
#   and preserve the out-of-process RustFS candidate replay job.
# =============================================================================

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

ruby -ryaml - "$ROOT" <<'RUBY'
root = ARGV.fetch(0)
def fail_check(message)
  abort("check_fuzz_nightly: #{message}")
end
paths = {
  nightly: File.join(root, ".github/workflows/fuzz-nightly.yml"),
  ci: File.join(root, ".github/workflows/ci.yml"),
  manifest: File.join(root, "fuzz/Cargo.toml"),
}
paths.each { |_, path| fail_check("required input is missing: #{path.delete_prefix("#{root}/")}") unless File.file?(path) }

registered = File.read(paths[:manifest], encoding: "UTF-8").scan(/^\[\[bin\]\]\s*\nname\s*=\s*"([^"]+)"/).flatten.sort
fail_check("fuzz/Cargo.toml registers no target") if registered.empty?

workflow = YAML.load_file(paths[:nightly])
triggers = workflow["on"] || workflow[true] || {}
names = triggers.is_a?(Hash) ? triggers.keys.map(&:to_s) : Array(triggers).map(&:to_s)
%w[pull_request pull_request_target push].each do |event|
  fail_check("fuzz-nightly.yml must not run on #{event}; the long-run lane is outside the PR gate") if names.include?(event)
end
fail_check("fuzz-nightly.yml must keep its schedule") unless names.include?("schedule")

jobs = workflow["jobs"] || {}
job = jobs["fuzz"]
fail_check("fuzz-nightly.yml has no fuzz job") unless job.is_a?(Hash)
matrix = job.dig("strategy", "matrix", "target")
fail_check("the fuzz job has no target matrix") unless matrix.is_a?(Array)
missing = registered - matrix
extra = matrix - registered
fail_check("registered targets never fuzzed nightly: #{missing.join(', ')}") unless missing.empty?
fail_check("matrix names targets fuzz/Cargo.toml does not register: #{extra.join(', ')}") unless extra.empty?
fail_check("the matrix lists a target twice") unless matrix.uniq.length == matrix.length

installs = Array(job["steps"]).map { |step| step.is_a?(Hash) ? step["run"].to_s : "" }
                              .select { |run| run.include?("scripts/ci_install_host_tools.sh") }
unless installs.length == 1 && installs.first.split.include?("--with-cxx")
  fail_check("the fuzz job must run scripts/ci_install_host_tools.sh --with-cxx once: " \
             "libfuzzer-sys builds libFuzzer from C++ and the runner image has no c++")
end

replay = jobs["rustfs-endpoint-replay"]
fail_check("fuzz-nightly.yml has no rustfs-endpoint-replay job (rustfs/backlog#2781)") unless replay.is_a?(Hash)
replay_needs = Array(replay["needs"]).map(&:to_s)
unless replay_needs.include?("fuzz")
  fail_check("rustfs-endpoint-replay must depend on the fuzz job so cached corpora are populated first")
end

replay_steps = Array(replay["steps"]).select { |step| step.is_a?(Hash) }
replay_runs = replay_steps.map { |step| step["run"].to_s }.join("\n")
unless replay_steps.any? { |step| step["uses"].to_s.start_with?("actions/checkout@") && step.dig("with", "repository") == "rustfs/rustfs" }
  fail_check("rustfs-endpoint-replay must check out the rustfs/rustfs candidate repository")
end
unless replay_runs.include?("fuzz-endpoint-replay") && replay_runs.include?("--endpoint")
  fail_check("rustfs-endpoint-replay must invoke fuzz-endpoint-replay with --endpoint (not in-process)")
end
%w[decode_diff encode_diff].each do |target|
  unless replay_runs.match?(/--target\s+#{Regexp.escape(target)}\b/)
    fail_check("rustfs-endpoint-replay must replay --target #{target} against --endpoint")
  end
  unless replay_runs.include?("fuzz/corpus/#{target}") && replay_runs.include?("fuzz/seeds/#{target}")
    fail_check("rustfs-endpoint-replay must pass both fuzz/corpus/#{target} and fuzz/seeds/#{target}")
  end
  restored = replay_steps.any? do |step|
    step["uses"].to_s.start_with?("actions/cache") && step.dig("with", "path").to_s == "fuzz/corpus/#{target}"
  end
  unless restored
    fail_check("rustfs-endpoint-replay must restore the cached fuzz/corpus/#{target} corpus")
  end
end
unless replay_runs.include?("candidate/rustfs/target/debug/rustfs")
  fail_check("rustfs-endpoint-replay must launch the out-of-process RustFS candidate binary")
end
%w[build-essential cmake pkg-config libssl-dev protobuf-compiler flatbuffers-compiler].each do |pkg|
  unless replay_runs.match?(/\b#{Regexp.escape(pkg)}\b/)
    fail_check("rustfs-endpoint-replay must install #{pkg} before building the RustFS candidate (run 45575867039)")
  end
end
upload_step = replay_steps.find do |step|
  step["uses"].to_s.start_with?("actions/upload-artifact@") && step["if"].to_s.include?("failure()")
end
if upload_step.nil?
  fail_check("rustfs-endpoint-replay must upload crash artifacts on failure()")
end

ci = File.read(paths[:ci], encoding: "UTF-8")
pinned = ci[/^\s{2}CARGO_FUZZ_TOOL:\s*cargo-fuzz@([0-9.]+)\s*$/, 1]
fail_check("ci.yml has no CARGO_FUZZ_TOOL pin") if pinned.nil?
nightly_env = workflow["env"] || {}
unless nightly_env["CARGO_FUZZ_VERSION"].to_s == pinned
  fail_check("CARGO_FUZZ_VERSION is #{nightly_env['CARGO_FUZZ_VERSION'].inspect}; ci.yml pins cargo-fuzz@#{pinned}")
end
toolchains = ci.scan(/^\s+toolchain:\s*(nightly-[0-9]{4}-[0-9]{2}-[0-9]{2})\s*$/).flatten.uniq
unless toolchains.include?(nightly_env["FUZZ_TOOLCHAIN"].to_s)
  fail_check("FUZZ_TOOLCHAIN is #{nightly_env['FUZZ_TOOLCHAIN'].inspect}; ci.yml pins #{toolchains.join(', ')}")
end
puts "OK: #{registered.length} fuzz targets run nightly on the pinned cargo-fuzz@#{pinned} and #{nightly_env['FUZZ_TOOLCHAIN']}, with RustFS candidate --endpoint replay for decode_diff and encode_diff"
RUBY
