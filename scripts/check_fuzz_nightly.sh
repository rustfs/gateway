#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_fuzz_nightly.sh
#
# WHAT THIS CHECKS
#   The long-run fuzz lane (.github/workflows/fuzz-nightly.yml) fuzzes exactly the
#   targets fuzz/Cargo.toml registers, with the cargo-fuzz version and nightly
#   toolchain ci.yml pins, on a runner given a C++ compiler, and never on a pull
#   request.
#
# WHY
#   rustfs/backlog#1766 a-pf-0008. A target added to fuzz/Cargo.toml but not to
#   the matrix is never fuzzed for longer than its seed replay, and nothing would
#   say so; a second, drifting cargo-fuzz pin is the moving install
#   check_tool_versions_pinned.sh exists to prevent. libfuzzer-sys compiles
#   libFuzzer's C++ sources and the org runner image ships no `c++`: without
#   `--with-cxx` every target fails to build (run 36511088057), and the lane had
#   never passed before that was noticed.
#
# HOW TO EXEMPT
#   There is no exemption. Add the target to the matrix, or change both pins in
#   one diff.
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

job = (workflow["jobs"] || {})["fuzz"]
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
puts "OK: #{registered.length} fuzz targets run nightly on the pinned cargo-fuzz@#{pinned} and #{nightly_env['FUZZ_TOOLCHAIN']}"
RUBY
