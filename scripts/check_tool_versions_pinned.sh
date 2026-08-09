#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_tool_versions_pinned.sh
#
# WHAT THIS CHECKS
#   The six non-toolchain Cargo tools named by rustfs/backlog#1743 have one
#   exact `tool@version` pin in the workflow, none uses `latest`, and the
#   rejected `cargo-binstall` installer is absent from workflow and manifests.
#
# WHY
#   Tool versions are build inputs. A moving install turns an unchanged commit
#   red without a reviewable repository diff, while scattered pins let jobs
#   silently disagree about which policy they enforce.
#
# HOW TO EXEMPT
#   Not applicable. Update the central workflow pins in one reviewed diff.
#
# USAGE
#   scripts/check_tool_versions_pinned.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_tool_versions_pinned.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$ROOT_DIR" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
workflow = root / ".github/workflows/ci.yml"
if not workflow.is_file():
    print("check_tool_versions_pinned.sh: required input is missing: .github/workflows/ci.yml", file=sys.stderr)
    raise SystemExit(1)

text = workflow.read_text()
expected = {
    "CARGO_SEMVER_CHECKS_TOOL": "cargo-semver-checks",
    "CARGO_HACK_TOOL": "cargo-hack",
    "CARGO_LLVM_COV_TOOL": "cargo-llvm-cov",
    "CARGO_DENY_TOOL": "cargo-deny",
    "CARGO_PUBLIC_API_TOOL": "cargo-public-api",
    "CARGO_FUZZ_TOOL": "cargo-fuzz",
}
failures = []
for key, tool in expected.items():
    matches = re.findall(rf"(?m)^\s{{2}}{re.escape(key)}:\s*['\"]?([^\s'\"]+)['\"]?\s*$", text)
    if len(matches) != 1:
        failures.append(f"{key} must appear exactly once in the workflow env block")
    elif not re.fullmatch(rf"{re.escape(tool)}@[0-9]+\.[0-9]+\.[0-9]+", matches[0]):
        failures.append(f"{key} must be {tool}@<exact-semver>, found {matches[0]}")

# There is deliberately no broad repository grep here: generated output and the
# pinned model are do-not-read paths. These are every location that can declare
# a build dependency or install a CI tool.
inputs = [workflow, root / "Cargo.toml", root / "xtask/Cargo.toml"]
inputs.extend((root / "crates").glob("*/Cargo.toml"))
vendor = root / "vendor"
if vendor.is_dir():
    inputs.extend(vendor.rglob("Cargo.toml"))

rejected = "cargo-" + "binstall"
for path in inputs:
    if path.is_file() and rejected in path.read_text():
        failures.append(f"{path.relative_to(root)} names {rejected}, which is not an approved installer")

if failures:
    for failure in failures:
        print(f"check_tool_versions_pinned.sh: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("OK: 6/6 CI tools pinned, no latest and no cargo-binstall")
PY
