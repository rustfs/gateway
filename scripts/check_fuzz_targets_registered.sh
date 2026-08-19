#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_fuzz_targets_registered.sh
#
# WHAT THIS CHECKS
#   That every file in `fuzz/fuzz_targets/` is a fuzz target the tooling will
#   actually build, and that every `[[bin]]` in `fuzz/Cargo.toml` names a file
#   that exists. Three properties:
#
#     1. Registered   — one `[[bin]]` per target file, its `name` equal to the
#                       file stem and its `path` equal to the file.
#     2. Backed       — no `[[bin]]` pointing at a file that is not there.
#     3. Still a fuzz target — each file declares `#![no_main]` and invokes
#                       `fuzz_target!`. A target that lost either one compiles
#                       to a binary that fuzzes nothing.
#
# WHY
#   `ci.yml` defers the fuzz job on purpose: a full run does not fit the ten
#   minute PR gate. That decision is right and it has a consequence — nothing in
#   CI compiles this crate, so an unregistered target is invisible. A fuzz file
#   sitting in the tree unbuilt reads exactly like one that runs clean, which is
#   the shape this repository has now produced eight times. This guard costs
#   milliseconds and closes the cheap half of it: the target is at least wired
#   up and still a target.
#
#   It does not claim to compile anything. `cargo +nightly fuzz build` is what
#   proves that, and it is run by hand with its output recorded in the PR.
#
# HOW TO EXEMPT
#   Not applicable. Add the `[[bin]]`, or delete the file.
#
# USAGE
#   scripts/check_fuzz_targets_registered.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_fuzz_targets_registered.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

MANIFEST="fuzz/Cargo.toml"
TARGETS="fuzz/fuzz_targets"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_fuzz_targets_registered.sh: required command is missing: python3\n' >&2
    exit 1
}

# Deliberately not `|| exit 0`. Both inputs exist in every checkout; an absent
# one means this guard cannot see what it checks, and reporting success then is
# indistinguishable from having checked.
if [[ ! -f "$MANIFEST" ]]; then
    printf 'check_fuzz_targets_registered.sh: cannot read %s — refusing to report success without checking\n' \
        "$MANIFEST" >&2
    exit 1
fi
if [[ ! -d "$TARGETS" ]]; then
    printf 'check_fuzz_targets_registered.sh: cannot read %s — refusing to report success without checking\n' \
        "$TARGETS" >&2
    exit 1
fi

python3 - "$MANIFEST" "$TARGETS" <<'PYEOF'
import pathlib
import re
import sys

manifest_path, targets_dir = (pathlib.Path(a) for a in sys.argv[1:3])

status = 0


def bad(message):
    global status
    status = 1
    print(f"check_fuzz_targets_registered: {message}", file=sys.stderr)


text = manifest_path.read_text(encoding="utf-8")
declared = {}
for block in re.split(r"(?m)^\[\[bin\]\]\s*$", text)[1:]:
    block = re.split(r"(?m)^\[", block)[0]
    name = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
    path = re.search(r'(?m)^\s*path\s*=\s*"([^"]+)"', block)
    if name is None or path is None:
        bad(f"{manifest_path}: a [[bin]] section is missing `name` or `path`")
        continue
    declared[name.group(1)] = path.group(1)

if not declared:
    bad(f"{manifest_path}: declares no [[bin]]; every fuzz target would be unbuilt")

files = sorted(p for p in targets_dir.glob("*.rs"))
if not files:
    bad(f"{targets_dir}: holds no target; the comparison would be vacuous")

for file in files:
    stem = file.stem
    if stem not in declared:
        bad(
            f"{file}: no [[bin]] in {manifest_path} names it. `cargo fuzz` builds what the "
            "manifest declares, so an unregistered target never runs and never says so"
        )
    elif manifest_path.parent / declared[stem] != file:
        bad(f"{manifest_path}: [[bin]] {stem!r} has path {declared[stem]!r}, but the file is {file}")
    body = file.read_text(encoding="utf-8")
    if "#![no_main]" not in body:
        bad(f"{file}: no `#![no_main]`; libFuzzer supplies main, and without it this is a plain binary")
    if not re.search(r"\bfuzz_target!\s*\(", body):
        bad(f"{file}: invokes no `fuzz_target!`; it builds, runs nothing, and reports no failure")

for name, path in sorted(declared.items()):
    if not (manifest_path.parent / path).is_file():
        bad(f"{manifest_path}: [[bin]] {name!r} points at {path!r}, which does not exist")

sys.exit(status)
PYEOF
