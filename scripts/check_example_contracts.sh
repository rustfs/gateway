#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Every Rust example is an explicit Cargo target and contains no unwrap/expect call.
# WHY
#   Examples are public copy-paste API: implicit target discovery and panic-shaped error handling
#   can disappear or spread without a compile-time failure in the consumer-facing path.
# HOW TO EXEMPT
#   There is no exemption. Declare the target and propagate recoverable errors with `?`.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
examples = sorted(root.glob("crates/*/examples/*.rs"))
if not examples:
    raise SystemExit("check_example_contracts: no Rust examples found")

failures = []
for example in examples:
    manifest_path = example.parent.parent / "Cargo.toml"
    if not manifest_path.is_file():
        failures.append(f"{example.relative_to(root)}: owning Cargo.toml is missing")
        continue
    manifest = manifest_path.read_text()
    sections = re.findall(r"(?ms)^\[\[example\]\]\s*(.*?)(?=^\[|\Z)", manifest)
    declared = set()
    for section in sections:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', section)
        if name:
            declared.add(name.group(1))
    if example.stem not in declared:
        failures.append(f"{example.relative_to(root)}: target is not explicitly declared in {manifest_path.relative_to(root)}")

    source = example.read_text()
    panic_call = re.search(r"(?:\.|::)(?:unwrap|expect)\s*\(", source)
    if panic_call:
        line = source.count("\n", 0, panic_call.start()) + 1
        failures.append(f"{example.relative_to(root)}:{line}: examples must propagate recoverable errors instead of panicking")

if failures:
    print("\n".join(f"check_example_contracts: {failure}" for failure in failures), file=sys.stderr)
    raise SystemExit(1)

print(f"OK: {len(examples)} Rust example target(s) are explicit and panic-free")
PY
