#!/usr/bin/env bash
set -euo pipefail

# REQUIRES-BUILD

# Keeps #[handlers] optional and legible: public docs show the macro-free form,
# link-time registries stay forbidden, and the real expansion/equivalence tests
# prove that the macro neither mints public types nor rewrites method bodies.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_macro_governance: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v cargo >/dev/null 2>&1 || fail 'required command is missing: cargo'
[[ -x "${SCRIPT_DIR}/check_no_global_registry_deps.sh" ]] || \
    fail 'required guard is missing: scripts/check_no_global_registry_deps.sh'

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
source = root / "crates/macros/src/lib.rs"
mapping = root / "crates/macros/MAP.md"
for path in (source, mapping):
    if not path.is_file() or path.is_symlink():
        print(f"check_macro_governance: required input is missing or not a regular file: {path.relative_to(root)}", file=sys.stderr)
        raise SystemExit(1)

text = source.read_text()
parts = (
    "//! # The hand-written equivalent, which always works",
    "//! #[rustfs_gateway::handlers(group = objects)]",
    "//! impl Handler<PutObject> for Fs {",
    "//!         builder.handle::<PutObject, Self>(Arc::clone(this))",
)
if any(text.count(part) != 1 for part in parts):
    print("check_macro_governance: macro-free documentation pair is missing or ambiguous", file=sys.stderr)
    raise SystemExit(1)
if not (text.index(parts[0]) < text.index(parts[1]) < text.index(parts[3]) < text.index(parts[2])):
    print("check_macro_governance: macro-free documentation pair is not adjacent and ordered", file=sys.stderr)
    raise SystemExit(1)

map_text = mapping.read_text()
rows = {
    number: [line for line in map_text.splitlines() if line.startswith(f"| {number} |")]
    for number in (1, 2, 4)
}
if any(len(lines) != 1 or "`scripts/check_macro_governance.sh`" not in lines[0] for lines in rows.values()):
    print("check_macro_governance: crate map does not bind all three executable governance proofs", file=sys.stderr)
    raise SystemExit(1)
PY

GATEWAY_CHECK_ROOT="$ROOT_DIR" "${SCRIPT_DIR}/check_no_global_registry_deps.sh" >/dev/null

run_test() {
    local label="$1"
    shift
    local output rc=0
    output="$(
        cd "$ROOT_DIR" &&
            CARGO_TARGET_DIR="$ROOT_DIR/target/macro-governance" \
                cargo test --quiet -p rustfs-gateway-macros "$@" 2>&1
    )" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        printf '%s\n' "$output" >&2
        fail "$label"
    fi
}

run_test 'macro expansion governance tests failed' --lib
run_test 'macro/manual equivalence tests failed' --test equivalence

printf 'check_macro_governance: docs pair, no link magic, expansion shape and equivalence are proven\n'
