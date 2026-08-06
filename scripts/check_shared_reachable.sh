#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_shared_reachable.sh
#
# WHAT THIS CHECKS
#   That every `pub` item under `crates/core/src/ops/shared/` is re-exported by
#   the `rustfs-gateway` facade.
#
# WHY
#   A shared contract exists so that two operations cannot drift apart. A
#   backend lives outside this workspace and can only reach what the facade
#   exports — so a contract that is not exported is a contract every backend
#   reimplements, which is the drift it was written to prevent.
#
#   This has now happened three times, and each one cost real defects:
#
#     copy_source   the conformance fixture mirrored CopySource and
#                   authorize_source by hand. GHSA-mx42 and GHSA-wfxj were both
#                   a second implementation forgetting the check the first made.
#     precondition  the mirror got strong/weak comparison wrong, evaluated
#                   existence before the condition, and missed If-Match
#                   suppressing If-Modified-Since — four RFC 9110 rules
#                   re-derived and re-broken next to a correct implementation.
#     Checksummer   uncallable outside the workspace, so the fixture vendored
#                   its own CRC32.
#
#   Three instances is the point at which a rule stops being someone's job to
#   remember.
#
# HOW TO EXEMPT
#   `scripts/allowances/shared-reachable-allowances.txt`, one `module::Item` per
#   line with the reason. An item genuinely internal to the shared module should
#   not be `pub` in the first place — prefer `pub(crate)`, which this guard
#   ignores.
#
# USAGE
#   scripts/check_shared_reachable.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_shared_reachable.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

SHARED_DIR="crates/core/src/ops/shared"
FACADE="crates/gateway/src/lib.rs"
ALLOWANCES="${SCRIPT_DIR}/allowances/shared-reachable-allowances.txt"

[[ -d "$SHARED_DIR" && -f "$FACADE" ]] || exit 0

python3 - "$SHARED_DIR" "$FACADE" "$ALLOWANCES" <<'PYEOF'
import pathlib
import re
import sys

shared_dir = pathlib.Path(sys.argv[1])
facade = pathlib.Path(sys.argv[2]).read_text()
allowance_file = pathlib.Path(sys.argv[3])

allowed = set()
if allowance_file.is_file():
    for line in allowance_file.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            allowed.add(line)

# `pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub const`, `pub type`.
# `pub(crate)` and `pub(super)` are deliberately not matched: they say "internal".
declaration = re.compile(r"^pub (?:fn|struct|enum|trait|const|type)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)

status = 0
for module in sorted(shared_dir.glob("*.rs")):
    if module.name == "mod.rs":
        continue
    for item in sorted(set(declaration.findall(module.read_text()))):
        qualified = f"{module.stem}::{item}"
        if qualified in allowed:
            continue
        # The facade may name it in a braced re-export list or on its own line.
        if re.search(rf"\b{re.escape(item)}\b", facade):
            continue
        status = 1
        print(
            f"{module}: `{item}` is public but the facade does not re-export it",
            file=sys.stderr,
        )

if status:
    print(
        "\nA backend can only reach what `rustfs-gateway` exports. An unexported contract\n"
        "is one every backend reimplements — which is the drift the contract exists to\n"
        "prevent, and it has already produced four wrong RFC 9110 rules once.\n"
        "Export it, make it `pub(crate)`, or record why in\n"
        "scripts/allowances/shared-reachable-allowances.txt.",
        file=sys.stderr,
    )

sys.exit(status)
PYEOF
