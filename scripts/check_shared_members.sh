#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_shared_members.sh
#
# WHAT THIS CHECKS
#   That every `crates/core/src/ops/shared/*.rs` module's `//! Members:` line
#   agrees, in both directions, with which operation modules actually `use` it:
#     - every operation named in `Members:` must `use` the module
#     - every operation that `use`s the module must be named in `Members:`
#
# WHY
#   The declaration is how a reader learns which operations share a rule, and it
#   is the thing that stops the List, Copy and Conditional clusters from growing
#   three private copies of one rule — the defect that had s3s emitting a quoted
#   ETag in one place and a bare one in another for eight revisions.
#
#   Until this script existed the rule was aspirational, and it had already
#   drifted: `precondition.rs` named seven operations while exactly one file in
#   the tree used it. The contract was written, reviewed, merged, and wired into
#   nothing, and no gate noticed for four commits. A declaration nobody checks
#   is a comment.
#
# HOW TO EXEMPT
#   There is no exemption. A module legitimately used by nobody yet should not
#   name members: leave `Members:` off entirely and the module is skipped, which
#   states "not wired" honestly instead of claiming a use that does not exist.
#
# USAGE
#   scripts/check_shared_members.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_shared_members.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

SHARED_DIR="crates/core/src/ops/shared"
OPS_DIR="crates/core/src/ops"

[[ -d "$SHARED_DIR" ]] || exit 0

python3 - "$SHARED_DIR" "$OPS_DIR" <<'PYEOF'
import pathlib
import re
import sys

shared_dir = pathlib.Path(sys.argv[1])
ops_dir = pathlib.Path(sys.argv[2])

# `GetObject` -> `get_object.rs`. The operation modules are the AWS operation
# name in snake_case, which is what makes this mapping mechanical.
def module_for(operation: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", operation).lower()
    return f"{snake}.rs"


status = 0

for module in sorted(shared_dir.glob("*.rs")):
    if module.name == "mod.rs":
        continue
    text = module.read_text()

    # `Members:` may wrap across several `//!` lines.
    match = re.search(r"^//! Members:(.*?)(?=^//! [A-Z]|^//!\s*$|^[^/])", text, re.M | re.S)
    if not match:
        continue
    declared = {
        name.strip()
        for name in match.group(1).replace("//!", " ").split(",")
        if name.strip()
    }
    if not declared:
        continue

    stem = module.stem
    actual = set()
    for op_file in ops_dir.glob("*.rs"):
        if op_file.name == "mod.rs":
            continue
        body = op_file.read_text()
        if re.search(rf"\bshared::{stem}\b", body) or re.search(rf"\buse .*shared::\{{[^}}]*\b{stem}\b", body):
            actual.add(op_file.name)

    expected = {module_for(name) for name in declared}

    claimed_not_using = sorted(expected - actual)
    using_not_claimed = sorted(actual - expected)

    if claimed_not_using:
        status = 1
        print(
            f"{module}: `Members:` names operations that do not use this module: "
            f"{', '.join(claimed_not_using)}",
            file=sys.stderr,
        )
        print(
            "    The contract is declared but not wired. Either call it from those "
            "operations, or stop naming them.",
            file=sys.stderr,
        )
    if using_not_claimed:
        status = 1
        print(
            f"{module}: used by operations absent from `Members:`: "
            f"{', '.join(using_not_claimed)}",
            file=sys.stderr,
        )
        print(
            "    A reader of the module cannot see who depends on it, which is how "
            "one rule becomes three copies.",
            file=sys.stderr,
        )

sys.exit(status)
PYEOF
