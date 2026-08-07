#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_route_coverage.sh
#
# WHAT THIS CHECKS
#   That the set of protocol-known operations whose own `@http` selector is
#   claimed by a *different* operation's route row has not grown.
#
# WHY
#   The model declares 112 operations. Only the ones under `include` emit a
#   route row, so a deferred operation's request does not get refused — it falls
#   through first-match to whichever registered row matches next, and that
#   operation answers it with its own data.
#
#   This is not hypothetical and it is not only a read:
#
#     GET  /b/k?attributes   answered with GetObject's object body      (fixed)
#     PUT  /b/k?acl          writes the ACL document over the object    (live)
#
#   PutObject's predicates are `Method("PUT")` and `Target("Object")` and
#   nothing else, so a request meant to change permissions destroys the data
#   instead, and returns 200. A caller cannot tell.
#
#   The real fix is for codegen to emit a row per deferred operation from its
#   `@http` trait, so a known-but-unimplemented operation always claims its own
#   selector and answers NotImplemented. That is blocked on
#   `ShadowingPolicy::EveryOverlap` (issue #4), which would then demand hundreds
#   of shadowing declarations.
#
#   Until then this guard does the one thing that is still worth doing: it makes
#   the exposure a number, and makes that number monotonic. Every swallowed
#   request is listed in the allowance file with the operation that eats it.
#   Implementing an operation removes its line. Adding a new deferred operation
#   whose selector is shadowed fails this check until someone writes the line
#   down and, in writing it, notices.
#
#   An allowance file with entries in it is not an approval. It is a debt
#   register that cannot be paid down by forgetting.
#
# HOW TO EXEMPT
#   `scripts/allowances/route-coverage-allowances.txt`, one
#   `Operation -> SwallowedBy` per line. Regenerate the whole file with:
#     GATEWAY_WRITE_ROUTE_ALLOWANCES=1 scripts/check_route_coverage.sh
#   Read the diff before committing it — a line that disappears is progress, a
#   line that appears is a new exposure.
#
# USAGE
#   scripts/check_route_coverage.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_route_coverage.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

MODEL="model/s3.json"
ROUTES="generated/routes.rs"
OVERLAYS="model/overlays/ops"
ALLOWANCES="${ROOT_DIR}/scripts/allowances/route-coverage-allowances.txt"

# Deliberately not `|| exit 0`. Every other guard here skips when its input is
# absent, because its input is a directory that may not exist yet. These three
# always exist in a checkout, so their absence means this guard is running
# somewhere it cannot see what it is checking — and a check that quietly reports
# success when it did nothing is indistinguishable from one that passed. That is
# the same shape as the conformance harness that hard-coded its own outcome, and
# it was found here the same way: by a self-test that expected a failure and got
# a pass.
for input in "$MODEL" "$ROUTES"; do
    if [[ ! -f "$input" ]]; then
        printf 'check_route_coverage.sh: cannot read %s — refusing to report success without checking\n' \
            "$input" >&2
        exit 1
    fi
done
if [[ ! -d "$OVERLAYS" ]]; then
    printf 'check_route_coverage.sh: cannot read %s — refusing to report success without checking\n' \
        "$OVERLAYS" >&2
    exit 1
fi

python3 - "$MODEL" "$ROUTES" "$OVERLAYS" "$ALLOWANCES" <<'PYEOF'
import json
import pathlib
import re
import sys
import os

model_path, routes_path, overlays_dir, allowance_path = (pathlib.Path(a) for a in sys.argv[1:5])

# ---------------------------------------------------------------- the model
# Every operation the protocol has, with the selector it declares for itself.
model = json.loads(model_path.read_text())
selectors = {}
for shape_id, shape in model["shapes"].items():
    if shape.get("type") != "operation":
        continue
    http = shape.get("traits", {}).get("smithy.api#http")
    if not http:
        continue
    name = shape_id.split("#", 1)[1]
    uri = http["uri"]
    path, _, query = uri.partition("?")
    # `x-id=Operation` is an SDK disambiguator, not a routing constraint: it is
    # sent by AWS SDKs on requests that are already unambiguous, and no S3
    # implementation routes on it. Counting it would hide every collision.
    keys = {part.split("=", 1)[0] for part in query.split("&") if part and not part.startswith("x-id")}
    path = path.rstrip("/") or "/"
    if path == "/":
        target = "Service"
    elif path.count("/") == 1:
        target = "Bucket"
    else:
        target = "Object"
    selectors[name] = (http["method"], target, keys)

# ------------------------------------------------------------- the overlays
# `include` is what emits a row; `deferred` is known-but-unrouted. The two
# together are the whole model, and codegen already fails on an operation in
# neither — so reading only `deferred` here is sound.
deferred = set()
for overlay in sorted(pathlib.Path(overlays_dir).glob("*.toml")):
    text = overlay.read_text()
    for block in re.finditer(r"^\[\[deferred\]\](.*?)(?=^\[|\Z)", text, re.M | re.S):
        listing = re.search(r"operations\s*=\s*\[(.*?)\]", block.group(1), re.S)
        if listing:
            deferred.update(re.findall(r'"([A-Za-z0-9]+)"', listing.group(1)))

# --------------------------------------------------------- the route table
# Ordered: first match wins, so the order these are read in is the semantics.
rows = []
for row in re.finditer(r"RouteRow\s*\{(.*?)\n    \}", routes_path.read_text(), re.S):
    body = row.group(1)
    operation = re.search(r'operation:\s*"([^"]+)"', body)
    predicates = []
    for predicate in re.finditer(r'RoutePredicate::(\w+)\(([^)]*)\)', body):
        kind = predicate.group(1)
        args = re.findall(r'"([^"]*)"', predicate.group(2))
        predicates.append((kind, args))
    if operation:
        rows.append((operation.group(1), predicates))


def claims(predicates, method, target, keys):
    """Would this row match a request carrying exactly this method, target and query keys?

    A predicate this guard does not model is treated as *not* matching, which
    under-reports rather than over-reports. A guard that invents exposures gets
    switched off; one that misses some still holds the line on the ones it sees.
    """
    for kind, args in predicates:
        if kind == "Method":
            if args[0] != method:
                return False
        elif kind == "Target":
            if args[0] != target:
                return False
        elif kind == "QueryPresent":
            if args[0] not in keys:
                return False
        elif kind == "QueryEquals":
            if args[0] not in keys:
                return False
        else:
            return False
    return True


swallowed = []
for name in sorted(deferred):
    if name not in selectors:
        continue
    method, target, keys = selectors[name]
    for operation, predicates in rows:
        if operation == name:
            break
        if claims(predicates, method, target, keys):
            swallowed.append(f"{name} -> {operation}")
            break

observed = sorted(set(swallowed))

if os.environ.get("GATEWAY_WRITE_ROUTE_ALLOWANCES"):
    allowance_path.parent.mkdir(parents=True, exist_ok=True)
    allowance_path.write_text(
        "# Protocol-known operations whose own selector is claimed by another\n"
        "# operation's route row. Each line is a request that is answered by the\n"
        "# wrong operation, with that operation's data. See issue #16.\n"
        "#\n"
        "# This is a debt register, not an approval list. A line that disappears is\n"
        "# progress; a line that appears is a new exposure.\n"
        "#\n"
        "# Regenerate: GATEWAY_WRITE_ROUTE_ALLOWANCES=1 scripts/check_route_coverage.sh\n"
        + "".join(f"{line}\n" for line in observed)
    )
    print(f"wrote {len(observed)} entries to {allowance_path}")
    sys.exit(0)

allowed = set()
if allowance_path.is_file():
    for line in allowance_path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            allowed.add(line)

status = 0
for entry in observed:
    if entry not in allowed:
        status = 1
        operation, _, eater = entry.partition(" -> ")
        print(
            f"{operation}: its own selector is claimed by `{eater}`, which will answer "
            f"the request with its own data",
            file=sys.stderr,
        )

stale = sorted(allowed - set(observed))
if stale:
    status = 1
    for entry in stale:
        print(f"allowance no longer applies: {entry}", file=sys.stderr)
    print(
        "\nAn exposure was closed and the register was not updated. Regenerate with\n"
        "GATEWAY_WRITE_ROUTE_ALLOWANCES=1 scripts/check_route_coverage.sh — a stale\n"
        "allowance is how the count stops meaning anything.",
        file=sys.stderr,
    )

if status and not stale:
    print(
        "\nA deferred operation emits no route row, so first-match hands its request to\n"
        "whichever row matches next — and that operation answers with its own data.\n"
        "`PUT /b/k?acl` is currently a write of the ACL document over the object.\n"
        "Implement the operation, or record the exposure in\n"
        "scripts/allowances/route-coverage-allowances.txt and say so on issue #16.",
        file=sys.stderr,
    )

sys.exit(status)
PYEOF
