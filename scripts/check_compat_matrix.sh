#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_compat_matrix.sh
#
# WHAT THIS CHECKS
#   Six properties of the compatibility manifest that can be judged without running any client:
#
#     1. The known-failure list only ever shrinks. Every entry in `compat/known-fail.txt` was
#        already in the committed version. Adding one is how a regression gets silenced in the same
#        change that introduced it, so adding one fails here. The ratchet starts per client row:
#        an entry for a client that `compat/versions.toml` did not declare in the comparison commit
#        is that client's first measured baseline, not a silenced regression, and is admitted. The
#        only list with no ratchet is one the comparison commit did not have at all: a list that
#        exists but is empty, because every excused failure was fixed, admits nothing new either.
#     2. Every known-failure entry names a client that exists in `compat/versions.toml` and a
#        scenario that exists under `compat/scenarios/`. An entry naming neither excuses nothing and
#        would sit there forever.
#     3. `compat/matrix.json` is internally consistent: its summary counts equal its own cells, and
#        the KNOWN / REGRESSION / FIXED verdicts on those cells agree with the known-failure list.
#        This is what makes a hand-edited manifest fail without a full matrix run — it is a
#        generated artefact, and the counts in it are the part a hand edit gets wrong.
#     4. Every declared client has an executable driver, and every driver belongs to a declared
#        client. A driver nobody runs, or a client with no driver, is a row of the published table
#        that measures nothing.
#     5. The matrix workflow is cron and manual dispatch only. A full run is tens of minutes and
#        the pull-request gate budget is ten (AGENTS.md, "CI budget"), so attaching it to
#        `pull_request` fails here rather than on the day the gate goes over.
#     6. The manifest says what answered it (`measured_against`), and the two skip statuses stay
#        apart: `client-unsupported` (the client cannot express the scenario) and `sut-unregistered`
#        (the server does not serve an operation it needs), each with a reason and its own count.
#        When an external endpoint answered and it is RustFS — declared so, or naming itself so in
#        its `Server` header — `sut-unregistered` must be zero: a RustFS candidate serves every
#        operation the matrix needs (rustfs/backlog#2758).
#
# USAGE
#   scripts/check_compat_matrix.sh                    # the committed compat/matrix.json
#   scripts/check_compat_matrix.sh --matrix <file>    # a manifest a run produced, e.g. an
#                                                     # external run's target/compat/matrix.json
#
# WHY
#   Compatibility is an external promise. `rustfs/backlog#1765` §4.5: the manifest is baseline-aware
#   with the same KNOWN / REGRESSION / FIXED semantics the conformance baseline uses, and the list
#   of excused failures is a ratchet.
#
# HOW TO EXEMPT
#   There is no exemption. Fix the client gap and remove the line.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_compat_matrix: %s\n' "$*" >&2
    exit 1
}

MATRIX="$ROOT_DIR/compat/matrix.json"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --matrix)
        MATRIX="${2:?--matrix requires a path}"
        shift 2
        ;;
    *)
        fail "unknown argument $1"
        ;;
    esac
done

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_compat_matrix)" || exit 1
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -f "$ROOT_DIR/compat/known-fail.txt" ]] || fail 'required input is missing: compat/known-fail.txt'
[[ -f "$MATRIX" ]] || fail "required input is missing: ${MATRIX#"$ROOT_DIR"/}"
[[ -f "$ROOT_DIR/compat/versions.toml" ]] || fail 'required input is missing: compat/versions.toml'
[[ -f "$ROOT_DIR/.github/workflows/client-matrix.yml" ]] || fail 'required input is missing: .github/workflows/client-matrix.yml'

previous="$(mktemp "${TMPDIR:-/tmp}/gateway-known-fail.XXXXXX")"
previous_versions="$(mktemp "${TMPDIR:-/tmp}/gateway-versions.XXXXXX")"
trap 'rm -f "$previous" "$previous_versions"' EXIT

# Before a commit, compare the working file with HEAD. In CI, actions/checkout checks out the
# pull-request merge commit, so HEAD^ is the base branch and the comparison covers the whole
# pull request rather than only its last commit.
baseline_ref="HEAD^"
if ! git -C "$ROOT_DIR" diff --quiet HEAD -- compat/known-fail.txt; then
    baseline_ref="HEAD"
fi
previous_state="present"
if ! git -C "$ROOT_DIR" show "${baseline_ref}:compat/known-fail.txt" >"$previous" 2>/dev/null; then
    # The file did not exist in the comparison commit, which is true exactly once: the pull request
    # that introduces it. Every entry is new then, and the ratchet check below is skipped for that
    # commit alone. An existing list that is empty is not that case: it keeps its ratchet.
    : >"$previous"
    previous_state="missing"
    printf 'check_compat_matrix: compat/known-fail.txt is new in %s; the ratchet starts here\n' "$baseline_ref"
fi

# The clients the comparison commit declared. A client absent there is new in this change, and its
# first known failures start its row of the ratchet. When the file cannot be read, every current
# client counts as old: the exemption fails closed.
if ! git -C "$ROOT_DIR" show "${baseline_ref}:compat/versions.toml" >"$previous_versions" 2>/dev/null; then
    cp "$ROOT_DIR/compat/versions.toml" "$previous_versions"
fi

"$PYTHON" - "$ROOT_DIR" "$previous" "$previous_versions" "$previous_state" "$MATRIX" <<'PY'
import json
import re
import sys
import tomllib
from pathlib import Path

root, previous, previous_versions = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
# Whether the comparison commit had a known-failure list at all. Only its absence waives the
# ratchet; an empty list is a list, and a fully fixed one must not reopen (rustfs/gateway#1073).
previous_present = sys.argv[4] == "present"
matrix_path = Path(sys.argv[5])
failures = []


ISSUE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+#[0-9]+")


def parse(text, source=None):
    entries = {}
    for number, line in enumerate(text.splitlines(), start=1):
        # A comment starts the line. `#` cannot introduce a trailing comment here, because every
        # entry's issue reference contains one.
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 2)
        if source is not None:
            if len(parts) < 3:
                failures.append(f"{source}:{number} is not `<client>/<scenario> <issue> <reason>`")
                continue
            if not ISSUE.fullmatch(parts[1]):
                failures.append(
                    f"{source}:{number} excuses {parts[0]} without an <owner>/<repo>#<number> issue; "
                    "an excused failure nobody owns is a permanent one"
                )
        entries[parts[0]] = {"issue": parts[1] if len(parts) > 2 else "", "reason": parts[2] if len(parts) > 2 else ""}
    return entries


current = parse((root / "compat/known-fail.txt").read_text(encoding="utf-8"), "compat/known-fail.txt")
before = parse(previous.read_text(encoding="utf-8"))

added = sorted(set(current) - set(before))
declared_before = set(tomllib.loads(previous_versions.read_text(encoding="utf-8")).get("clients", {}))
if added and previous_present:
    for cell in added:
        if cell.partition("/")[0] not in declared_before:
            print(f"check_compat_matrix: {cell} starts the baseline of a client this change adds")
            continue
        failures.append(f"compat/known-fail.txt gained {cell}; the list may only shrink")

clients = set(tomllib.loads((root / "compat/versions.toml").read_text(encoding="utf-8")).get("clients", {}))
scenarios = {path.stem for path in (root / "compat/scenarios").glob("*.yaml")}
for cell in sorted(current):
    client, _, scenario = cell.partition("/")
    if client not in clients:
        failures.append(f"compat/known-fail.txt names client {client!r}, which compat/versions.toml does not declare")
    if scenario not in scenarios:
        failures.append(f"compat/known-fail.txt names scenario {scenario!r}, which compat/scenarios/ does not define")

for client in sorted(clients):
    driver = root / "compat/drivers" / client / "run.sh"
    if not driver.is_file():
        failures.append(f"client {client} has no driver at compat/drivers/{client}/run.sh")
    elif not driver.stat().st_mode & 0o111:
        failures.append(f"compat/drivers/{client}/run.sh is not executable")
for driver in sorted((root / "compat/drivers").glob("*/run.sh")):
    if driver.parent.name not in clients:
        failures.append(f"{driver.parent.name} has a driver but is not declared in compat/versions.toml")

matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
# Named as given, so a manifest checked with --matrix is the one the diagnostics name.
try:
    label = str(matrix_path.resolve().relative_to(root.resolve()))
except ValueError:
    label = str(matrix_path)

# What answered the rows. `gateway-fs` is the launcher, named in full by the sut block below; an
# external endpoint's own `Server` header is recorded (null when it sent none — an observation, while
# an absent key is none), and so is the product it was declared to be.
against = matrix.get("measured_against")
external = False
rustfs_endpoint = False
if not isinstance(against, dict):
    failures.append(f"{label} has no measured_against block saying what answered it")
elif against.get("sut") == "gateway-fs":
    pass
elif against.get("sut") == "external":
    external = True
    product = str(against.get("product") or "").strip()
    if not product:
        failures.append(
            f"{label} was measured against an external endpoint but names no product; the "
            "RustFS rule keys on it, so a missing product would switch that rule off"
        )
    if "endpoint_build" not in against:
        failures.append(f"{label} was measured against an external endpoint and records no endpoint_build")
    build = str(against.get("endpoint_build") or "")
    names_rustfs = build.lower().startswith("rustfs")
    if names_rustfs and product and product != "rustfs":
        failures.append(
            f"{label} declares the external endpoint as {product!r}, but its Server header names "
            f"RustFS ({build!r}); declare it as rustfs"
        )
    rustfs_endpoint = product == "rustfs" or names_rustfs
else:
    failures.append(f"{label} measured_against names an unknown system under test {against.get('sut')!r}")

# The manifest must say what answered it. A compatibility row whose system under test is unnamed
# cannot be re-measured, and a provisional one that stops saying so silently becomes a claim about
# a server nobody checked.
sut = matrix.get("sut")
if not isinstance(sut, dict):
    failures.append(f"{label} has no sut block")
else:
    for field in ("name", "version", "commit", "generation", "binary", "package", "assembly"):
        if not sut.get(field):
            failures.append(f"{label} sut block has no {field}")
    if sut.get("provisional") and not str(sut.get("provisional_reason", "")).strip():
        failures.append(f"{label} marks the system under test provisional with no reason")
counted = {"pass": 0, "fail": 0, "client-unsupported": 0, "sut-unregistered": 0}
skips = ("client-unsupported", "sut-unregistered")
unregistered_cells = []
verdicts = {"known": 0, "regression": 0, "fixed": 0, "stale": 0}
for client in matrix.get("clients", []):
    for row in client.get("scenarios", []):
        status = row.get("status")
        if status not in counted:
            failures.append(f"{label} records an unknown status {status!r} for {client['name']}/{row.get('id')}")
            continue
        counted[status] += 1
        cell = f"{client['name']}/{row['id']}"
        expected = None
        if status == "fail":
            expected = "KNOWN" if cell in current else "REGRESSION"
        elif cell in current:
            expected = "FIXED" if status == "pass" else "STALE"
        if row.get("verdict") != expected:
            failures.append(
                f"{label} records verdict {row.get('verdict')!r} for {cell} where the "
                f"known-failure list implies {expected!r}"
            )
        if expected:
            verdicts[expected.lower()] += 1
        # A skip must be a skip with a reason. A skipped row whose reason is empty is
        # indistinguishable from a pass to anything that reads only the status.
        if status in skips and not (row.get("detail") or "").strip():
            failures.append(f"{label} records {cell} as {status} with no reason")
        if status == "sut-unregistered":
            unregistered_cells.append(cell)
        # A known failure carries its owning issue in the manifest, not only in the excuse list.
        if expected == "KNOWN" and row.get("issue") != current[cell]["issue"]:
            failures.append(
                f"{label} records issue {row.get('issue')!r} for {cell} where "
                f"compat/known-fail.txt names {current[cell]['issue']!r}"
            )
        if status == "fail" and expected == "REGRESSION" and row.get("issue"):
            failures.append(f"{label} attributes an unexcused failure {cell} to an issue")

summary = matrix.get("summary", {})
for key, value in list(counted.items()) + list(verdicts.items()):
    if summary.get(key) != value:
        failures.append(f"{label} summary says {key}={summary.get(key)}, its own cells say {value}")

if external and rustfs_endpoint and unregistered_cells:
    failures.append(
        f"{label} was measured against an external RustFS endpoint, which must register every "
        f"operation the matrix needs; sut-unregistered is {len(unregistered_cells)}, not 0: "
        + ", ".join(unregistered_cells)
    )

workflow = (root / ".github/workflows/client-matrix.yml").read_text(encoding="utf-8")
triggers = re.search(r"(?m)^on:\n((?:[ \t]+.*\n|\n)*)", workflow)
if not triggers:
    failures.append(".github/workflows/client-matrix.yml declares no trigger block")
else:
    declared = re.findall(r"(?m)^ {2}([a-z_]+):", triggers.group(1))
    forbidden = sorted(set(declared) - {"schedule", "workflow_dispatch"})
    if forbidden:
        failures.append(
            f".github/workflows/client-matrix.yml is triggered by {forbidden}; the matrix is cron and "
            "manual dispatch only, because a full run does not fit the ten-minute gate budget"
        )
    if "schedule" not in declared:
        failures.append(".github/workflows/client-matrix.yml has no schedule; a matrix nobody runs measures nothing")

if failures:
    for line in failures:
        print(f"check_compat_matrix: {line}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"OK: known-fail {len(current)} <= previous {len(before) if before else len(current)}, "
    f"matrix {counted['pass']} pass / {counted['fail']} fail / {counted['client-unsupported']} client-unsupported / "
    f"{counted['sut-unregistered']} sut-unregistered against {(against or {}).get('sut')}"
)
PY
