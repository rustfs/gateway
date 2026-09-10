#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Every workspace member that ships integration tests is accounted for: either a named
#   consolidation guard holds it in one Cargo test target, or it carries a written exception row
#   naming the crate, the number of targets it costs today, a tracking issue, and a reason.
# WHY
#   rustfs/gateway#277. scripts/check_test_target_consolidation.sh opens with "There are no
#   exemptions" and then covers three crates by name, so every other member was exempt by omission
#   and nothing said so. `crates/server` did not slip past that guard — it landed two days before
#   it and was simply never listed. A guard that names the crates it protects can only protect the
#   crates somebody remembered, and the omission is invisible by construction.
#
#   The survey on that issue makes the case better than the argument does: it was written by hand
#   over `crates/*` and reported 22 uncovered targets, and it missed `spikes/ext-field` — a
#   workspace member with three more. This guard reads the member list instead, so the next member
#   cannot be missed by whoever is counting.
# HOW TO EXEMPT
#   Add a row to EXCEPTIONS below with the crate directory, its current target count, a tracking
#   issue and a reason. The row is a debt record, not a waiver: the recorded count is a ratchet, so
#   a new loose test file in an excepted crate fails until the number is updated deliberately, and
#   the row must be removed once the crate is consolidated.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_test_target_coverage)" || exit 1

"$PYTHON" - "$REPO_ROOT" <<'PYEOF'
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1]).resolve()

# Members held in one test target by a guard, and the guard that holds each one. The guard name is
# checked to exist and to name the member, so a row cannot outlive the guard it points at.
COVERED = {
    "crates/conformance": "check_test_target_consolidation.sh",
    "crates/core": "check_test_target_consolidation.sh",
    "crates/corpus": "check_test_target_coverage.sh",
    "crates/dialect-minio": "check_test_target_coverage.sh",
    "crates/gateway": "check_test_target_consolidation.sh",
    "crates/http": "check_http_test_target_consolidation.sh",
    "crates/server": "check_server_test_target_consolidation.sh",
    "crates/sig": "check_sig_test_target_consolidation.sh",
    "xtask": "check_xtask_test_target_consolidation.sh",
}

# Members not yet consolidated. targets is what `cargo test --workspace` links for that member
# today and is enforced exactly, so the debt cannot grow quietly while phase 2 is pending.
EXCEPTIONS = {
    "crates/fs": (
        1,
        "rustfs/gateway#277",
        "one CRUD integration target; consolidation starts when a second source would otherwise "
        "create another linked test binary",
    ),
    "crates/macros": (
        2,
        "rustfs/gateway#277",
        "equivalence.rs drives a trybuild expansion batch that AGENTS.md macro governance pins to "
        "its own target",
    ),
    "crates/types": (
        1,
        "rustfs/gateway#277",
        "one target; consolidating a single source buys nothing until a second one is added",
    ),
    "spikes/ext-field": (
        3,
        "rustfs/gateway#277",
        "the spike this guard's own hand-written survey missed; consolidate it or retire the spike",
    ),
}


def fail(message: str) -> None:
    raise SystemExit(f"test-target coverage violation: {message}")


try:
    workspace = tomllib.loads((root / "Cargo.toml").read_text()).get("workspace")
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse the workspace manifest: {error}")
if not isinstance(workspace, dict):
    fail("the root manifest declares no [workspace] table")
patterns = workspace.get("members")
if not isinstance(patterns, list) or not patterns or any(not isinstance(p, str) for p in patterns):
    fail("[workspace] members must be a non-empty list of path patterns")

members: list[str] = []
for pattern in patterns:
    if "\\" in pattern or pattern.startswith("/"):
        fail(f"workspace member pattern is not a relative path: {pattern}")
    matches = sorted(root.glob(pattern)) if "*" in pattern or "?" in pattern else [root / pattern]
    resolved = [m for m in matches if (m / "Cargo.toml").is_file()]
    if not resolved:
        fail(f"workspace member pattern matches no manifest: {pattern}")
    for member in resolved:
        members.append(member.relative_to(root).as_posix())
if len(set(members)) != len(members):
    fail("the same workspace member is reachable from two member patterns")


def manifest_of(member: str) -> dict:
    try:
        return tomllib.loads((root / member / "Cargo.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {member}/Cargo.toml: {error}")
    raise AssertionError("unreachable")


def explicit_test_targets(manifest: dict) -> list[dict]:
    declared = manifest.get("test")
    if declared is None:
        return []
    if not isinstance(declared, list) or any(not isinstance(entry, dict) for entry in declared):
        fail("a member declares an invalid [[test]] inventory")
    return declared


def autodiscovered(member: str) -> list[str]:
    """Cargo's own autotest rule: every tests/*.rs, plus every tests/<dir>/main.rs."""
    tests = root / member / "tests"
    if not tests.is_dir():
        return []
    found = []
    for entry in sorted(tests.iterdir()):
        if entry.is_file() and entry.suffix == ".rs":
            found.append(entry.stem)
        elif entry.is_dir() and (entry / "main.rs").is_file():
            found.append(entry.name)
    return found


def target_count(member: str, manifest: dict) -> int:
    package = manifest.get("package")
    if not isinstance(package, dict):
        fail(f"{member}/Cargo.toml declares no [package] table")
    explicit = explicit_test_targets(manifest)
    if package.get("autotests") is False:
        return len(explicit)
    return len(set(autodiscovered(member)) | {e.get("name") for e in explicit if e.get("name")})


def is_consolidated(member: str, manifest: dict) -> bool:
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("autotests") is not False:
        return False
    explicit = explicit_test_targets(manifest)
    if len(explicit) != 1:
        return False
    path = explicit[0].get("path")
    return isinstance(path, str) and path.startswith("tests/")


# A member "ships integration tests" if it has a tests/ tree Cargo would build from, or says so in
# its manifest. Both halves matter: a consolidated crate's sources are still under tests/, and an
# explicit target could point somewhere else entirely.
carrying = [m for m in members if autodiscovered(m) or explicit_test_targets(manifest_of(m))]

overlap = sorted(set(COVERED) & set(EXCEPTIONS))
if overlap:
    fail(f"a member is both covered and excepted: {', '.join(overlap)}")

listed = set(COVERED) | set(EXCEPTIONS)
unlisted = sorted(set(carrying) - listed)
if unlisted:
    fail(
        f"workspace member(s) ship integration tests but appear in no table: {', '.join(unlisted)}. "
        "Consolidate to one target and add a COVERED row, or add an EXCEPTIONS row naming the "
        "target count, a tracking issue and a reason"
    )
dead = sorted(listed - set(carrying))
if dead:
    fail(f"table row(s) name something that is not a workspace member shipping tests: {', '.join(dead)}")

covered_targets = 0
for member, guard in sorted(COVERED.items()):
    guard_path = root / "scripts" / guard
    if not guard_path.is_file():
        fail(f"{member} names a consolidation guard that does not exist: scripts/{guard}")
    try:
        guard_source = guard_path.read_text()
    except OSError as error:
        fail(f"cannot read scripts/{guard}: {error}")
    # Every consolidation guard names its subject by the member path it is given — `crates/sig`
    # for the sig wrapper, the bare `xtask` for the xtask one, because that is its member path.
    # The row stops being true the moment the guard stops naming it, and this is what says so.
    if member not in guard_source:
        fail(f"scripts/{guard} does not name {member}, so it cannot be what holds it consolidated")
    manifest = manifest_of(member)
    if not is_consolidated(member, manifest):
        fail(
            f"{member} is listed as covered but is not in the consolidated shape: it must set "
            "package.autotests = false and declare exactly one [[test]] target under tests/"
        )
    covered_targets += target_count(member, manifest)

excepted_targets = 0
for member, row in sorted(EXCEPTIONS.items()):
    if not isinstance(row, tuple) or len(row) != 3:
        fail(f"the exception row for {member} must be (targets, issue, reason)")
    recorded, issue, reason = row
    if not isinstance(recorded, int) or recorded < 1:
        fail(f"the exception row for {member} must record a positive target count")
    if not isinstance(issue, str) or not issue.startswith("rustfs/gateway#") or not issue[15:].isdigit():
        fail(f"the exception row for {member} must name a rustfs/gateway#<number> tracking issue")
    if not isinstance(reason, str) or len(reason.split()) < 5:
        fail(f"the exception row for {member} must carry a reason, not a placeholder")
    manifest = manifest_of(member)
    if is_consolidated(member, manifest):
        fail(
            f"{member} is consolidated but still carries an exception row. Remove the row and add "
            f"it to COVERED with the guard that holds it"
        )
    actual = target_count(member, manifest)
    if actual != recorded:
        fail(
            f"{member} links {actual} test target(s), but its exception row records {recorded}. "
            "Consolidate the crate, or update the row deliberately — the count is a ratchet so "
            "this debt cannot grow unremarked"
        )
    excepted_targets += actual

print(
    f"test-target coverage: {len(members)} workspace members, "
    f"{len(COVERED)} consolidated to {covered_targets} target(s), "
    f"{len(EXCEPTIONS)} excepted at {excepted_targets} target(s), "
    f"{covered_targets + excepted_targets} linked by cargo test --workspace"
)
PYEOF
