#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_suites_pinned.sh
#
# WHAT THIS CHECKS
#   Four rules about how this repository reaches an external acceptance suite:
#
#     1. ci/s3tests/pins.env pins ceph/s3-tests to an exact 40-hex commit on
#        the repository it names. That project has never published a tag, so a
#        commit is the only pin that exists.
#     2. Nothing under ci/ or .github/workflows/ checks out a suite by branch
#        or by a floating ref, and nothing pulls a container image by a moving
#        tag — `:latest` above all. An archived upstream plus a floating tag is
#        a result that cannot be reproduced next week.
#     3. Every external-suite workflow is on cron only. A `pull_request`,
#        `pull_request_target` or `push` trigger on a 30-90 minute suite is
#        incompatible with the ten-minute pull-request gate budget, and the
#        budget is the reason the gate still gets run.
#     4. The pull-request workflow does not invoke an external suite runner by
#        any other route either.
#
# WHY
#   Two consecutive weekly runs are only comparable if they ran the same cases.
#   Everything downstream — the xfail ratchet, the domain counts, the claim
#   that a regression is a regression — rests on that, and nothing else checks
#   it. A floating revision does not fail loudly; it quietly makes the whole
#   series meaningless.
#
# HOW TO EXEMPT
#   None. Move a pin by editing ci/s3tests/pins.env in a reviewed diff.
#
# USAGE
#   scripts/check_suites_pinned.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_suites_pinned.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$ROOT_DIR" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
failures: list[str] = []

# --- rule 1: the s3-tests pin ------------------------------------------------------------
pins = root / "ci/s3tests/pins.env"
if not pins.is_file():
    print("check_suites_pinned: required input is missing: ci/s3tests/pins.env", file=sys.stderr)
    raise SystemExit(1)
values: dict[str, str] = {}
for line in pins.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    key, _, value = stripped.partition("=")
    values[key.strip()] = value.strip()

sha = values.get("S3TESTS_SHA", "")
if not re.fullmatch(r"[0-9a-f]{40}", sha):
    failures.append(
        f"ci/s3tests/pins.env must set S3TESTS_SHA to an exact 40-hex commit, got {sha!r}. "
        "ceph/s3-tests publishes no tags, so a commit is the only pin available."
    )
repository = values.get("S3TESTS_REPOSITORY", "")
if repository != "https://github.com/ceph/s3-tests":
    failures.append(
        f"ci/s3tests/pins.env points S3TESTS_REPOSITORY at {repository!r}; the suite this "
        "project's licence review covers is https://github.com/ceph/s3-tests"
    )

# --- rules 2 and 3: every runner input ---------------------------------------------------
workflow_dir = root / ".github/workflows"
if not workflow_dir.is_dir():
    print("check_suites_pinned: required input is missing: .github/workflows", file=sys.stderr)
    raise SystemExit(1)

# External-suite workflows are recognised by name, not by content: a workflow that stops
# looking like one is a rename this guard should notice, and renames are reviewed.
suite_workflows = sorted(
    path for path in workflow_dir.iterdir() if path.suffix in {".yml", ".yaml"} and path.name.startswith("e2e-")
)
if not suite_workflows:
    failures.append(
        ".github/workflows holds no e2e-* workflow; this guard's rules 3 and 4 would have "
        "nothing to judge, which reads exactly like them passing"
    )

scanned: list[Path] = list(suite_workflows)
scanned.extend(sorted(path for path in (root / "ci").rglob("*") if path.is_file()))

FLOATING_IMAGE = re.compile(r"\b([A-Za-z0-9._/-]+)\s*:\s*(latest|master|main|edge|nightly)\b")
# Any checkout or clone on the same line as a branch name rather than a commit. Deliberately
# blunt: a false positive is one reviewed line, a false negative is a year of incomparable runs.
BRANCH_CHECKOUT = re.compile(r"\bgit\b[^\n]*\b(?:checkout|clone)\b[^\n]*?\b(?:origin/)?(master|main|HEAD)\b")
for path in scanned:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        continue
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0]
        if not line.strip():
            continue
        relative = path.relative_to(root)
        image = FLOATING_IMAGE.search(line)
        if image is not None and "/" in image.group(1):
            failures.append(
                f"{relative}:{number}: pulls {image.group(1)}:{image.group(2)}, a moving tag. "
                "Pin the image by digest (`name@sha256:...`) — an upstream that is archived "
                "still republishes tags, and a moving one makes a run irreproducible."
            )
        branch = BRANCH_CHECKOUT.search(line)
        if branch is not None:
            failures.append(
                f"{relative}:{number}: checks out {branch.group(1)} rather than a pinned commit"
            )

for path in suite_workflows:
    text = path.read_text(encoding="utf-8")
    relative = path.relative_to(root)
    for trigger in ("pull_request_target", "pull_request", "push"):
        if re.search(rf"^\s{{2}}{trigger}:", text, re.MULTILINE):
            failures.append(
                f"{relative} triggers on {trigger}. An external suite runs 30-90 minutes and the "
                "pull-request gate has a hard ten-minute budget (AGENTS.md 'CI budget'); a gate "
                "people stop running catches nothing."
            )
    if not re.search(r"^\s{4}- cron:", text, re.MULTILINE):
        failures.append(f"{relative} declares no cron schedule, so nothing would ever run it")

# --- rule 4: the pull-request workflow keeps its distance ---------------------------------
gate = root / ".github/workflows/ci.yml"
if not gate.is_file():
    print("check_suites_pinned: required input is missing: .github/workflows/ci.yml", file=sys.stderr)
    raise SystemExit(1)
gate_text = gate.read_text(encoding="utf-8")
for needle in ("ci/s3tests/run.sh", "ci/mint/run.sh", "minio/mint"):
    for number, raw in enumerate(gate_text.splitlines(), start=1):
        if needle in raw and not raw.lstrip().startswith("#"):
            failures.append(
                f".github/workflows/ci.yml:{number}: the pull-request gate invokes {needle}; "
                "external suites belong on cron"
            )

if failures:
    for failure in failures:
        print(f"check_suites_pinned: {failure}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: s3-tests@{sha}; {len(suite_workflows)} cron-only suite workflow(s); no floating revision")
PYEOF
