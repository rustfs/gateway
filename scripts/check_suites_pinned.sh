#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_suites_pinned.sh
#
# WHAT THIS CHECKS
#   Five rules about how this repository reaches an external acceptance suite:
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
#     5. The weekly s3-tests workflow builds the local compatibility SUT, and
#        its runner exports the complete suite configuration before starting an
#        overridable command with every required identity and endpoint flag.
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

# --- rule 5: the weekly s3-tests job can launch the repository SUT -----------------------
s3tests_workflow = workflow_dir / "e2e-s3tests.yml"
s3tests_runner = root / "ci/s3tests/run.sh"
sut_library = root / "ci/lib/sut.sh"
for required in (s3tests_workflow, s3tests_runner, sut_library):
    if not required.is_file():
        print(
            f"check_suites_pinned: required input is missing: {required.relative_to(root)}",
            file=sys.stderr,
        )
        raise SystemExit(1)

workflow_text = s3tests_workflow.read_text(encoding="utf-8")
toolchain = re.search(
    r"^\s*uses:\s*(?:dtolnay/rust-toolchain|actions-rust-lang/setup-rust-toolchain)@"
    r"[0-9a-f]{40}\s*$",
    workflow_text,
    re.MULTILINE,
)
release_build = re.search(
    r"^\s*run:\s*cargo build --release -p rustfs-gateway-compat-sut\s*$",
    workflow_text,
    re.MULTILINE,
)
suite_run_match = re.search(r"^\s*ci/s3tests/run\.sh\b", workflow_text, re.MULTILINE)
if toolchain is None:
    failures.append(
        ".github/workflows/e2e-s3tests.yml must install Rust through a toolchain action "
        "pinned to an exact 40-hex revision"
    )
if release_build is None:
    failures.append(
        ".github/workflows/e2e-s3tests.yml must run "
        "`cargo build --release -p rustfs-gateway-compat-sut`"
    )
if (
    toolchain is not None
    and release_build is not None
    and suite_run_match is not None
    and not (toolchain.start() < release_build.start() < suite_run_match.start())
):
    failures.append(
        ".github/workflows/e2e-s3tests.yml must install Rust and build the release "
        "compatibility SUT before invoking ci/s3tests/run.sh"
    )

runner_text = s3tests_runner.read_text(encoding="utf-8")
sut_start = runner_text.find("\nsut_start\n")
if sut_start < 0:
    failures.append("ci/s3tests/run.sh must invoke sut_start on its own line")
    before_sut_start = runner_text
else:
    before_sut_start = runner_text[:sut_start]

command_default = before_sut_start.find(': "${GATEWAY_SUT_COMMAND:=')
if command_default < 0:
    failures.append(
        "ci/s3tests/run.sh must default GATEWAY_SUT_COMMAND with the overridable `:=` "
        "form before sut_start"
    )
    command_text = ""
else:
    command_text = before_sut_start[command_default:]

if "target/release/compat-sut" not in command_text:
    failures.append(
        "ci/s3tests/run.sh's default GATEWAY_SUT_COMMAND must launch "
        "target/release/compat-sut"
    )
required_flags = (
    "--data",
    "--host",
    "--port",
    "--region",
    "--access-key",
    "--secret-key",
    "--owner-id",
    "--display-name",
    "--alt-access-key",
    "--alt-secret-key",
    "--alt-owner-id",
    "--alt-display-name",
    "--lc-debug-interval",
)
missing_flags = [flag for flag in required_flags if flag not in command_text]
if missing_flags:
    failures.append(
        "ci/s3tests/run.sh's default GATEWAY_SUT_COMMAND is missing required flags: "
        + ", ".join(missing_flags)
    )

configured_names = set(
    re.findall(r': "\$\{(S3TESTS_[A-Z0-9_]+):=', before_sut_start)
)
configured_names.update(
    re.findall(r"^\s*(S3TESTS_[A-Z0-9_]+)=", before_sut_start, re.MULTILINE)
)
exported_names: set[str] = set()
for export_line in re.findall(r"^\s*export\s+(.+)$", before_sut_start, re.MULTILINE):
    exported_names.update(
        name for name in export_line.split() if re.fullmatch(r"S3TESTS_[A-Z0-9_]+", name)
    )
missing_exports = sorted(configured_names - exported_names)
if missing_exports:
    failures.append(
        "ci/s3tests/run.sh must export every configured S3TESTS value before sut_start; "
        "missing: " + ", ".join(missing_exports)
    )

sut_text = sut_library.read_text(encoding="utf-8")
endpoint_branch = sut_text.find('if [[ -n "${GATEWAY_SUT_ENDPOINT:-}" ]]')
command_branch = sut_text.find('if [[ -z "${GATEWAY_SUT_COMMAND:-}" ]]')
if endpoint_branch < 0 or command_branch < 0 or endpoint_branch >= command_branch:
    failures.append(
        "ci/lib/sut.sh must prefer GATEWAY_SUT_ENDPOINT before requiring "
        "GATEWAY_SUT_COMMAND, so an external endpoint remains authoritative"
    )

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
