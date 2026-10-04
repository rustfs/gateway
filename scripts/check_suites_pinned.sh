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
#     5b. The suite's Python client is pinned too: ci/s3tests/requirements.lock
#        names every package at one exact version with a sha256, and the runner
#        installs it with --require-hashes --no-deps, never through tox (whose
#        environment follows the suite's floating requirements.txt).
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

def require_release_sut_before(relative: str, workflow_text: str, runner: str) -> None:
    """The workflow installs pinned stable Rust and builds the release SUT before the runner."""
    toolchain = re.search(
        r"^(?P<indent>[ \t]*)uses:[ \t]*(?:dtolnay/rust-toolchain|actions-rust-lang/setup-rust-toolchain)@"
        r"[0-9a-f]{40}[ \t]*$",
        workflow_text,
        re.MULTILINE,
    )
    release_build = re.search(
        r"^\s*run:\s*cargo build --release -p rustfs-gateway-compat-sut\s*$",
        workflow_text,
        re.MULTILINE,
    )
    suite_run_match = re.search(rf"^\s*{re.escape(runner)}\b", workflow_text, re.MULTILINE)
    if toolchain is None:
        failures.append(
            f"{relative} must install Rust through a toolchain action pinned to an exact 40-hex revision"
        )
    if toolchain is not None:
        # Bind the input to this action, not a later step or a comment containing the selector.
        indent = re.escape(toolchain.group("indent"))
        selection = re.match(
            rf"\n{indent}with:[ \t]*\n{indent}  toolchain:[ \t]*stable[ \t]*(?:\n|$)",
            workflow_text[toolchain.end():],
        )
        if selection is None:
            failures.append(f"{relative} must set with.toolchain to stable on the pinned Rust action step")
    if release_build is None:
        failures.append(f"{relative} must run `cargo build --release -p rustfs-gateway-compat-sut`")
    if suite_run_match is None:
        failures.append(f"{relative} never invokes {runner}")
    elif (
        toolchain is not None
        and release_build is not None
        and not (toolchain.start() < release_build.start() < suite_run_match.start())
    ):
        failures.append(
            f"{relative} must install Rust and build the release compatibility SUT before invoking {runner}"
        )


workflow_text = s3tests_workflow.read_text(encoding="utf-8")
require_release_sut_before(".github/workflows/e2e-s3tests.yml", workflow_text, "ci/s3tests/run.sh")

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
    # The suite sweeps its bucket prefix as `[s3 tenant]` around every case; a service that
    # does not know that key errors ~99% of the run in setup (rustfs/backlog#1764).
    "--tenant-access-key",
    "--tenant-secret-key",
    "--tenant-owner-id",
    "--tenant-display-name",
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

# --- rule 5b: the suite's Python client is pinned as tightly as the suite ----------------
# The suite's own requirements.txt floats, so a pinned suite commit run through tox still
# measured whatever boto3/botocore/pytest PyPI served that week. The lock names every package
# at one exact version with at least one sha256, and the runner installs from it with
# --require-hashes --no-deps and never through tox.
lock_path = root / "ci/s3tests/requirements.lock"
if not lock_path.is_file():
    failures.append(
        "ci/s3tests/requirements.lock is missing; without it the suite's client floats with PyPI"
    )
else:
    lock_logical: list[str] = []
    pending = ""
    for raw in lock_path.read_text(encoding="utf-8").splitlines():
        stripped = raw.split("#", 1)[0].strip() if raw.lstrip().startswith("#") else raw.strip()
        if not stripped:
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lock_logical.append(pending + stripped)
        pending = ""
    if pending:
        lock_logical.append(pending)
    if not lock_logical:
        failures.append("ci/s3tests/requirements.lock names no requirement at all")
    for requirement in lock_logical:
        head = requirement.split()[0]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.!+_-]+", head):
            failures.append(
                f"ci/s3tests/requirements.lock: `{head}` is not pinned to one exact version with =="
            )
        if not re.search(r"--hash=sha256:[0-9a-f]{64}", requirement):
            failures.append(
                f"ci/s3tests/requirements.lock: `{head}` carries no sha256 hash, so --require-hashes "
                "would refuse the whole install"
            )
runner_code = "\n".join(
    line for line in runner_text.splitlines() if not line.lstrip().startswith("#")
)
if re.search(r"\btox\b", runner_code):
    failures.append(
        "ci/s3tests/run.sh invokes tox, whose environment installs from the suite's floating "
        "requirements.txt; install ci/s3tests/requirements.lock instead"
    )
if not re.search(
    r"pip install\b[^\n]*(?:\\\n[^\n]*)*--require-hashes[^\n]*(?:\\\n[^\n]*)*"
    r'-r "\$LOCK"',
    runner_code,
) or 'LOCK="${ROOT_DIR}/ci/s3tests/requirements.lock"' not in runner_code:
    failures.append(
        "ci/s3tests/run.sh must install the suite environment with "
        '`pip install --require-hashes --no-deps -r "$LOCK"` from ci/s3tests/requirements.lock'
    )
elif "--no-deps" not in runner_code:
    failures.append(
        "ci/s3tests/run.sh must pass --no-deps, so nothing outside ci/s3tests/requirements.lock is installed"
    )

# --- rule 6: the MinIO mint runner is complete --------------------------------------------
MINT_INPUTS = (
    ".github/workflows/e2e-mint.yml",
    "ci/mint/run.sh",
    "ci/mint/pins.env",
    "ci/mint/report.py",
    "ci/mint/_redaction.py",
    "ci/mint/baseline.txt",
)
missing_mint = [name for name in MINT_INPUTS if not (root / name).is_file()]
if missing_mint:
    print(
        "check_suites_pinned: the mint runner is incomplete; required inputs are missing: "
        + ", ".join(missing_mint),
        file=sys.stderr,
    )
    raise SystemExit(1)


def read_env(path: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        found[key.strip()] = value.strip().strip('"')
    return found


mint_pins = read_env(root / "ci/mint/pins.env")
mint_image = mint_pins.get("MINT_IMAGE", "")
if not re.fullmatch(r"docker\.io/minio/mint@sha256:[0-9a-f]{64}", mint_image):
    failures.append(
        f"ci/mint/pins.env must set MINT_IMAGE to docker.io/minio/mint@sha256:<64 hex>, got {mint_image!r}. "
        "An archived image is still re-tagged; only a digest names one build."
    )
# The recipe CI measures builds on exactly that digest. Where it is fetched from may vary
# (MINT_REGISTRY: a pull by digest is verified against the digest); what is fetched may not.
mint_recipe = root / "ci/mint/Dockerfile"
if not mint_recipe.is_file():
    failures.append("required input is missing: ci/mint/Dockerfile")
elif re.fullmatch(r"docker\.io/minio/mint@sha256:[0-9a-f]{64}", mint_image):
    recipe_text = mint_recipe.read_text(encoding="utf-8")
    recipe_bases = re.findall(r"(?m)^FROM\s+(\S+)", recipe_text)
    pinned_base = "${MINT_REGISTRY}/minio/mint@" + mint_image.partition("@")[2]
    stray = [base for base in recipe_bases if "minio/mint" in base and base != pinned_base]
    if stray or not recipe_bases or recipe_bases[-1] != pinned_base:
        failures.append(
            f"ci/mint/Dockerfile must build its final stage, and every mint stage, FROM {pinned_base} "
            f"(the ci/mint/pins.env digest); found {recipe_bases!r}"
        )
    if not re.search(r"(?m)^ARG MINT_REGISTRY=docker\.io$", recipe_text):
        failures.append(
            "ci/mint/Dockerfile must default MINT_REGISTRY to docker.io, the source ci/mint/pins.env names"
        )
mint_platform = mint_pins.get("MINT_PLATFORM", "")
if mint_platform != "linux/amd64":
    failures.append(
        f"ci/mint/pins.env must set MINT_PLATFORM=linux/amd64, got {mint_platform!r}; the pinned digest is "
        "a single-platform linux/amd64 manifest"
    )
mint_sdks = mint_pins.get("MINT_SDKS", "").split()
if not mint_sdks or len(set(mint_sdks)) != len(mint_sdks):
    failures.append("ci/mint/pins.env must name each SDK in MINT_SDKS exactly once")

MINT_WORKFLOW = ".github/workflows/e2e-mint.yml"
mint_workflow_text = (root / MINT_WORKFLOW).read_text(encoding="utf-8")
require_release_sut_before(MINT_WORKFLOW, mint_workflow_text, "ci/mint/run.sh")
if not re.search(r"^  workflow_dispatch:\s*$", mint_workflow_text, re.MULTILINE):
    failures.append(f"{MINT_WORKFLOW} must stay dispatchable, so a record run can be started by hand")
if not re.search(r"^\s*-\s*record\s*$", mint_workflow_text, re.MULTILINE):
    failures.append(f"{MINT_WORKFLOW} must offer a `record` mode input")
for number, raw in enumerate(mint_workflow_text.splitlines(), start=1):
    used = re.match(r"^\s*(?:-\s*)?uses:\s*(\S+)", raw)
    if used is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}", used.group(1)):
        failures.append(
            f"{MINT_WORKFLOW}:{number}: uses {used.group(1)}; every action is pinned by a 40-hex commit"
        )
uploads = re.findall(r"uses:\s*actions/upload-artifact@", mint_workflow_text)
upload_paths = re.findall(r"^\s*path:\s*(.+?)\s*$", mint_workflow_text, re.MULTILINE)
if len(uploads) != 1 or upload_paths != ["${{ runner.temp }}/mint-out"]:
    failures.append(
        f"{MINT_WORKFLOW} must upload exactly one artifact, from `${{{{ runner.temp }}}}/mint-out`: the "
        "repository-owned aggregate. The console and the raw per-SDK JSON stay in runner storage, because "
        "upstream failure text can carry Authorization, presigned-query or signature material."
    )
issue_steps = [step for step in re.split(r"(?m)^      - ", mint_workflow_text) if "gh issue create" in step]
if len(issue_steps) != 1:
    failures.append(f"{MINT_WORKFLOW} must file regression issues from exactly one step")
else:
    condition = re.search(r"(?m)^\s*if:\s*(.+?)\s*$", issue_steps[0])
    if condition is None or condition.group(1) != "failure() && steps.suite.outputs.status == '1'":
        failures.append(
            f"{MINT_WORKFLOW}: the issue step must run only on "
            "`failure() && steps.suite.outputs.status == '1'`; an incomplete run (exit 3) measured "
            "nothing and must not file a regression"
        )

mint_runner = (root / "ci/mint/run.sh").read_text(encoding="utf-8")
mint_start = mint_runner.find("\nsut_start\n")
if 'source "${ROOT_DIR}/ci/lib/sut.sh"' not in mint_runner or mint_start < 0:
    failures.append(
        "ci/mint/run.sh must start or adopt its SUT through ci/lib/sut.sh (source it, then call "
        "sut_start on its own line); a second launcher is a second place for the exit-3 rule to go missing"
    )
mint_before_start = mint_runner[:mint_start] if mint_start >= 0 else mint_runner
mint_default = mint_before_start.find(': "${GATEWAY_SUT_COMMAND:=')
if mint_default < 0:
    failures.append(
        "ci/mint/run.sh must default GATEWAY_SUT_COMMAND with the overridable `:=` form before sut_start"
    )
else:
    if "target/release/compat-sut" not in mint_before_start:
        failures.append("ci/mint/run.sh's default SUT must be target/release/compat-sut")
    mint_flags = ("--data", "--host", "--port", "--region", "--access-key", "--secret-key")
    missing_mint_flags = [flag for flag in mint_flags if flag not in mint_before_start[mint_default:]]
    if missing_mint_flags:
        failures.append(
            "ci/mint/run.sh's default GATEWAY_SUT_COMMAND is missing required flags: " + ", ".join(missing_mint_flags)
        )
if 'source "${ROOT_DIR}/ci/mint/pins.env"' not in mint_runner:
    failures.append("ci/mint/run.sh must read its image, platform and SDK census from ci/mint/pins.env")
if 'docker pull --quiet --platform "$MINT_PLATFORM" "$MINT_IMAGE"' not in mint_runner:
    failures.append("ci/mint/run.sh must pull the pinned image with --platform \"$MINT_PLATFORM\"")

# The run's steps, in the only order that makes its verdict mean anything. The suite runs in
# passes (rustfs/gateway#719): one container over plaintext, and one over the SUT's TLS listener
# for the SDKs only it can measure. Each pass is `mint_pass`, which creates its container from
# the pinned image, runs it, and copies its /mint/log out before returning, so the plaintext
# pass's call is where "the suite ran and its evidence was copied" sits in the file.
MINT_STEPS = (
    ("census", "-A /mint/run/core", "its SDK census check against the image"),
    ("suite", 'mint_pass "$MINT_CONTAINER"', "its plaintext suite pass"),
    ("redact", 'report.py" redact', "its redaction of the copied evidence"),
    ("judge", 'report.py" "${REPORT_ARGS[@]}"', "its judgement of the redacted evidence"),
)
positions: dict[str, int] = {}
for key, marker, description in MINT_STEPS:
    positions[key] = mint_runner.find(marker)
    if positions[key] < 0:
        failures.append(f"ci/mint/run.sh lost {description}: {marker}")
if all(position >= 0 for position in positions.values()):
    ordered = [positions[key] for key, _, _ in MINT_STEPS]
    if ordered != sorted(ordered):
        failures.append(
            "ci/mint/run.sh must check the census, run the suite, redact the copied evidence, and only "
            "then judge it, in that order; a report written before the log is copied judges nothing"
        )

# One pass, in order: a container from the pinned image and platform naming its SDKs explicitly,
# run to completion, then its /mint/log copied out before anything else can remove it.
pass_start = mint_runner.find("\nmint_pass() {\n")
pass_end = mint_runner.find("\n}\n", pass_start) if pass_start >= 0 else -1
if pass_start < 0 or pass_end < 0:
    failures.append("ci/mint/run.sh lost `mint_pass() {`, the one place a suite container is run")
else:
    body = mint_runner[pass_start:pass_end]
    PASS_STEPS = (
        ("create", "docker create", "its container creation"),
        ("image", '"$MINT_IMAGE" "$@"', "its suite run naming the pass's SDKs explicitly"),
        ("start", "docker start --attach", "its suite run"),
        ("copy", 'docker cp "${container}:/mint/log"', "its copy of /mint/log out of the container"),
    )
    found = {key: body.find(marker) for key, marker, _ in PASS_STEPS}
    for key, marker, description in PASS_STEPS:
        if found[key] < 0:
            failures.append(f"ci/mint/run.sh's mint_pass lost {description}: {marker}")
    if all(position >= 0 for position in found.values()):
        if [found[key] for key, _, _ in PASS_STEPS] != sorted(found.values()):
            failures.append("ci/mint/run.sh's mint_pass must create, run, and only then copy /mint/log out")
        if '--platform "$MINT_PLATFORM"' not in body[found["create"]:found["image"]]:
            failures.append('ci/mint/run.sh must create the suite container with --platform "$MINT_PLATFORM"')

# Every pinned SDK runs in exactly one pass. The runner derives the plaintext list from the census
# list, and the report is handed that full list plus each pass's own; ci/mint/report.py refuses
# (exit 2) passes that do not cover it exactly once, so an SDK cannot silently never start.
for marker, description in (
    ('for sdk in "${MINT_SDK_LIST[@]}"', "its plaintext SDK list derived from the census list"),
    ('--sdks "${MINT_SDK_LIST[*]}"', "the full SDK list it hands the report"),
    ('--pass "${MINT_PLAIN_LIST[*]}"', "the plaintext pass it hands the report"),
):
    if marker not in mint_runner:
        failures.append(f"ci/mint/run.sh lost {description}: {marker}")
if not re.search(r"REPORT_ARGS=\(\s*judge\b", mint_runner):
    failures.append("ci/mint/run.sh must hand the report the `judge` command")

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
