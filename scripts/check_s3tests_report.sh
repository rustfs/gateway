#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_s3tests_report.sh
#
# WHAT THIS CHECKS
#   That ci/s3tests/report.py's ratchet can actually fail, in every direction it
#   claims to have. Eight probes over synthetic JUnit documents:
#
#     1. a failure the xfail list names          -> KNOWN,      exit 0
#     2. a failure the xfail list does not name  -> REGRESSION,  exit 1
#     3. a listed case that now passes           -> FIXED,       exit 0
#     4. a listed case the run never reported    -> STALE,       exit 0
#     5. a listed case the run skipped           -> STALE, and NOT counted known
#     6. every case errored                      -> environment, exit 3
#     7. an empty JUnit document                 -> environment, exit 3
#     8. an xfail list with no generation header -> environment, exit 3
#
#   Plus: a case id is classified into the same capability domain every time.
#
# WHY THIS IS A GUARD AND NOT A UNIT TEST
#   The zombie failure mode for an external suite is not that the suite breaks.
#   It is that the *judgement* silently stops judging — a parser that reads no
#   `<failure>` element reports a clean run over a suite that was entirely red,
#   and a clean run reads exactly like a passing one. This repository has
#   produced that defect seven times (AGENTS.md, "Measurement"), so the tool
#   that decides whether the weekly job is green owes a check that runs on every
#   pull request, not one that runs weekly with the suite it judges.
#
#   Probes 6 and 7 are the ones that matter most: `connection refused` reaches
#   pytest as a setup error on every case, and recording that as ~980
#   regressions would either fail the job for the wrong reason or, worse, invite
#   somebody to paste the whole suite into the xfail list.
#
# HOW TO EXEMPT
#   None.
#
# USAGE
#   scripts/check_s3tests_report.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_s3tests_report.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
REPORT="${ROOT_DIR}/ci/s3tests/report.py"

if [[ ! -f "$REPORT" ]]; then
    printf 'check_s3tests_report: required input is missing: ci/s3tests/report.py\n' >&2
    exit 1
fi

python3 - "$REPORT" <<'PYEOF'
import subprocess
import sys
import tempfile
from pathlib import Path

report = sys.argv[1]
failures: list[str] = []

MULTIPART = "s3tests_boto3.functional.test_s3::test_multipart_upload_small"
ACL = "s3tests_boto3.functional.test_s3::test_bucket_acl_grant_email"
LIFECYCLE = "s3tests_boto3.functional.test_s3::test_lifecycle_expiration"


def junit(cases: list[tuple[str, str]]) -> str:
    body = []
    for case_id, outcome in cases:
        classname, _, name = case_id.rpartition("::")
        inner = {
            "passed": "",
            "failed": "<failure message=\"assert 0 == 1\">detail</failure>",
            "errored": "<error message=\"ConnectionRefusedError\">detail</error>",
            "skipped": "<skipped message=\"marker\"/>",
        }[outcome]
        body.append(f'<testcase classname="{classname}" name="{name}">{inner}</testcase>')
    joined = "".join(body)
    return f'<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="s3tests">{joined}</testsuite></testsuites>'


def xfail(entries: list[str], generation: str | None = "3") -> str:
    header = "" if generation is None else f"# generation: {generation}\n"
    return header + "".join(f"{entry}\n" for entry in entries)


def probe(label: str, cases, entries, expected_code: int, expect_out: list[str], forbid_out: list[str] = []):
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        junit_path = work / "junit.xml"
        xfail_path = work / "xfail.txt"
        junit_path.write_text(cases if isinstance(cases, str) else junit(cases), encoding="utf-8")
        xfail_path.write_text(entries if isinstance(entries, str) else xfail(entries), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, report, "--junit", str(junit_path), "--xfail", str(xfail_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    combined = result.stdout + result.stderr
    if result.returncode != expected_code:
        failures.append(
            f"{label}: expected exit {expected_code}, got {result.returncode}\n"
            + "\n".join(f"    {line}" for line in combined.splitlines())
        )
        return
    for needle in expect_out:
        if needle not in combined:
            failures.append(f"{label}: expected {needle!r} in the output, got:\n" + combined)
    for needle in forbid_out:
        if needle in combined:
            failures.append(f"{label}: {needle!r} must not appear in the output, got:\n" + combined)


# 1. A tolerated failure is tolerated, and is counted as known rather than passed.
probe(
    "a listed failure is KNOWN",
    [(MULTIPART, "failed"), (ACL, "passed")],
    [MULTIPART],
    0,
    ["known=1", "regression=0", "passed=1"],
    ["REGRESSION"],
)

# 2. The whole point of the ratchet.
probe(
    "an unlisted failure is a REGRESSION and fails",
    [(MULTIPART, "failed"), (ACL, "passed")],
    [],
    1,
    ["regression=1", f"REGRESSION multipart {MULTIPART}"],
)

# 3. A listed case that passes drives the ratchet forward.
probe(
    "a listed case that passes is FIXED",
    [(MULTIPART, "passed")],
    [MULTIPART],
    0,
    ["fixed=1", f"FIXED multipart {MULTIPART}"],
)

# 4. An entry naming a case nothing reported is dead weight and is named as such.
probe(
    "an unreported entry is STALE",
    [(ACL, "passed")],
    [LIFECYCLE],
    0,
    ["stale=1", f"STALE {LIFECYCLE}"],
)

# 5. A skip is not evidence that a tolerated case still fails. If a listed case was
#    skipped it was not measured, and counting it as known would let a case that stopped
#    running keep its entry forever.
probe(
    "a listed case that was skipped is STALE and not KNOWN",
    [(MULTIPART, "skipped")],
    [MULTIPART],
    0,
    ["known=0", "stale=1", "skipped=1"],
)

# 6. connection refused reaches pytest as an error on every case.
probe(
    "an all-errored run is an environment failure",
    [(MULTIPART, "errored"), (ACL, "errored")],
    [],
    3,
    ["was not reachable"],
    ["REGRESSION"],
)

# 7. A document with no cases asserts nothing about anything.
probe(
    "a JUnit document with no cases is an environment failure",
    '<?xml version="1.0"?><testsuites></testsuites>',
    [],
    3,
    ["reported no cases"],
)

# 8. A list with no generation cannot be ratcheted, so it is refused rather than read.
probe(
    "an xfail list with no generation header is refused",
    [(ACL, "passed")],
    xfail([], generation=None),
    3,
    ["generation"],
)

# 9. Classification is a function of the id, not of the run it appeared in.
# Importing the module must not leave a __pycache__ behind in the repository tree.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(report).parent))
import report as report_module  # noqa: E402

for case_id, domain in (
    (MULTIPART, "multipart"),
    (ACL, "acl"),
    (LIFECYCLE, "lifecycle"),
    ("s3tests_boto3.functional.test_s3::test_object_versioning_enabled", "versioning"),
):
    actual = report_module.classify(case_id)
    if actual != domain:
        failures.append(f"classify({case_id!r}) is {actual!r}, expected {domain!r}")

if failures:
    for failure in failures:
        print(f"check_s3tests_report: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("OK: the s3-tests ratchet fails on a regression, tolerates a listed failure, reports fixed and stale entries, and refuses a run that measured nothing")
PYEOF
