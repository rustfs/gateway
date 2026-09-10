#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"

# WHAT: Validates the pinned smithy-rs signing-suite identity and complete case census.
# WHY: A missing checkout or a hand-picked subset must never count as official-suite evidence.
# HOW TO EXEMPT: There is no exemption; update the protected lock through the BREAKING process.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LOCK="$ROOT/spec/third-party/aws-signing-test-suite.lock"
RUNNER="$ROOT/xtask/src/sigsuite.rs"

fail() {
    printf 'check_signing_suite_lock: %s\n' "$*" >&2
    exit 1
}

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_signing_suite_lock)" || exit 1
[[ -f "$LOCK" ]] || fail 'protected signing-suite lock is missing'
[[ -f "$RUNNER" ]] || fail 'signing-suite runner is missing'

"$PYTHON" - "$ROOT" "${1:-}" "${2:-}" <<'PY'
from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
mode = sys.argv[2]
checkout_arg = sys.argv[3]
lock_path = root / "spec/third-party/aws-signing-test-suite.lock"
runner_path = root / "xtask/src/sigsuite.rs"


def fail(message: str) -> None:
    print(f"check_signing_suite_lock: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    runner = runner_path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read signing-suite runner: {error}")
repository_cargo = '''fn suite_cargo_command() -> Command {
    Command::new("cargo")
}'''
if runner.count(repository_cargo) != 1:
    fail("signing-suite runner must launch Cargo through the repository-selected rustup proxy")
if runner.count("let status = suite_cargo_command()") != 1:
    fail("signing-suite run must use the repository-selected Cargo command exactly once")
if 'env!("CARGO")' in runner:
    fail("signing-suite runner must not capture a toolchain-specific Cargo path at build time")


try:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse lock: {error}")

required_scalars = {
    "repository": "https://github.com/smithy-lang/smithy-rs.git",
    "commit": "cb39d6e52459b47fa8881a241ac9f78849f1bc25",
    "suite_path": "aws/rust-runtime/aws-sigv4/aws-signing-test-suite",
    "v4_tree": "a40b300e3d573b47b6fc959787d1773b571f532f",
    "v4a_tree": "23ac7f51434778a8d15a727dbc6fb1f0dc2bda65",
    "license_path": "aws/rust-runtime/aws-sigv4/LICENSE",
    "license_blob": "67db8588217f266eb561f75fae738656325deac9",
    "license": "Apache-2.0",
    "retrieved": "2026-08-14",
}
for key, expected in required_scalars.items():
    if lock.get(key) != expected:
        fail(f"{key} must equal the reviewed upstream identity")

for key, expected_count in (("v4_cases", 40), ("v4a_cases", 38)):
    values = lock.get(key)
    if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
        fail(f"{key} must be a non-empty string array")
    if len(values) != expected_count or len(set(values)) != expected_count or values != sorted(values):
        fail(f"{key} must contain exactly {expected_count} unique sorted cases")

v4_run = lock.get("v4_run_three_layer")
v4_negative = lock.get("v4_s3_negative")
v4a_refused = lock.get("v4a_reject_not_implemented")
for key, values, expected_count in (
    ("v4_run_three_layer", v4_run, 31),
    ("v4_s3_negative", v4_negative, 9),
    ("v4a_reject_not_implemented", v4a_refused, 38),
):
    if not isinstance(values, list) or len(values) != expected_count or len(set(values)) != expected_count:
        fail(f"{key} must contain exactly {expected_count} unique cases")
if sorted(v4_run + v4_negative) != lock["v4_cases"]:
    fail("v4 dispositions must cover the protected census exactly once")
if v4a_refused != lock["v4a_cases"]:
    fail("v4a refusal disposition must equal the protected census")

notice = (root / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
for phrase in (
    "## Smithy signing test suite",
    required_scalars["commit"],
    "Apache License 2.0",
    "external runner",
):
    if notice.count(phrase) != 1:
        fail(f"third-party provenance must contain exactly one {phrase!r}")

protected_row = (
    "| `spec/third-party/aws-signing-test-suite.lock` | Reviewed smithy-rs signing-suite commit, "
    "license, tree identities, and complete v4/v4a case census |"
)
agents = (root / "AGENTS.md").read_text(encoding="utf-8")
protected_guard = (root / "scripts/check_protected_files.sh").read_text(encoding="utf-8")
if agents.count(protected_row) != 1:
    fail("AGENTS.md must protect the signing-suite lock exactly once")
if protected_guard.count('"`spec/third-party/aws-signing-test-suite.lock`"') != 1:
    fail("protected path table must list the signing-suite lock exactly once")
if protected_guard.count('"spec/third-party/aws-signing-test-suite.lock"') != 1:
    fail("protected exact-path set must list the signing-suite lock exactly once")

if mode not in {"", "--checkout"}:
    fail("usage: check_signing_suite_lock.sh [--checkout PATH]")
if not mode:
    print("check_signing_suite_lock: lock records 31 executed v4, 9 S3 negative, and 38 refused v4a cases")
    raise SystemExit(0)
if not checkout_arg:
    fail("--checkout requires a path")

checkout = Path(checkout_arg).resolve()
try:
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    if status:
        fail("checkout has tracked or untracked changes")
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
except (OSError, subprocess.CalledProcessError) as error:
    fail(f"cannot inspect checkout: {error}")
if head != required_scalars["commit"]:
    fail("checkout HEAD does not match the protected commit")

suite = checkout / required_scalars["suite_path"]
for directory, key, tree_key in (
    (suite / "v4", "v4_cases", "v4_tree"),
    (suite / "v4a", "v4a_cases", "v4a_tree"),
):
    if not directory.is_dir():
        fail(f"suite directory is missing: {directory}")
    relative = directory.relative_to(checkout).as_posix()
    tree = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", f"HEAD:{relative}"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if tree != required_scalars[tree_key]:
        fail(f"{tree_key} checkout identity differs from the protected lock")
    actual = sorted(path.name for path in directory.iterdir() if path.is_dir())
    if actual != lock[key]:
        fail(f"{key} checkout census differs from the protected lock")
    for case in actual:
        for asset in ("request.txt", "header-canonical-request.txt"):
            if not (directory / case / asset).is_file():
                fail(f"{key} case {case} is missing required asset {asset}")

license_path = checkout / required_scalars["license_path"]
if not license_path.is_file():
    fail("upstream license is missing")
blob = subprocess.run(
    ["git", "-C", str(checkout), "hash-object", str(license_path)],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout.strip()
if blob != required_scalars["license_blob"]:
    fail("upstream license blob differs from the protected lock")

print("check_signing_suite_lock: checkout matches commit, trees, license, and 40/38 census")
PY
