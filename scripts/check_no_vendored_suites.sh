#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_vendored_suites.sh
#
# WHAT THIS CHECKS
#   That no part of an external acceptance suite is committed to this
#   repository. Two detectors, because a rename defeats either one alone:
#
#     1. Path fingerprints — a tracked file under an `s3tests/`,
#        `s3tests_boto3/`, `s3-tests/` or `mint/run/` directory, or named
#        `s3tests.conf.SAMPLE`.
#     2. Content fingerprints — a tracked file that imports `s3tests_boto3`,
#        declares itself part of the Ceph suite, or carries mint's runner
#        preamble.
#
#   `ci/**` and `scripts/**` are exempt from the path rule and not from the
#   content rule: this project's own runner lives at `ci/s3tests/`, which is a
#   directory name, and a directory name is not somebody else's source.
#
# WHY
#   Vendoring is the decision that is cheap to make and expensive to undo.
#   ceph/s3-tests is MIT and minio/mint is Apache-2.0, so a copy would be
#   lawful with attribution — and it would still be wrong: an upstream copy in
#   the tree has to be merged forward by hand on every bump, and the thing that
#   makes a weekly run meaningful is that it ran upstream's cases and not this
#   repository's edited memory of them. Calling out to a pinned revision costs
#   nothing and forecloses both problems.
#
#   The related clean-room rule about the MinIO *server* — AGPL, and never to
#   be read, ported or vendored — is a separate and stronger prohibition, and
#   lives in scripts/check_no_minio_source.sh.
#
# HOW TO EXEMPT
#   None. Call the suite at a pinned revision; see ci/s3tests/pins.env.
#
# USAGE
#   scripts/check_no_vendored_suites.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_vendored_suites.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v git >/dev/null 2>&1 || {
    printf 'check_no_vendored_suites: required command is missing: git\n' >&2
    exit 1
}

listing="$(mktemp "${TMPDIR:-/tmp}/gateway-vendored-suites.XXXXXX")"
trap 'rm -f "$listing"' EXIT
if ! git -C "$ROOT_DIR" ls-files --cached --others --exclude-standard >"$listing"; then
    printf 'check_no_vendored_suites: cannot list working-tree files\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" "$listing" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
paths = [line for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines() if line]
if not paths:
    print("check_no_vendored_suites: the file listing is empty; there is nothing to judge", file=sys.stderr)
    raise SystemExit(1)

SELF = "scripts/check_no_vendored_suites.sh"

# A path segment that only upstream would produce. `ci/s3tests` is this repository's runner
# directory and is not in this list on purpose — the directory name is not the source.
PATH_SEGMENTS = ("s3tests_boto3", "s3-tests")
PATH_EXACT = ("s3tests.conf.SAMPLE",)

# A line only upstream's own files carry. Written as fragments so this guard does not itself
# become the thing it forbids.
CONTENT_PATTERNS = (
    (re.compile(r"^\s*(?:from|import)\s+s3tests_boto3\b", re.MULTILINE), "imports the Ceph suite's own package"),
    (re.compile(r"^\s*from\s+\.\s+import\s+get_client\b", re.MULTILINE), "carries the Ceph suite's fixture import"),
    (re.compile(r"MINT_(?:MODE|DATA_DIR)\s*=", re.MULTILINE), "carries mint's runner environment preamble"),
)

failures: list[str] = []
for path in paths:
    if path == SELF:
        continue
    segments = path.split("/")
    exempt_tree = path.startswith(("ci/", "scripts/", "docs/"))
    if not exempt_tree:
        for segment in PATH_SEGMENTS:
            if segment in segments:
                failures.append(f"{path}: sits under a vendored copy of an external suite ({segment}/)")
                break
        if segments[-1] in PATH_EXACT:
            failures.append(f"{path}: is a file from the Ceph suite's own tree")
    if "mint" in segments and "run" in segments:
        failures.append(f"{path}: sits under a vendored copy of mint's runner tree")

    file_path = root / path
    if not file_path.is_file() or file_path.is_symlink():
        continue
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        continue
    for pattern, description in CONTENT_PATTERNS:
        if pattern.search(text):
            failures.append(f"{path}: {description}; external suites are called at a pinned revision, never copied")

if failures:
    for failure in sorted(set(failures)):
        print(f"check_no_vendored_suites: {failure}", file=sys.stderr)
    print(
        "\nExternal suites are invoked as pinned external runners. See ci/s3tests/pins.env "
        "and docs/third-party.md.",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"OK: no vendored suite sources in {len(paths)} tracked file(s)")
PYEOF
