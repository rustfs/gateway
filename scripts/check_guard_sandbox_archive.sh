#!/usr/bin/env bash
set -euo pipefail

# WHAT: `make_sandbox` must create and extract a temporary archive in separate steps.
# WHY: rustfs/gateway#66 records a stream whose producer failed with `Write error` while the
#      extractor returned success; both archive phases must fail closed and clean partial state.
# HOW TO EXEMPT: no exemptions; this is the guard self-test's own isolation boundary.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SOURCE="${ROOT_DIR}/scripts/test_guard_scripts.sh"

if [[ ! -f "$SOURCE" ]]; then
    printf 'check_guard_sandbox_archive.sh: required input is missing: scripts/test_guard_scripts.sh\n' >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_guard_sandbox_archive.sh: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$SOURCE" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
text = source.read_text()
start = text.find("make_sandbox() {")
end = text.find("cleanup_sandbox() {", start)
if start < 0 or end < 0:
    print("check_guard_sandbox_archive.sh: cannot locate make_sandbox", file=sys.stderr)
    raise SystemExit(1)
body = text[start:end]

streaming_tar = r"^[ \t]*(?!#)[^\n#]*\btar\s+-(?:c|x)f\s+-"
if re.search(streaming_tar, body, re.MULTILINE):
    print("check_guard_sandbox_archive.sh: make_sandbox must not stream a tar archive", file=sys.stderr)
    raise SystemExit(1)

if not re.search(r"^\s*local\s+dir\s+list\s+archive\s*$", body, re.MULTILINE):
    print("check_guard_sandbox_archive.sh: make_sandbox must own a temporary archive path", file=sys.stderr)
    raise SystemExit(1)
for label, line in (
    ("file list", 'list="${dir}.files"'),
    ("archive", 'archive="${dir}.tar"'),
):
    if not re.search(r"^\s*" + re.escape(line) + r"\s*$", body, re.MULTILINE):
        print(f"check_guard_sandbox_archive.sh: {label} must derive from the unique sandbox path", file=sys.stderr)
        raise SystemExit(1)

def failure_branch_pattern(label: str, pattern: str) -> re.Match[str]:
    match = re.search(pattern, body, re.MULTILINE | re.DOTALL)
    if match is None:
        print(f"check_guard_sandbox_archive.sh: {label} must have an explicit failure branch", file=sys.stderr)
        raise SystemExit(1)
    branch = match.group("failure")
    for required in ('rm -f "$list" "$archive" || true', 'rm -rf "$dir" || true', "return 1"):
        executable = r"^\s*" + re.escape(required) + r"\s*$"
        if not re.search(executable, branch, re.MULTILINE):
            print(f"check_guard_sandbox_archive.sh: {label} failure must run: {required}", file=sys.stderr)
            raise SystemExit(1)
    return match

def failure_branch(label: str, header: str) -> re.Match[str]:
    pattern = r"^\s*" + re.escape(header) + r"\s*$\n(?P<failure>.*?)^\s*fi\s*$"
    return failure_branch_pattern(label, pattern)

failure_branch_pattern(
    "file-list creation",
    r'^\s*if ! \(\s*$\n'
    r'^\s*cd "\$REPO_ROOT" &&\s*$\n'
    r'^\s*git ls-files >"\$list" &&\s*$\n'
    r'^\s*git ls-files --others --exclude-standard >>"\$list" &&\s*$\n'
    r'^\s*sort -u -o "\$list" "\$list"\s*$\n'
    r'^\s*\); then\s*$\n'
    r'(?P<failure>.*?)^\s*fi\s*$',
)
failure_branch(
    "archive creation",
    'if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then',
)
failure_branch(
    "archive extraction",
    'if ! (cd "$dir" && tar -xf "$archive"); then',
)
failure_branch("successful extraction cleanup", 'if ! rm -f "$list" "$archive"; then')
failure_branch("sandbox git initialization", 'if ! (cd "$dir" && git init -q .); then')
failure_branch("sandbox git index creation", 'if ! (cd "$dir" && git add -A >/dev/null 2>&1); then')
commit = failure_branch(
    "sandbox base commit",
    'if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then',
)
published = re.search(r'^\s*SANDBOX="\$dir"\s*$', body, re.MULTILINE)
if published is None or published.start() < commit.end():
    print("check_guard_sandbox_archive.sh: SANDBOX must be published only after the base commit", file=sys.stderr)
    raise SystemExit(1)

print("OK: guard sandbox archive creation and extraction fail closed")
PY
