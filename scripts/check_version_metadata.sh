#!/usr/bin/env bash
set -euo pipefail

# The public DTO crate version identifies the AWS model snapshot it represents.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

python3 - "$ROOT_DIR" <<'PY'
import datetime
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
workspace = root / "Cargo.toml"
manifest = root / "crates/types/Cargo.toml"
for path in (workspace, manifest):
    if not path.is_file():
        print(f"check_version_metadata.sh: required input is missing: {path.relative_to(root)}", file=sys.stderr)
        raise SystemExit(1)

dependency_match = re.search(
    r'(?m)^rustfs-gateway-types\s*=\s*\{[^\n]*\bversion\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"[^\n]*\}\s*$',
    workspace.read_text(),
)
types_match = re.search(r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)\+aws\.([0-9]{4}-[0-9]{2}-[0-9]{2})"\s*$', manifest.read_text())
if dependency_match is None:
    print("check_version_metadata.sh: root types dependency version is missing or malformed", file=sys.stderr)
    raise SystemExit(1)
if types_match is None:
    print("check_version_metadata.sh: crates/types version must end in +aws.YYYY-MM-DD", file=sys.stderr)
    raise SystemExit(1)
if types_match.group(1) != dependency_match.group(1):
    print("check_version_metadata.sh: crates/types numeric version differs from the root dependency", file=sys.stderr)
    raise SystemExit(1)
try:
    datetime.date.fromisoformat(types_match.group(2))
except ValueError:
    print("check_version_metadata.sh: AWS model date is not a calendar date", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: rustfs-gateway-types {types_match.group(1)}+aws.{types_match.group(2)}")
PY
