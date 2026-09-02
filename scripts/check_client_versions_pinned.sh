#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_client_versions_pinned.sh
#
# WHAT THIS CHECKS
#   `compat/versions.toml` pins every compatibility-matrix client to one exact version, and no
#   other file in the matrix writes a client version down a second time.
#
#     1. The file exists and declares at least one client. A missing input fails; it does not skip.
#     2. Every client has a `version` that is not `latest`, `*`, `main`, `master`, `HEAD`, `devel`,
#        `stable`, `edge`, `nightly`, empty, or a range operator (`^ ~ > < ,`).
#     3. Every client declares an install method this matrix knows how to verify, and the fields
#        that method needs.
#     4. No driver, workflow or runner script contains a version-bearing install command. A second
#        pin is how the two silently disagree, and then a red matrix is unattributable.
#
# WHY
#   A client's behaviour changes between releases: which payload mode it declares, whether it sends
#   a trailer, how it paginates. Without an exact pin, a matrix that turns red says nothing about
#   whether the gateway changed or the client did — which is the one question the matrix exists to
#   answer. rustfs/backlog#1765 §4.3.
#
# HOW TO EXEMPT
#   There is no exemption. Bump the pin in `compat/versions.toml`, in its own reviewed pull request.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_client_versions_pinned: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT_DIR" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
manifest = root / "compat/versions.toml"
failures = []


def fail(message):
    failures.append(message)


if not manifest.is_file():
    print("check_client_versions_pinned: required input is missing: compat/versions.toml", file=sys.stderr)
    raise SystemExit(1)

document = tomllib.loads(manifest.read_text(encoding="utf-8"))
clients = document.get("clients")
if not isinstance(clients, dict) or not clients:
    fail("compat/versions.toml declares no clients")
    clients = {}

FLOATING = {"latest", "*", "main", "master", "head", "devel", "stable", "edge", "nightly", ""}
REQUIRED = {"pip": ("package",), "go": ("module", "module_version_path", "binary")}

for name, spec in sorted(clients.items()):
    if not isinstance(spec, dict):
        fail(f"client {name} is not a table")
        continue
    version = str(spec.get("version", "")).strip()
    if version.lower() in FLOATING:
        fail(f"client {name} has a floating version {version!r}; pin one exact version")
    if re.search(r"[\^~<>,]|\.\*|\bx\b", version):
        fail(f"client {name} has a version range {version!r}; pin one exact version")
    install = spec.get("install")
    if install not in REQUIRED:
        fail(f"client {name} declares an install method {install!r} this matrix cannot verify")
        continue
    for field in REQUIRED[install]:
        if not spec.get(field):
            fail(f"client {name} installs with {install} but declares no {field}")

# A second place that names a version is a second thing to keep in sync, and the matrix would then
# run one version while reporting another.
elsewhere = [root / "ci/compat/run_matrix.sh", root / "ci/compat/install_clients.sh", root / ".github/workflows/client-matrix.yml"]
elsewhere.extend(sorted(root.glob("compat/drivers/*/run.sh")))
pattern = re.compile(r"(pip install\s+\S+==|go install\s+\S+@v?[0-9])")
for path in elsewhere:
    if not path.is_file():
        continue
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        if pattern.search(line):
            fail(f"{path.relative_to(root)}:{number} pins a client version outside compat/versions.toml")

if failures:
    for line in failures:
        print(f"check_client_versions_pinned: {line}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: {len(clients)}/{len(clients)} clients pinned, no floating version")
PY
