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
#     5. Every pip requirement a client installs is exact: `name==<version>`, or a direct archive
#        URL carrying a `#sha256=` digest pip verifies. The client's own pin appears in one of them.
#     6. A `program` client's lock file — the one place a second copy of the version is
#        unavoidable — names the SDK exactly once, at exactly the version pinned here.
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

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_client_versions_pinned)" || exit 1

"$PYTHON" - "$ROOT_DIR" <<'PY'
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
REQUIRED = {
    "pip": ("package",),
    "go": ("module", "module_version_path", "binary"),
    "venv": ("requirements", "binary", "version_command", "version_pattern"),
    "program": ("source", "toolchain", "build", "version_command", "lock_file", "lock_pattern"),
}
EXACT_REQUIREMENT = re.compile(r"^[A-Za-z0-9._-]+(==[A-Za-z0-9.+!-]+| @ https://\S+#sha256=[0-9a-f]{64})$")

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
    missing = [field for field in REQUIRED[install] if not spec.get(field)]
    for field in missing:
        fail(f"client {name} installs with {install} but declares no {field}")
    if missing:
        continue
    requirements = spec.get("requirements") or []
    for requirement in requirements:
        if not EXACT_REQUIREMENT.match(str(requirement)):
            fail(f"client {name} installs {requirement!r}, which is not an exact pin")
    if requirements and not any(
        str(requirement).endswith(f"=={version}") or f"/{version}." in str(requirement) for requirement in requirements
    ):
        fail(f"client {name} is pinned at {version!r} but none of its requirements installs that version")
    if install == "program":
        lock = root / spec["source"] / spec["lock_file"]
        if not lock.is_file():
            fail(f"client {name} names lock file {spec['source']}/{spec['lock_file']}, which does not exist")
            continue
        locked = re.findall(spec["lock_pattern"], lock.read_text(encoding="utf-8"), flags=re.MULTILINE)
        if len(locked) != 1:
            fail(f"client {name}: {spec['lock_file']} matches its lock_pattern {len(locked)} time(s), expected exactly once")
        elif locked[0] != version:
            fail(f"client {name} is pinned at {version!r} but {spec['lock_file']} locks {locked[0]!r}")

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
