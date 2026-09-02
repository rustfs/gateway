#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# install_clients.sh
#
# WHAT THIS DOES
#   Installs every client at the version `compat/versions.toml` pins, and nothing else. No version
#   is written down here: `scripts/check_client_versions_pinned.sh` fails if one is, because a
#   second pin is how the installed client and the reported client silently drift apart.
#
#   Go clients are installed with `go install <module>@<version>`, so the Go module checksum
#   database verifies the source before it is built and `go version -m` can read the exact version
#   back out of the artefact. `ci/compat/report.py preflight` does read it back, and refuses to run
#   the matrix on a mismatch.
#
# USAGE
#   ci/compat/install_clients.sh            # install into $GOBIN (default ~/go/bin) and pip
# =============================================================================

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

problem() {
    printf 'install_clients: %s\n' "$*" >&2
    exit 3
}

command -v python3 >/dev/null 2>&1 || problem 'required command is missing: python3'
command -v go >/dev/null 2>&1 || problem 'required command is missing: go'

python3 - "$ROOT_DIR/compat/versions.toml" <<'PY' >"${TMPDIR:-/tmp}/compat-install.$$"
import shlex
import sys
import tomllib
from pathlib import Path

clients = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["clients"]
for name, spec in sorted(clients.items()):
    if spec["install"] == "go":
        print(shlex.join(["go", "install", f"{spec['module']}@{spec['version']}"]))
    elif spec["install"] == "pip":
        requirements = spec.get("requirements") or [f"{spec['package']}=={spec['version']}"]
        print(shlex.join(["python3", "-m", "pip", "install", "--disable-pip-version-check", *requirements]))
    else:
        raise SystemExit(f"install_clients: client {name} declares an unknown install method")
PY

plan="${TMPDIR:-/tmp}/compat-install.$$"
trap 'rm -f "$plan"' EXIT
while IFS= read -r command; do
    [[ -z "$command" ]] && continue
    printf 'install_clients: %s\n' "$command"
    eval "$command"
done <"$plan"

printf 'install_clients: done; PATH must include %s\n' "${GOBIN:-${GOPATH:-$HOME/go}/bin}"
