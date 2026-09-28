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
#   back out of the artefact. `venv` clients get a virtualenv each under `$COMPAT_CLIENTS_DIR`, and
#   `program` clients — SDK driver programs — are copied there and built from their own lock file.
#   `ci/compat/report.py preflight` reads every installed version back, and refuses to run the
#   matrix on a mismatch.
#
#   A toolchain a client needs (go, node, cargo, mvn, dotnet) is the runner's job; its absence
#   stops the install with exit 3 rather than leaving a client half-built.
#
# USAGE
#   ci/compat/install_clients.sh [--clients a,b]
#       Go binaries go to $GOBIN (default ~/go/bin), pip clients into the running interpreter, and
#       everything else under $COMPAT_CLIENTS_DIR (default target/compat-clients).
# =============================================================================

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

problem() {
    printf 'install_clients: %s\n' "$*" >&2
    exit 3
}

CLIENT_FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --clients)
        CLIENT_FILTER="${2:?--clients requires a list}"
        shift 2
        ;;
    *)
        problem "unknown argument $1"
        ;;
    esac
done

command -v python3 >/dev/null 2>&1 || problem 'required command is missing: python3'

COMPAT_CLIENTS_DIR="${COMPAT_CLIENTS_DIR:-$ROOT_DIR/target/compat-clients}"
export COMPAT_CLIENTS_DIR
mkdir -p "$COMPAT_CLIENTS_DIR/bin"
export PATH="$COMPAT_CLIENTS_DIR/bin:$PATH"

plan="$(mktemp "${TMPDIR:-/tmp}/compat-install.XXXXXX")"
trap 'rm -f "$plan"' EXIT

# One line per client: `<name> <toolchain> <command>`. The toolchain is checked before the command
# runs, so a missing one names itself instead of surfacing as a build error three layers down.
python3 - "$ROOT_DIR" "$COMPAT_CLIENTS_DIR" "$CLIENT_FILTER" <<'PY' >"$plan"
import shlex
import sys
import tomllib
from pathlib import Path

root, clients_dir, wanted = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
clients = tomllib.loads((root / "compat/versions.toml").read_text(encoding="utf-8"))["clients"]
selected = {name for name in wanted.split(",") if name} if wanted else set(clients)
unknown = sorted(selected - set(clients))
if unknown:
    raise SystemExit(f"install_clients: --clients names undeclared client(s) {unknown}")
for name, spec in sorted(clients.items()):
    if name not in selected:
        continue
    out = clients_dir / name
    method = spec["install"]
    if method == "go":
        toolchain = "go"
        command = shlex.join(["go", "install", f"{spec['module']}@{spec['version']}"])
    elif method == "pip":
        toolchain = "python3"
        requirements = spec.get("requirements") or [f"{spec['package']}=={spec['version']}"]
        command = shlex.join(["python3", "-m", "pip", "install", "--disable-pip-version-check", *requirements])
    elif method == "venv":
        toolchain = "python3"
        venv = out / "venv"
        command = " && ".join(
            [
                shlex.join(["rm", "-rf", str(out)]),
                shlex.join(["python3", "-m", "venv", str(venv)]),
                shlex.join(
                    [str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "--quiet"]
                    + list(spec["requirements"])
                ),
                shlex.join(["ln", "-sf", str(venv / "bin" / spec["binary"]), str(clients_dir / "bin" / spec["binary"])]),
            ]
        )
    elif method == "program":
        # Built from a copy, so a build never writes into the source tree and an artefact left by an
        # earlier pin cannot survive into this one.
        toolchain = spec["toolchain"]
        command = " && ".join(
            [
                shlex.join(["rm", "-rf", str(out)]),
                shlex.join(["mkdir", "-p", str(out)]),
                shlex.join(["cp", "-R", f"{root / spec['source']}/.", str(out / "src")]),
                "cd " + shlex.quote(str(out / "src")),
                shlex.join(["env", f"COMPAT_CLIENT_OUT={out}", "bash", "-c", spec["build"]]),
            ]
        )
    else:
        raise SystemExit(f"install_clients: client {name} declares an unknown install method {method!r}")
    print(f"{name} {toolchain} {command}")
PY

while IFS=' ' read -r name toolchain command; do
    [[ -z "$name" ]] && continue
    command -v "$toolchain" >/dev/null 2>&1 || problem "client $name needs $toolchain, which is not on PATH"
    printf 'install_clients: %s: %s\n' "$name" "$command"
    (eval "$command") || problem "client $name did not install"
done <"$plan"

printf 'install_clients: done; PATH must include %s and %s\n' \
    "$COMPAT_CLIENTS_DIR/bin" "${GOBIN:-${GOPATH:-$HOME/go}/bin}"
