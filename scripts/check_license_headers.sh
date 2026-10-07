#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_license_headers.sh
#
# WHAT THIS CHECKS
#   That every tracked `.rs` file opens with the Apache-2.0 licence header used
#   across rustfs/rustfs:
#
#       // Copyright <year> RustFS Team
#       //
#       // Licensed under the Apache License, Version 2.0 (the "License");
#       // ...
#
#   The assertion is deliberately loose: the first 14 lines must contain the
#   line `Licensed under the Apache License, Version 2.0`. It is NOT a
#   byte-for-byte comparison, because the copyright year moves and future
#   contributors may be credited on the copyright line. What must not vary is
#   the licence grant itself.
#
#   Scope: tracked `*.rs` files only. `target/` is untracked and therefore never
#   seen; `generated/**` is excluded explicitly so that a future codegen output
#   tree does not have to carry per-file headers (the generator's own source
#   does). Shell scripts are not required to carry a header — the main
#   repository only headers 19 of its 72 scripts, and a guard nobody follows is
#   worse than no guard.
#
# WHY
#   ADR-0001 (licensing and provenance boundary): this project is Apache-2.0 and
#   is a clean-room implementation. A per-file licence header is what makes the
#   grant survive file-level copying — a file lifted out of this repository into
#   another project carries its licence with it, and a file arriving here
#   WITHOUT the header is exactly the case that needs provenance review before
#   it is merged. The header is therefore a provenance tripwire, not paperwork.
#
# HOW TO EXEMPT
#   Add the exact repository-relative path to
#   `scripts/allowances/license-header-allowances.txt` (create it if absent):
#
#       path/to/file.rs    # <why this file cannot carry the header>
#
#   Vendored third-party code under a compatible licence is the only expected
#   reason, and it belongs in a clearly named `vendor/` or `third_party/` tree
#   with its upstream licence text preserved.
#
# USAGE
#   scripts/check_license_headers.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_license_headers.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ALLOWANCE_FILE="${ROOT_DIR}/scripts/allowances/license-header-allowances.txt"

cd "$ROOT_DIR"

HEADER_MARKER='Licensed under the Apache License, Version 2.0'
HEADER_WINDOW=14

status=0

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_license_headers)" || exit 1

# Open each header in this interpreter instead of spawning head/grep for every source.
"$PYTHON" - "$ROOT_DIR" "$ALLOWANCE_FILE" "$HEADER_MARKER" "$HEADER_WINDOW" <<'PY' || status=1
import itertools
import os
from pathlib import Path
import subprocess
import sys

root, allowance_file, marker, window = sys.argv[1:]
marker = marker.encode()
allowances = set()
try:
    if os.path.isfile(allowance_file):
        # Keep the shell reader's newline-terminated records and space/tab normalization.
        for line in Path(allowance_file).read_bytes().split(b"\n")[:-1]:
            path = line.split(b"#", 1)[0].replace(b" ", b"").replace(b"\t", b"")
            if path:
                allowances.add(path)
except OSError as error:
    raise SystemExit(f"check_license_headers: cannot read allowances: {error}")

try:
    files = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--",
         "*.rs", ":!:target/*", ":!:generated/*", ":!:*/generated/*"],
        cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.split(b"\0")
except (OSError, subprocess.CalledProcessError) as error:
    raise SystemExit(f"check_license_headers: cannot enumerate Rust sources: {error}")

checked = 0
failed = False
for relative in files:
    if not relative or relative in allowances:
        continue
    path = os.path.join(os.fsencode(root), relative)
    if not os.path.isfile(path):
        continue
    checked += 1
    try:
        with open(path, "rb") as source:
            lines = list(itertools.islice(source, int(window)))
        if any(marker in line for line in lines):
            continue
        print(f"{os.fsdecode(relative)}: missing the Apache-2.0 licence header in the first {window} lines",
              file=sys.stderr)
    except OSError as error:
        print(f"{os.fsdecode(relative)}: cannot read Rust source: {error}", file=sys.stderr)
    failed = True
if checked == 0:
    print("check_license_headers: no tracked Rust sources to check.")
sys.exit(1 if failed else 0)
PY

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Prepend the standard header (licence block first, then `//!` module docs):

    // Copyright 2026 RustFS Team
    //
    // Licensed under the Apache License, Version 2.0 (the "License");
    // you may not use this file except in compliance with the License.
    // You may obtain a copy of the License at
    //
    //     http://www.apache.org/licenses/LICENSE-2.0
    //
    // Unless required by applicable law or agreed to in writing, software
    // distributed under the License is distributed on an "AS IS" BASIS,
    // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    // See the License for the specific language governing permissions and
    // limitations under the License.

If the file came from elsewhere, resolve its provenance before merging — see
docs/adr/0001-licensing-and-provenance-boundary.md.
EOF
fi

exit "$status"
