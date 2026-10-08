#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# gen_compat_table.sh
#
# WHAT THIS DOES
#   Rewrites the compatibility table in README.md from `compat/matrix.json`, between the two
#   marker comments. Nothing else in README.md is touched.
#
#   The table is generated because a hand-written one drifts from the manifest within a release and
#   nobody notices: the table is what a reader believes, and the manifest is what was measured.
#
#   The two skips are never shown as one (rustfs/backlog#2758): a cell the client cannot express is
#   `—`, a cell whose server does not register an operation it needs is `unregistered`, and each
#   scenario row counts them in two columns of their own.
#
# USAGE
#   scripts/gen_compat_table.sh          # rewrite README.md
#   scripts/gen_compat_table.sh --check  # fail if it would change (this is what CI runs)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

MODE="write"
if [[ "${1:-}" == "--check" ]]; then
    MODE="check"
elif [[ $# -gt 0 ]]; then
    printf 'gen_compat_table: unknown argument %s\n' "$1" >&2
    exit 2
fi

python3 - "$ROOT_DIR" "$MODE" <<'PY'
import json
import sys
from pathlib import Path

root, mode = Path(sys.argv[1]), sys.argv[2]
matrix_path = root / "compat/matrix.json"
readme_path = root / "README.md"
BEGIN = "<!-- BEGIN GENERATED COMPATIBILITY TABLE -->"
END = "<!-- END GENERATED COMPATIBILITY TABLE -->"

if not matrix_path.is_file():
    print("gen_compat_table: required input is missing: compat/matrix.json", file=sys.stderr)
    raise SystemExit(1)

matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
clients = matrix["clients"]
scenarios = sorted({row["id"] for client in clients for row in client["scenarios"]})
mark = {"pass": "pass", "fail": "FAIL", "client-unsupported": "—", "sut-unregistered": "unregistered"}
SKIPS = ("client-unsupported", "sut-unregistered")

against = matrix.get("measured_against") or {}
if against.get("sut") == "external":
    build = against.get("endpoint_build")
    measured = (
        f"Measured against an external `{against.get('product')}` endpoint "
        f"({'`Server: ' + build + '`' if build else 'no `Server` header'}) through `compat-sut --external` "
        f"at harness commit `{matrix['sut'].get('harness_commit')}` on {matrix['generated_at']}."
    )
else:
    measured = (
        f"Measured against `{matrix['sut']['name']}` {matrix['sut']['version']} at commit "
        f"`{matrix['sut']['commit']}` on {matrix['generated_at']}."
    )
lines = [BEGIN, ""]
lines.append(
    f"{measured} `—` is a scenario the client cannot express and `unregistered` one the server "
    f"does not serve; both are skips with a recorded reason, never a pass: see `compat/matrix.json`."
)
lines.append("")
header = (
    "| Scenario | "
    + " | ".join(f"{client['name']} {client['version']}" for client in clients)
    + " | client-unsupported | sut-unregistered |"
)
lines.append(header)
lines.append("| --- |" + " --- |" * (len(clients) + len(SKIPS)))
for scenario in scenarios:
    cells = []
    counts = {status: 0 for status in SKIPS}
    for client in clients:
        row = next((entry for entry in client["scenarios"] if entry["id"] == scenario), None)
        if row is None:
            cells.append("?")
            continue
        text = mark[row["status"]]
        if row["status"] == "fail":
            text = "FAIL (known)" if row.get("verdict") == "KNOWN" else "FAIL"
        if row["status"] in counts:
            counts[row["status"]] += 1
        cells.append(text)
    cells.extend(str(counts[status]) for status in SKIPS)
    lines.append(f"| `{scenario}` | " + " | ".join(cells) + " |")
lines.append("")
summary = matrix["summary"]
lines.append(
    f"{summary['pass']} pass, {summary['fail']} fail ({summary['known']} known), "
    f"{summary['client-unsupported']} not expressible by the client, "
    f"{summary['sut-unregistered']} not registered by the server."
)
streaming = matrix.get("streaming_signed_clients") or []
lines.append("")
if streaming:
    lines.append(
        "Clients observed sending real `STREAMING-AWS4-HMAC-SHA256` chunk-signed uploads: "
        + ", ".join(f"`{name}`" for name in streaming)
        + "."
    )
else:
    lines.append("No client was observed sending a `STREAMING-AWS4-HMAC-SHA256` chunk-signed upload.")
lines.append("")
lines.append(END)
generated = "\n".join(lines)

text = readme_path.read_text(encoding="utf-8")
if BEGIN not in text or END not in text:
    print(f"gen_compat_table: README.md has no {BEGIN} / {END} block", file=sys.stderr)
    raise SystemExit(1)
head, _, rest = text.partition(BEGIN)
_, _, tail = rest.partition(END)
updated = head + generated + tail

if mode == "check":
    if updated != text:
        print("gen_compat_table: README.md does not match compat/matrix.json; run scripts/gen_compat_table.sh", file=sys.stderr)
        raise SystemExit(1)
    print("OK: the README compatibility table matches compat/matrix.json")
    raise SystemExit(0)

readme_path.write_text(updated, encoding="utf-8")
print(f"OK: rewrote the README compatibility table from compat/matrix.json ({len(clients)} clients)")
PY
