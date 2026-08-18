#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps the error code to HTTP status mapping total, single-sourced, and free of dead rows.
# WHY: rustfs/backlog#1694. A code with no row used to take a silent 400 fallback, which reads
# exactly like a mapped code — six codes operations declare they can produce were hiding there.
# The fallback is gone, so the failure that replaces it must be loud: a declared code with no row,
# a second hand-written table, a 5xx that nobody allowlisted, or a row nothing can reach.
# HOW TO EXEMPT: A row with no use site yet goes in allowances/error-status-unreferenced.txt with
# a reason. There is no exemption for the other four rules.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_error_status_total: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'

python3 - "$ROOT_DIR" <<'PYEOF'
from __future__ import annotations

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])

AUTHORITY = "model/overlays/error-status.toml"
RUNTIME = "generated/error_status.rs"
DECLARED = "generated/error_codes.rs"
TYPE_SOURCE = "crates/types/src/scalar/error_code.rs"
ALLOWANCE = "allowances/error-status-unreferenced.txt"


def fail(message: str) -> None:
    print(f"check_error_status_total: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(relative: str) -> str:
    path = root / relative
    # A missing input is a failure, never a skip: every one of these paths always exists, so an
    # absent file means the tree moved and the guard would otherwise report green over nothing.
    if not path.is_file():
        fail(f"required input is missing: {relative}")
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The authority
# ---------------------------------------------------------------------------
authority_text = read(AUTHORITY)
rows: list[dict[str, object]] = []
current: dict[str, object] | None = None
for line in authority_text.splitlines():
    stripped = line.strip()
    if stripped == "[[code]]":
        current = {}
        rows.append(current)
        continue
    if current is None or not stripped or stripped.startswith("#"):
        continue
    match = re.match(r'^(name|constant)\s*=\s*"([A-Za-z0-9_]+)"$', stripped)
    if match:
        current[match.group(1)] = match.group(2)
        continue
    match = re.match(r"^status\s*=\s*([0-9]{3})$", stripped)
    if match:
        current["status"] = int(match.group(1))
        continue
    match = re.match(r"^server_fault\s*=\s*(true|false)$", stripped)
    if match:
        current["server_fault"] = match.group(1) == "true"

if not rows:
    fail(f"{AUTHORITY} declares no `[[code]]` row")
for index, row in enumerate(rows):
    for key in ("name", "constant", "status"):
        if key not in row:
            fail(f"{AUTHORITY}: the row at position {index} has no `{key}`")

authority = {str(row["name"]): row for row in rows}
if len(authority) != len(rows):
    fail(f"{AUTHORITY} declares one wire code twice; one of the two statuses would win silently")
constants = {str(row["constant"]) for row in rows}
if len(constants) != len(rows):
    fail(f"{AUTHORITY} declares one constant twice")

# ---------------------------------------------------------------------------
# Rule 1: the 5xx allowlist, in both directions
# ---------------------------------------------------------------------------
for row in rows:
    status = int(row["status"])  # type: ignore[arg-type]
    flagged = bool(row.get("server_fault", False))
    if status >= 500 and not flagged:
        fail(
            f"{AUTHORITY}: `{row['name']}` maps to {status} without `server_fault = true`; a client "
            "error in the 5xx band is retried and trips a circuit breaker"
        )
    if status < 500 and flagged:
        fail(f"{AUTHORITY}: `{row['name']}` is flagged `server_fault` but maps to {status}")
    if not 100 <= status <= 599:
        fail(f"{AUTHORITY}: `{row['name']}` maps to {status}, which is not an HTTP status")

# ---------------------------------------------------------------------------
# Rule 2: one table. The runtime table is the authority, rendered.
# ---------------------------------------------------------------------------
runtime_text = read(RUNTIME)
runtime_constants = set(re.findall(r"^    pub const ([A-Z0-9_]+): Self = Self \{$", runtime_text, re.M))
runtime_rows = dict(re.findall(r'^    \("([A-Za-z0-9]+)", StatusCode::([A-Z_]+)\),$', runtime_text, re.M))
runtime_names = set(runtime_rows)
# The constant spelling per status, so a hand-edited status in the generated file is caught too:
# comparing names alone would let `("NoSuchKey", StatusCode::OK)` through.
STATUS_NAMES = {
    200: "OK", 204: "NO_CONTENT", 206: "PARTIAL_CONTENT", 301: "MOVED_PERMANENTLY", 304: "NOT_MODIFIED",
    307: "TEMPORARY_REDIRECT", 400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED", 408: "REQUEST_TIMEOUT", 409: "CONFLICT", 411: "LENGTH_REQUIRED",
    412: "PRECONDITION_FAILED", 413: "PAYLOAD_TOO_LARGE", 416: "RANGE_NOT_SATISFIABLE", 429: "TOO_MANY_REQUESTS",
    500: "INTERNAL_SERVER_ERROR", 501: "NOT_IMPLEMENTED", 502: "BAD_GATEWAY", 503: "SERVICE_UNAVAILABLE",
    504: "GATEWAY_TIMEOUT",
}
if runtime_constants != constants:
    missing = sorted(constants - runtime_constants)
    extra = sorted(runtime_constants - constants)
    fail(
        f"{RUNTIME} and {AUTHORITY} disagree about the constants: absent from the generated table "
        f"{missing}, present without a row {extra}; regenerate with `cargo xtask codegen`"
    )
if runtime_names != set(authority):
    fail(f"{RUNTIME} and {AUTHORITY} disagree about the wire codes; regenerate with `cargo xtask codegen`")
for row in rows:
    name, status = str(row["name"]), int(row["status"])  # type: ignore[arg-type]
    expected = STATUS_NAMES.get(status)
    if expected is None:
        fail(f"{AUTHORITY}: `{name}` maps to {status}, which has no `StatusCode` constant")
    if runtime_rows[name] != expected:
        fail(
            f"{RUNTIME} and {AUTHORITY} disagree about `{name}`: the row says {status} "
            f"(`StatusCode::{expected}`) and the generated table says `StatusCode::{runtime_rows[name]}`; "
            "regenerate with `cargo xtask codegen`"
        )

# ---------------------------------------------------------------------------
# Rule 3: no second hand-written table, and no fallback to fall back to
# ---------------------------------------------------------------------------
type_text = read(TYPE_SOURCE)
# Comments are excluded from both checks below. The `custom` doc example must show a status and an
# example is not a table; and a commented-out `include!` is not an include, which is exactly how a
# substring test would have read it.
code = "\n".join(line for line in type_text.splitlines() if not line.lstrip().startswith(("///", "//!", "//")))
if 'include!("../../../../generated/error_status.rs");' not in code:
    fail(f"{TYPE_SOURCE} no longer includes the generated table")
hand_written = re.findall(r"StatusCode::[A-Z_]+", code)
if hand_written:
    fail(
        f"{TYPE_SOURCE} names {sorted(set(hand_written))} directly; the status of a code comes from "
        f"{AUTHORITY} alone, and a second hand-written answer here is the drift this guard exists for"
    )
custom = re.search(r"pub fn custom\((?P<args>[^)]*)\)", type_text)
if custom is None:
    fail(f"{TYPE_SOURCE} has no `ErrorCode::custom`")
if "status: StatusCode" not in custom.group("args"):
    fail(
        "`ErrorCode::custom` no longer makes its caller name a status; an implicit one is a status "
        "nobody chose, which is the defect rustfs/backlog#1694 removed"
    )
for path in sorted(root.glob("crates/*/src/**/*.rs")) + sorted(root.glob("crates/*/tests/**/*.rs")):
    if "generated" in path.parts:
        continue
    if "FALLBACK_STATUS" in path.read_text(encoding="utf-8"):
        fail(f"{path.relative_to(root)} reintroduces a fallback status")

# ---------------------------------------------------------------------------
# Rule 4: totality. Every code an operation can produce has a row.
# ---------------------------------------------------------------------------
declared_text = read(DECLARED)
produced = set(re.findall(r'^    \("([A-Za-z0-9]+)", &\[', declared_text, re.M))
not_configured = set(re.findall(r'^    \("[A-Za-z0-9]+", "([A-Za-z0-9]+)"\),$', declared_text, re.M))
spec_dir = root / "spec/operations"
if not spec_dir.is_dir():
    fail("required input is missing: spec/operations")
missing_error = set()
for spec in sorted(spec_dir.glob("*.toml")):
    missing_error.update(re.findall(r'missing_error = "([A-Za-z0-9]+)"', spec.read_text(encoding="utf-8")))

for label, codes in (
    ("an operation declares it can produce", produced),
    ("an operation names it for an unconfigured subresource", not_configured),
    ("a codec raises it for a missing member", missing_error),
):
    orphans = sorted(codes - set(authority))
    if orphans:
        fail(
            f"{orphans} have no row in {AUTHORITY} and {label}; without a row there is no status to "
            "answer with, and before rustfs/backlog#1694 that was a silent 400"
        )

# ---------------------------------------------------------------------------
# Rule 5: the pre-authentication vocabulary is inside the authority
#
# `AuthError::code()` returns a wire spelling, and `render::from_auth` resolves it through
# `ErrorCode::known`. A variant whose spelling has no row would fall to that call's `unwrap_or`,
# which is why the arms are read here rather than trusted: `AuthError` is `#[non_exhaustive]`, so
# no test outside `rustfs-gateway-sig` can prove it covers every variant.
# ---------------------------------------------------------------------------
verdict = read("crates/sig/src/verdict.rs")
body = re.search(r"pub const fn code\(&self\) -> &'static str \{(?P<arms>.*?)\n    \}", verdict, re.S)
if body is None:
    fail("crates/sig/src/verdict.rs no longer has `AuthError::code`; this rule reads its arms")
auth_codes = set(re.findall(r'=> "([A-Za-z0-9]+)"', body.group("arms")))
if not auth_codes:
    fail("`AuthError::code` returned no spellings; the arm pattern moved and this rule went blind")
undeclared = sorted(auth_codes - set(authority))
if undeclared:
    fail(
        f"`AuthError::code` can answer {undeclared}, which {AUTHORITY} does not declare; a code "
        "answered before authentication has no status to fall back to"
    )

# ---------------------------------------------------------------------------
# Rule 6: no dead rows, and no stale allowance
# ---------------------------------------------------------------------------
referenced: set[str] = set()
used_constants: set[str] = set()
# Wire spellings written as literals count too: `AuthError::code()` returns one, and a row it
# reaches through `ErrorCode::known` is not dead just because no constant is named at that line.
literals: set[str] = set()
for path in sorted(root.glob("crates/**/*.rs")) + sorted(root.glob("xtask/**/*.rs")):
    if "generated" in path.parts or "target" in path.parts:
        continue
    text = path.read_text(encoding="utf-8")
    used_constants.update(re.findall(r"ErrorCode::([A-Z0-9_]+)\b", text))
    literals.update(re.findall(r'"([A-Za-z0-9]+)"', text))
case_dir = root / "conformance/cases"
if case_dir.is_dir():
    for path in sorted(case_dir.rglob("*.toml")):
        literals.update(re.findall(r'"([A-Za-z0-9]+)"', path.read_text(encoding="utf-8")))
for row in rows:
    name, constant = str(row["name"]), str(row["constant"])
    if constant in used_constants or name in produced or name in not_configured or name in missing_error:
        referenced.add(name)
    elif name in literals:
        referenced.add(name)

allowance_text = read(ALLOWANCE)
allowed: dict[str, str] = {}
for line in allowance_text.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if "|" not in line:
        fail(f"{ALLOWANCE}: `{line}` is not `WireCode|reason`")
    code, reason = line.split("|", 1)
    if not reason.strip():
        fail(f"{ALLOWANCE}: `{code}` has no reason")
    if code in allowed:
        fail(f"{ALLOWANCE}: `{code}` is listed twice")
    allowed[code] = reason

unknown = sorted(set(allowed) - set(authority))
if unknown:
    fail(f"{ALLOWANCE} names {unknown}, which {AUTHORITY} does not declare")
stale = sorted(code for code in allowed if code in referenced)
if stale:
    fail(
        f"{ALLOWANCE} still excuses {stale}, which the tree now reaches; delete the line, or the "
        "ledger stops meaning what it says"
    )
dead = sorted(set(authority) - referenced - set(allowed))
if dead:
    fail(
        f"{dead} have a row in {AUTHORITY} that nothing reaches: no `ErrorCode::` use site, no "
        f"operation, no conformance case. Wire it up or add it to {ALLOWANCE} with a reason"
    )

print(
    f"OK: {len(rows)} error codes mapped, "
    f"{sum(1 for row in rows if row.get('server_fault'))} allowlisted 5xx, "
    f"{len(allowed)} unreferenced rows on the ledger, 0 codes without a status"
)
PYEOF
