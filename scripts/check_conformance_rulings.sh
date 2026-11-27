#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   The committed conformance rulings ledger (conformance/rulings/rustfs-profile.toml,
#   rustfs/backlog#2757, rustfs/gateway#1631) is structurally valid, free of expired
#   entries, bound to existing corpus cases, and rules no in-process-only case:
#     1. All required inputs exist (fail-closed if the ledger, corpus cases, or
#        in-process-only census is missing).
#     2. The ledger matches crates/conformance/src/rulings.rs strictly: only
#        `[[ruling]]` rows, each with exact non-empty string keys `id`, `verdict`,
#        `issue`, `approved_by`, `expires`, no duplicate `id`, valid verdict
#        (`legacy-identical` | `accepted-change`), valid `<owner>/<repo>#<number>`
#        issue reference, and valid `YYYY-MM-DD` calendar date.
#     3. No ruling is past its `expires` review date (`expires < today`). Entries
#        due within GATEWAY_RULINGS_WARN_DAYS days (default 30) emit a workflow
#        warning.
#     4. Every ruled `id` exists in `conformance/cases/**/*.toml` (no stale or
#        unknown case IDs) and does not appear in `IN_PROCESS_ONLY`
#        (`crates/conformance/src/inprocess/in_process_only.rs`).
#
#   GATEWAY_RULINGS_TODAY=YYYY-MM-DD replaces today's date (self-test only).
#
# WHY
#   Unchecked rulings rot silently: expired entries, typos, renamed case IDs, or
#   harness-only cases would otherwise remain in the committed ledger unnoticed
#   until someone runs an external RustFS-profile conformance sweep by hand.
#
# HOW TO EXEMPT
#   There is no exemption. Retire passing or removed cases, fix malformed rows,
#   or review and renew expiring entries with maintainer sign-off.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_conformance_rulings)" || exit 1

fail() {
    printf 'check_conformance_rulings: %s\n' "$*" >&2
    exit 1
}

LEDGER="${ROOT_DIR}/conformance/rulings/rustfs-profile.toml"
CASES_DIR="${ROOT_DIR}/conformance/cases"
IN_PROCESS_ONLY="${ROOT_DIR}/crates/conformance/src/inprocess/in_process_only.rs"

[[ -f "$LEDGER" ]] || fail "required input is missing: conformance/rulings/rustfs-profile.toml"
[[ -d "$CASES_DIR" ]] || fail "required input is missing: conformance/cases"
[[ -f "$IN_PROCESS_ONLY" ]] || fail "required input is missing: crates/conformance/src/inprocess/in_process_only.rs"

"$PYTHON" - "$LEDGER" "$CASES_DIR" "$IN_PROCESS_ONLY" "${GATEWAY_RULINGS_TODAY:-}" "${GATEWAY_RULINGS_WARN_DAYS:-30}" <<'PY'
from __future__ import annotations

import datetime
import pathlib
import re
import sys
import tomllib

ledger_path = pathlib.Path(sys.argv[1])
cases_dir = pathlib.Path(sys.argv[2])
in_process_path = pathlib.Path(sys.argv[3])
today_text = sys.argv[4]
warn_text = sys.argv[5]

REQUIRED_FIELDS = ("id", "verdict", "issue", "approved_by", "expires")
REQUIRED_SET = set(REQUIRED_FIELDS)
VALID_VERDICTS = {"legacy-identical", "accepted-change"}
ISSUE_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+#[0-9]+$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
IN_PROCESS_CASE_RE = re.compile(r'\(\s*"(c-[a-z0-9-]+)"\s*,')


def fail(message: str) -> None:
    print(f"check_conformance_rulings: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    today = (
        datetime.date.fromisoformat(today_text)
        if today_text
        else datetime.datetime.now(datetime.timezone.utc).date()
    )
except ValueError:
    fail(f"GATEWAY_RULINGS_TODAY is not a date: {today_text!r}")
if today_text and not DATE_RE.fullmatch(today_text):
    fail(f"GATEWAY_RULINGS_TODAY must use YYYY-MM-DD: {today_text!r}")
if not warn_text.isdigit():
    fail(f"GATEWAY_RULINGS_WARN_DAYS is not a number of days: {warn_text!r}")
horizon = today + datetime.timedelta(days=int(warn_text))

try:
    document = tomllib.loads(ledger_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot read conformance/rulings/rustfs-profile.toml: {error}")

unknown_top = sorted(set(document) - {"ruling"})
if unknown_top:
    fail(
        f"unknown top-level key(s) {unknown_top}; a ledger holds `[[ruling]]` rows and nothing else"
    )

rows = document.get("ruling", [])
if not isinstance(rows, list):
    fail("`ruling` must be an array of tables, one `[[ruling]]` per row")

seen_ids: set[str] = set()
rulings: list[tuple[str, datetime.date]] = []
problems: list[str] = []

for index, row in enumerate(rows):
    if not isinstance(row, dict):
        problems.append(f"ruling {index} is not a table")
        continue
    raw_id = row.get("id")
    label = f"`{raw_id}`" if isinstance(raw_id, str) and raw_id.strip() else f"ruling {index}"
    unknown_keys = sorted(set(row) - REQUIRED_SET)
    if unknown_keys:
        problems.append(f"{label} has unknown key(s) {', '.join(unknown_keys)}")
        continue
    missing_or_bad = False
    values: dict[str, str] = {}
    for key in REQUIRED_FIELDS:
        if key not in row:
            problems.append(f"{label} has no `{key}`")
            missing_or_bad = True
            continue
        value = row[key]
        if not isinstance(value, str):
            problems.append(f"{label}: `{key}` must be a string")
            missing_or_bad = True
            continue
        if not value.strip():
            problems.append(f"{label}: `{key}` is empty")
            missing_or_bad = True
            continue
        values[key] = value
    if missing_or_bad:
        continue

    case_id = values["id"]
    if case_id in seen_ids:
        problems.append(f"`{case_id}` is ruled twice")
        continue
    seen_ids.add(case_id)

    if values["verdict"] not in VALID_VERDICTS:
        problems.append(
            f"`{case_id}`: verdict `{values['verdict']}` is not one of legacy-identical | accepted-change"
        )
    if not ISSUE_RE.fullmatch(values["issue"]):
        problems.append(
            f"`{case_id}`: issue `{values['issue']}` is not of the form `<owner>/<repository>#<number>`"
        )
    expires_text = values["expires"]
    if not DATE_RE.fullmatch(expires_text):
        problems.append(f"`{case_id}`: expires `{expires_text}` is not a calendar date of the form YYYY-MM-DD")
        continue
    try:
        expires = datetime.date.fromisoformat(expires_text)
    except ValueError:
        problems.append(f"`{case_id}`: expires `{expires_text}` is not a calendar date of the form YYYY-MM-DD")
        continue
    rulings.append((case_id, expires))

if problems:
    for problem in problems:
        print(f"conformance/rulings/rustfs-profile.toml: {problem}", file=sys.stderr)
    fail(f"{len(problems)} malformed ruling row(s)")

case_files = sorted(cases_dir.rglob("*.toml"))
if not case_files:
    fail("conformance/cases holds no `.toml` case files")

corpus_ids: set[str] = set()
for case_file in case_files:
    try:
        parsed = tomllib.loads(case_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse corpus case {case_file}: {error}")
    case_table = parsed.get("case")
    case_id = case_table.get("id") if isinstance(case_table, dict) else parsed.get("id")
    if isinstance(case_id, str) and case_id.strip():
        corpus_ids.add(case_id)

if not corpus_ids:
    fail("conformance/cases declared no case IDs")

in_process_text = in_process_path.read_text(encoding="utf-8")
table_marker = "const IN_PROCESS_ONLY:"
marker_pos = in_process_text.find(table_marker)
if marker_pos < 0:
    fail("cannot find `IN_PROCESS_ONLY` table in crates/conformance/src/inprocess/in_process_only.rs")
table_end = in_process_text.find("];", marker_pos)
if table_end < 0:
    fail("cannot find end of `IN_PROCESS_ONLY` table in crates/conformance/src/inprocess/in_process_only.rs")
in_process_ids = set(IN_PROCESS_CASE_RE.findall(in_process_text[marker_pos:table_end]))
if not in_process_ids:
    fail("`IN_PROCESS_ONLY` table yielded no case IDs")

unknown_cases = sorted(case_id for case_id, _ in rulings if case_id not in corpus_ids)
if unknown_cases:
    for case_id in unknown_cases:
        print(
            f"conformance/rulings/rustfs-profile.toml: `{case_id}` names no case in conformance/cases",
            file=sys.stderr,
        )
    fail(f"{len(unknown_cases)} ruling(s) name unknown or removed corpus case(s)")

unavailable_ruled = sorted(case_id for case_id, _ in rulings if case_id in in_process_ids)
if unavailable_ruled:
    for case_id in unavailable_ruled:
        print(
            f"conformance/rulings/rustfs-profile.toml: `{case_id}` is in IN_PROCESS_ONLY and must stay unruled",
            file=sys.stderr,
        )
    fail(f"{len(unavailable_ruled)} ruling(s) name case(s) unavailable on external endpoints")

expired = [(case_id, expires) for case_id, expires in rulings if expires < today]
due = [(case_id, expires) for case_id, expires in rulings if today <= expires <= horizon]

for case_id, expires in due:
    print(f"::warning::conformance ruling {case_id} is due for review on {expires.isoformat()}")
if expired:
    for case_id, expires in expired:
        print(
            f"conformance/rulings/rustfs-profile.toml: {case_id} expired on {expires.isoformat()}",
            file=sys.stderr,
        )
    fail(f"{len(expired)} ruling(s) past their review date")

print(
    f"OK: {len(rulings)} conformance ruling(s) valid, bound to {len(corpus_ids)} corpus cases, "
    f"0 in-process-only, 0 expired, {len(due)} due within {warn_text} days"
)
PY
