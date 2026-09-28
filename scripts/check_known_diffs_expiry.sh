#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   No entry of the differential's known-diffs register
#   (crates/difftest/known-diffs.toml, rustfs/backlog#1762) is past its
#   `expires` review date (a-df-0018). An entry due within
#   GATEWAY_KNOWN_DIFFS_WARN_DAYS days (default 30) is printed as a workflow
#   warning, so the review starts before the gate turns red.
#
#   `--due` prints the ids of every entry expired or due within the warning
#   window, one per line, and always exits 0 when the register reads: the
#   weekly `known-diffs-review` workflow files one issue from that list.
#
#   GATEWAY_KNOWN_DIFFS_TODAY=YYYY-MM-DD replaces today's date (self-test only).
#
# WHY
#   A temporary acceptance that nobody reviews is a permanent one. The review
#   date makes each entry come back; the warning window and the issue make it
#   come back before it blocks unrelated pull requests.
#
# HOW TO EXEMPT
#   There is no exemption. Review the entry: remove it if the difference is
#   gone, or extend `expires` with the argument check_known_diffs_ratchet.sh
#   asks for.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
REGISTER="${ROOT_DIR}/crates/difftest/known-diffs.toml"

fail() {
    printf 'check_known_diffs_expiry: %s\n' "$*" >&2
    exit 1
}

mode=gate
case "${1:-}" in
'') ;;
--due) mode=due ;;
*) fail "unknown argument: $1 (usage: check_known_diffs_expiry.sh [--due])" ;;
esac

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$REGISTER" ]] || fail "rule input is missing: crates/difftest/known-diffs.toml"

python3 - "$REGISTER" "$mode" "${GATEWAY_KNOWN_DIFFS_TODAY:-}" "${GATEWAY_KNOWN_DIFFS_WARN_DAYS:-30}" <<'PY'
from __future__ import annotations

import datetime
import sys
import tomllib

path, mode, today_text, warn_text = sys.argv[1:]


def fail(message: str) -> None:
    print(f"check_known_diffs_expiry: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    today = datetime.date.fromisoformat(today_text) if today_text else datetime.datetime.now(datetime.timezone.utc).date()
except ValueError:
    fail(f"GATEWAY_KNOWN_DIFFS_TODAY is not a date: {today_text!r}")
if not warn_text.isdigit():
    fail(f"GATEWAY_KNOWN_DIFFS_WARN_DAYS is not a number of days: {warn_text!r}")
horizon = today + datetime.timedelta(days=int(warn_text))

try:
    with open(path, "rb") as handle:
        document = tomllib.load(handle)
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot read the register: {error}")

expired, due = [], []
for position, entry in enumerate(document.get("diff", []), start=1):
    identifier = entry.get("id", f"entry {position}") if isinstance(entry, dict) else f"entry {position}"
    try:
        expires = datetime.date.fromisoformat(entry["expires"])
    except (KeyError, TypeError, ValueError):
        fail(f"{identifier}: no expires review date of the form YYYY-MM-DD")
    if expires < today:
        expired.append((identifier, expires))
    elif expires <= horizon:
        due.append((identifier, expires))

if mode == "due":
    for identifier, expires in expired + due:
        print(f"{identifier} {expires.isoformat()}")
    raise SystemExit(0)

for identifier, expires in due:
    print(f"::warning::known-diffs entry {identifier} is due for review on {expires.isoformat()}")
if expired:
    for identifier, expires in expired:
        print(f"crates/difftest/known-diffs.toml: {identifier} expired on {expires.isoformat()}", file=sys.stderr)
    fail(f"{len(expired)} register entr{'y' if len(expired) == 1 else 'ies'} past the review date (a-df-0018)")
print(f"check_known_diffs_expiry: no entry past its review date; {len(due)} due within {warn_text} days")
PY
