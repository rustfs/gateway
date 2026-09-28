#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-PR

# =============================================================================
# WHAT THIS CHECKS
#   The known-diffs register of the gateway/s3s differential
#   (crates/difftest/known-diffs.toml, rustfs/backlog#1762) only shrinks without
#   an argument:
#     1. Every entry at the head carries an id, a non-empty `reason`, and an
#        `expires` review date that is a real calendar date (a-df-0017).
#     2. Every entry the pull request adds, and every existing entry it changes
#        (a wider pattern, a later review date, a new reason), is named in the
#        pull-request description on a line of its own:
#            known-diff <id>: <why this difference is accepted, in a sentence>
#        An entry added or widened without that line fails (a-df-0016). The
#        maintainer approval the branch ruleset requires is the approval of
#        that argument.
#     3. An added or changed entry is reviewed again within a year: its
#        `expires` is at most 366 days after the day the check runs.
#     4. A change to the code that decides what an entry matches, or what the
#        runner never judges (crates/difftest/src/known.rs, normalize.rs,
#        corpus.rs, runner.rs), needs a line of its own:
#            Difftest-matching change: <what now matches or is skipped, and why>
#        Widening what is accepted there does not touch the register file.
#   Removing an entry needs nothing: a difference that went away is the point.
#   Lines inside HTML comments or code fences do not count: a reviewer reading
#   the rendered description cannot see them.
#
# WHY
#   Every entry is a difference the differential stops reporting. Without this
#   ratchet the cheapest way to turn the diff green is one more entry, and a
#   register that only grows is a list of differences nobody looked at twice.
#
# HOW TO EXEMPT
#   There is no exemption. The justification line is the process.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
REGISTER="crates/difftest/known-diffs.toml"

fail() {
    printf 'check_known_diffs_ratchet: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -n "${GATEWAY_PR_BODY_JSON+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY_JSON'
# Encoded as one JSON line for the reason check_protected_files.sh gives (rustfs/gateway#224).
[[ "$GATEWAY_PR_BODY_JSON" != *$'\n'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ "$GATEWAY_PR_BODY_JSON" != *$'\r'* ]] ||
    fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
[[ -n "${GATEWAY_KNOWN_DIFFS_BASE:-}" ]] || fail 'required input is missing: GATEWAY_KNOWN_DIFFS_BASE'
[[ -n "${GATEWAY_KNOWN_DIFFS_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_KNOWN_DIFFS_HEAD'

python3 - "$ROOT_DIR" "$GATEWAY_KNOWN_DIFFS_BASE" "$GATEWAY_KNOWN_DIFFS_HEAD" "$GATEWAY_PR_BODY_JSON" "$REGISTER" <<'PY'
from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
base, head, body_json, register = sys.argv[2:]


def fail(message: str) -> None:
    print(f"check_known_diffs_ratchet: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    body = json.loads(body_json)
except ValueError as error:
    fail(f"GATEWAY_PR_BODY_JSON is not JSON (rule: rustfs/gateway#224): {error}")
if body is None:
    body = ""
if not isinstance(body, str):
    fail(f"GATEWAY_PR_BODY_JSON must decode to a string, got {type(body).__name__}")
# What a reviewer sees: HTML comments and fenced blocks are not arguments anyone read.
body = re.sub(r"<!--.*?(?:-->|\Z)", "", body, flags=re.DOTALL)
body = re.sub(r"^\s*(```|~~~).*?(?:^\s*\1.*?$|\Z)", "", body, flags=re.DOTALL | re.MULTILINE)


def revision(ref: str) -> str:
    try:
        subprocess.run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=root, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot resolve {ref}: {error}")
    listed = subprocess.run(["git", "ls-tree", "--name-only", ref, "--", register], cwd=root, capture_output=True, text=True)
    if listed.returncode != 0:
        fail(f"cannot list {ref}:{register}")
    if not listed.stdout.strip():
        return ""
    shown = subprocess.run(["git", "show", f"{ref}:{register}"], cwd=root, capture_output=True)
    if shown.returncode != 0:
        fail(f"cannot read {ref}:{register}")
    try:
        return shown.stdout.decode("utf-8")
    except UnicodeError as error:
        fail(f"{ref}:{register} is not UTF-8: {error}")


def entries(ref: str, required: bool) -> dict[str, dict]:
    text = revision(ref)
    if not text:
        if required:
            fail(f"{ref}:{register} does not exist")
        return {}
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        fail(f"{ref}:{register} is not TOML: {error}")
    listed = document.get("diff", [])
    if not isinstance(listed, list):
        fail(f"{ref}:{register}: `diff` must be an array of tables")
    found: dict[str, dict] = {}
    for position, entry in enumerate(listed, start=1):
        if not isinstance(entry, dict):
            fail(f"{ref}:{register}: entry {position} is not a table")
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"kd-(decode|encode)-[0-9]{4}", identifier):
            fail(f"{ref}:{register}: entry {position} has no id of the form kd-<decode|encode>-NNNN")
        if identifier in found:
            fail(f"{ref}:{register}: {identifier} appears twice")
        found[identifier] = entry
    return found


# The pull request's own change: the register where the branch left the base, against its head.
# Comparing with the base tip would charge the branch for entries main removed meanwhile.
fork = subprocess.run(["git", "merge-base", base, head], cwd=root, capture_output=True, text=True)
if fork.returncode != 0 or not fork.stdout.strip():
    fail(f"cannot find where {head} left {base}")
fork_commit = fork.stdout.strip()
old = entries(fork_commit, required=False)
new = entries(head, required=True)

problems = []
for identifier, entry in new.items():
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        problems.append(f"{identifier}: no reason (a-df-0017)")
    expires = entry.get("expires")
    try:
        if not isinstance(expires, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", expires):
            raise ValueError
        datetime.date.fromisoformat(expires)
    except ValueError:
        problems.append(f"{identifier}: no expires review date of the form YYYY-MM-DD (a-df-0017)")
if problems:
    for problem in problems:
        print(f"{register}: {problem}", file=sys.stderr)
    fail("every register entry says why and until when")

justified = {}
for line in body.splitlines():
    match = re.fullmatch(r"\s*(?:[-*]\s+)?known-diff (kd-(?:decode|encode)-[0-9]{4}): (.*\S)\s*", line)
    if match and len(match.group(2)) >= 20:
        justified[match.group(1)] = match.group(2)

added = sorted(set(new) - set(old))
changed = sorted(identifier for identifier in set(new) & set(old) if new[identifier] != old[identifier])
removed = sorted(set(old) - set(new))
today = datetime.datetime.now(datetime.timezone.utc).date()
horizon = today + datetime.timedelta(days=366)
distant = [
    identifier
    for identifier in added + changed
    if datetime.date.fromisoformat(new[identifier]["expires"]) > horizon
]
if distant:
    for identifier in distant:
        print(f"{register}: {identifier} expires {new[identifier]['expires']}, beyond {horizon.isoformat()}", file=sys.stderr)
    fail("an added or changed entry is reviewed again within a year")

MATCHING = [
    "crates/difftest/src/known.rs",
    "crates/difftest/src/normalize.rs",
    "crates/difftest/src/corpus.rs",
    "crates/difftest/src/runner.rs",
]
touched = subprocess.run(
    ["git", "diff", "--name-only", fork_commit, head, "--", *MATCHING], cwd=root, capture_output=True, text=True
)
if touched.returncode != 0:
    fail(f"cannot diff {fork_commit}..{head}")
matching_changed = [path for path in touched.stdout.splitlines() if path]
matching_argued = any(
    (match := re.fullmatch(r"\s*(?:[-*]\s+)?Difftest-matching change: (.*\S)\s*", line)) and len(match.group(1)) >= 20
    for line in body.splitlines()
)
if matching_changed and not matching_argued:
    for path in matching_changed:
        print(f"{path}: decides what the register accepts or the runner skips", file=sys.stderr)
    fail("a change to the matching code needs a `Difftest-matching change: <why>` line (20+ characters) in the pull-request description")

unargued = [identifier for identifier in added + changed if identifier not in justified]
if unargued:
    for identifier in unargued:
        verb = "added" if identifier in added else "changed"
        print(
            f"{register}: {identifier} {verb} without a `known-diff {identifier}: <why>` line (20+ characters) in the pull-request description (a-df-0016)",
            file=sys.stderr,
        )
    fail(f"{len(unargued)} register entr{'y' if len(unargued) == 1 else 'ies'} grew without an argument")
print(
    f"check_known_diffs_ratchet: {len(new)} entries ({len(old)} before): "
    f"{len(added)} added, {len(changed)} changed, {len(removed)} removed; every addition and change argued"
)
PY
