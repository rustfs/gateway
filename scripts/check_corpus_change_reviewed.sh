#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-PR

# =============================================================================
# check_corpus_change_reviewed.sh
#
# WHAT THIS CHECKS
#   A change under `corpus/` reaches `main` only as a reviewed pull request that states what
#   it did to the corpus (rustfs/backlog#1763 a-cp-0017):
#     pull request  when the diff touches `corpus/`, the description carries a `## Corpus change`
#                   section with the line `Entries: <before> -> <after>`, and both numbers equal
#                   `entries` in `corpus/MANIFEST.toml` at the base and at the head;
#     push          every commit in the pushed range that touches `corpus/` is a pull-request
#                   merge, i.e. its subject ends in `(#<number>)`. A corpus commit pushed
#                   straight to `main` turns `main` red.
#
# WHY
#   A corpus change silently changes every differential result computed from it, so it must be
#   an explicit, reviewed event and never an automatic commit. The census line makes the
#   reviewer look at the number that moved, and the check that it matches the manifest keeps
#   the statement honest.
#
#   `corpus/MANIFEST.toml` is deliberately NOT a protected file. The protected-files process is
#   for contracts whose change breaks a downstream: it demands `BREAKING`, a version bump and a
#   migration path. A corpus refresh breaks nobody, and marking every refresh `BREAKING` would
#   teach reviewers that the word means nothing. This guard asks for the review a refresh needs
#   and nothing else.
#
# HOW TO EXEMPT
#   There is none. State the census in the pull request.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_corpus_change_reviewed: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'

if [[ -n "${GATEWAY_CORPUS_PUSH_RANGE:-}" ]]; then
    mode=push
else
    mode=pr
    [[ -n "${GATEWAY_PR_BODY_JSON+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY_JSON (or GATEWAY_CORPUS_PUSH_RANGE for a push)'
    [[ "$GATEWAY_PR_BODY_JSON" != *$'\n'* && "$GATEWAY_PR_BODY_JSON" != *$'\r'* ]] ||
        fail 'GATEWAY_PR_BODY_JSON must be a single-line JSON string (rule: rustfs/gateway#224)'
    [[ -n "${GATEWAY_CORPUS_BASE:-}" ]] || fail 'required input is missing: GATEWAY_CORPUS_BASE'
    [[ -n "${GATEWAY_CORPUS_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_CORPUS_HEAD'
fi

python3 - "$ROOT_DIR" "$mode" <<'PY'
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
mode = sys.argv[2]
MANIFEST = "corpus/MANIFEST.toml"


def fail(message: str) -> None:
    print(f"check_corpus_change_reviewed: {message}", file=sys.stderr)
    raise SystemExit(1)


def git(*arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", *arguments], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"git {' '.join(arguments)} failed: {error}")
        raise


def entries_at(revision: str) -> int:
    result = subprocess.run(
        ["git", "show", f"{revision}:{MANIFEST}"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        return 0
    found = re.findall(r"(?m)^entries = (\d+)$", result.stdout.decode("utf-8", "replace"))
    if len(found) != 1:
        fail(f"{MANIFEST} at {revision[:12]} does not declare exactly one top-level `entries`")
    return int(found[0])


if mode == "push":
    commits = [line for line in git("rev-list", os.environ["GATEWAY_CORPUS_PUSH_RANGE"]).splitlines() if line]
    unreviewed = []
    for commit in commits:
        if not git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", commit, "--", "corpus").strip():
            continue
        subject = git("log", "-1", "--format=%s", commit).strip()
        if not re.search(r"\(#\d+\)$", subject):
            unreviewed.append(f"{commit[:12]} {subject}")
    for line in unreviewed:
        print(f"check_corpus_change_reviewed: {line}: changes corpus/ outside a pull request", file=sys.stderr)
    if unreviewed:
        raise SystemExit(1)
    print(f"OK: {len(commits)} pushed commit(s); every corpus change arrived through a pull request")
    raise SystemExit(0)

base = os.environ["GATEWAY_CORPUS_BASE"]
head = os.environ["GATEWAY_CORPUS_HEAD"]
changed = [line for line in git("diff", "--name-only", f"{base}...{head}", "--", "corpus").splitlines() if line]
if not changed:
    print("OK: this pull request does not change corpus/")
    raise SystemExit(0)

try:
    body = json.loads(os.environ["GATEWAY_PR_BODY_JSON"]) or ""
except ValueError as error:
    fail(f"GATEWAY_PR_BODY_JSON is not JSON (rule: rustfs/gateway#224): {error}")
if not isinstance(body, str):
    fail("GATEWAY_PR_BODY_JSON must decode to a string")

before, after = entries_at(base), entries_at(head)
expected = f"Entries: {before} -> {after}"
section = re.search(r"(?ms)^## Corpus change[ \t]*$(.*?)(?=^## |\Z)", body)
if section is None:
    fail(
        f"this pull request changes {len(changed)} file(s) under corpus/ but its description has no "
        f"`## Corpus change` section; add one with the line `{expected}`"
    )
stated = re.findall(r"(?m)^\s*(?:[-*]\s*)?Entries:\s*(\d+)\s*->\s*(\d+)\s*$", section.group(1))
if stated != [(str(before), str(after))]:
    fail(
        f"the `## Corpus change` section must state `{expected}` exactly once, as {MANIFEST} "
        f"reads at the base and the head; it states {['{} -> {}'.format(*pair) for pair in stated] or 'no census line'}"
    )
print(f"OK: corpus change reviewed ({expected}, {len(changed)} file(s))")
PY
