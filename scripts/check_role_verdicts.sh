#!/usr/bin/env bash
set -euo pipefail
# REQUIRES-PR

# Deterministically checks that the PR body records every role selected by the
# AGENTS.md trigger table. It checks presence, never whether an advisory verdict
# is favourable. Rule: AGENTS.md "Expert Roles & Trigger Table".

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_role_verdicts: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -f "${ROOT_DIR}/AGENTS.md" ]] || fail 'rule input is missing: AGENTS.md'
[[ -n "${GATEWAY_PR_BODY+x}" ]] || fail 'required input is missing: GATEWAY_PR_BODY'

if [[ -z "${GATEWAY_CHANGED_FILES+x}" ]]; then
    [[ -n "${GATEWAY_ROLE_BASE:-}" ]] || fail 'required input is missing: GATEWAY_ROLE_BASE'
    [[ -n "${GATEWAY_ROLE_HEAD:-}" ]] || fail 'required input is missing: GATEWAY_ROLE_HEAD'
fi

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
body = os.environ["GATEWAY_PR_BODY"]

table_rows = [
    "| `docs/**`, `.github/**`, Markdown-only changes | none | no role |",
    "| added `conformance/cases/**` | `simplicity-adversary`, `test-adversary` | single-session skill |",
    "| `model/**`, `spec/**`, `generated/**` | `simplicity-adversary`, `protocol-auditor` | skill plus deterministic spec verification |",
    "| `crates/types/**`, `crates/xml/**` | `simplicity-adversary`, `protocol-auditor` | single-session skill |",
    "| `crates/http/**` | `simplicity-adversary`, `security-adversary`, `concurrency-durability`, `perf-engineer` | parallel review allowed; high risk |",
    "| `crates/sig/**` | `simplicity-adversary`, `security-adversary`, `test-adversary` | parallel review allowed; high risk |",
    "| `crates/core/**` routing or pipeline | `simplicity-adversary`, `security-adversary` | single-session skill |",
    "| `ops/**` or `crates/core/src/ops/**` | `simplicity-adversary`, `protocol-auditor` | single-session skill |",
    "| a `compat-s3s` change | `simplicity-adversary`, `migration-safety-reviewer` | single-session skill |",
    "| every other behaviour-affecting path | `simplicity-adversary` | single-session skill |",
]


def fail(message: str) -> None:
    print(f"check_role_verdicts: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read AGENTS.md: {error}")
for row in table_rows:
    if agents.count(row) != 1:
        fail(f"AGENTS.md trigger table drifted at {row!r}")
for phrase in (
    "The default is at most 2 roles per PR",
    "contains `HIGH-RISK`",
    "at most 60k tokens per PR",
    "Role judgement is advisory and never a merge verdict.",
):
    if agents.count(phrase) != 1:
        fail(f"AGENTS.md cost rule drifted at {phrase!r}")


def git(*arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *arguments], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"git {' '.join(arguments)} failed: {error}")


def git_blob(revision: str, path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "show", f"{revision}:{path}"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"git show failed: {error}")
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace")


changes: list[tuple[str, str]] = []
provided = os.environ.get("GATEWAY_CHANGED_FILES")
if provided is not None:
    for line in provided.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) == 1:
            changes.append(("M", fields[0]))
        elif fields[0].startswith(("R", "C")) and len(fields) == 3:
            changes.extend(((fields[0][0], fields[1]), (fields[0][0], fields[2])))
        elif len(fields) == 2:
            changes.append((fields[0][0], fields[1]))
        else:
            fail(f"invalid GATEWAY_CHANGED_FILES line: {line!r}")
else:
    base = os.environ["GATEWAY_ROLE_BASE"]
    head = os.environ["GATEWAY_ROLE_HEAD"]
    git("rev-parse", "--verify", f"{base}^{{commit}}")
    git("rev-parse", "--verify", f"{head}^{{commit}}")
    # Select roles from what this branch changed, which is the diff from the merge base —
    # not from the base branch tip. GATEWAY_ROLE_BASE is
    # `github.event.pull_request.base.sha`, and that tracks `main` live: it moves under an
    # open pull request every time anything else merges. A two-dot diff against it hands
    # the trigger table every path in somebody else's commit, as a reverse change, and
    # then asks this author for a verdict on work that is not in the branch at all.
    # Measured: rustfs/gateway#199, whose entire diff is `scripts/**`, was asked for
    # `security-adversary` because rustfs/gateway#189 touched
    # `crates/core/src/error_resolution.rs` while it was in flight, and again for
    # rustfs/gateway#198's `crates/sig/**` on the next attempt. Rebasing narrows that
    # window; only the merge base closes it.
    role_base = os.fsdecode(git("merge-base", base, head)).strip()
    role_head = head
    fields = git("diff", "--name-status", "-z", "--find-renames", role_base, role_head).split(b"\0")
    index = 0
    while index < len(fields) and fields[index]:
        status = os.fsdecode(fields[index])
        index += 1
        if status[0] in {"R", "C"}:
            changes.append((status[0], os.fsdecode(fields[index])))
            index += 1
        changes.append((status[0], os.fsdecode(fields[index])))
        index += 1

if not changes:
    fail("changed-file input is empty")

paths = [path for _, path in changes]
diff_text = ""
compat_source_change = False
if provided is not None:
    if any(path.startswith("crates/types/") for path in paths) and "GATEWAY_CHANGED_DIFF" not in os.environ:
        fail("required input is missing for a types change: GATEWAY_CHANGED_DIFF")
    diff_text = os.environ.get("GATEWAY_CHANGED_DIFF", "")
else:
    # Same reasoning as the changed-file diff above: the "before" this branch is judged
    # against is the commit it was cut from, not whatever the base branch has since become.
    diff_text = git(
        "diff",
        "--unified=0",
        role_base,
        role_head,
        "--",
        "crates/types",
    ).decode("utf-8", errors="replace")
    base = role_base
    head = role_head
    for path in {path for path in paths if path.startswith("crates/types/") and path.endswith(".rs")}:
        before = git_blob(base, path)
        after = git_blob(head, path)
        if before is None and after is None:
            fail(f"cannot inspect changed types source at either revision: {path}")
        if "compat-s3s" in (before or "") or "compat-s3s" in (after or ""):
            compat_source_change = True


def exempt(path: str) -> bool:
    return path.startswith(("docs/", ".github/")) or path.lower().endswith(".md")


required: set[str] = set()
reasons: dict[str, set[str]] = {}


def require(role: str, path: str) -> None:
    required.add(role)
    reasons.setdefault(role, set()).add(path)


for status, path in changes:
    if exempt(path):
        continue
    require("simplicity-adversary", path)
    if path.startswith(("model/", "spec/", "generated/")):
        require("protocol-auditor", path)
    elif path.startswith(("crates/types/", "crates/xml/")):
        require("protocol-auditor", path)
    elif path.startswith("crates/http/"):
        for role in ("security-adversary", "concurrency-durability", "perf-engineer"):
            require(role, path)
    elif path.startswith("crates/sig/"):
        require("security-adversary", path)
        require("test-adversary", path)
    elif path.startswith("ops/") or path.startswith("crates/core/src/ops/"):
        require("protocol-auditor", path)
    elif path.startswith("crates/core/"):
        require("security-adversary", path)
    elif path.startswith("conformance/cases/") and status == "A":
        require("test-adversary", path)

if "compat-s3s" in diff_text or compat_source_change:
    require("migration-safety-reviewer", "compat-s3s diff")

def visible_lines(markdown: str) -> list[str]:
    result: list[str] = []
    comment = False
    fence: tuple[str, int] | None = None
    for raw in markdown.splitlines():
        if fence:
            if re.fullmatch(rf" {{0,3}}{re.escape(fence[0])}{{{fence[1]},}}[ \t]*", raw):
                fence = None
            continue
        if raw.startswith("\t") or re.match(r"^ {4,}", raw):
            continue
        visible = ""
        rest = raw
        while rest:
            if comment:
                end = rest.find("-->")
                if end < 0:
                    rest = ""
                else:
                    rest = rest[end + 3 :]
                    comment = False
            else:
                start = rest.find("<!--")
                if start < 0:
                    visible += rest
                    rest = ""
                else:
                    visible += rest[:start]
                    rest = rest[start + 4 :]
                    comment = True
        stripped = visible.lstrip(" ")
        if re.match(r"</?[A-Za-z][A-Za-z0-9-]*(?:[\t />]|$)", stripped) or stripped.startswith(("<?", "<![CDATA[")) or re.match(r"<![A-Z]", stripped):
            fail("PR body contains unsupported raw HTML; role verdicts must be visible Markdown")
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", visible)
        if opening:
            marker, info = opening.groups()
            if marker[0] != "`" or "`" not in info:
                fence = (marker[0], len(marker))
                continue
        result.append(visible)
    if comment:
        fail("PR body has an unterminated HTML comment")
    if fence:
        fail("PR body has an unterminated fenced block")
    return result


lines = visible_lines(body)
high_risk_path = any(path.startswith(("crates/http/", "crates/sig/")) for path in paths)
visible_high_risk = any("HIGH-RISK" in line for line in lines)
if len(required) > 2 and not high_risk_path and not visible_high_risk:
    fail(f"trigger table selected more than two roles outside a high-risk path: {sorted(required)}")
headings = [index for index, line in enumerate(lines) if line == "## Role Verdicts"]
if not required:
    print("check_role_verdicts: changed paths require no expert role")
    raise SystemExit(0)
if len(headings) != 1:
    fail("PR body must contain exactly one visible ## Role Verdicts section")
start = headings[0] + 1
end = next((index for index in range(start, len(lines)) if re.match(r"^##\s+", lines[index])), len(lines))
verdicts: dict[str, str] = {}
for line in lines[start:end]:
    match = re.match(r"^- ([a-z0-9-]+):\s*(.*?)\s*$", line)
    if not match:
        continue
    role, verdict = match.groups()
    if role in verdicts:
        fail(f"duplicate verdict line for {role}")
    verdicts[role] = verdict

bare = {"pass", "ok", "lgtm", "n/a", "na", "none", "pending", "todo", "-"}
for role in sorted(required):
    verdict = verdicts.get(role, "")
    reason = ", ".join(sorted(reasons[role]))
    if not verdict:
        fail(f"missing substantive verdict for {role}; selected by {reason} (rule: AGENTS.md Expert Roles & Trigger Table)")
    normalized = verdict.strip().lower().rstrip(".! ")
    words = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", normalized)
    if normalized in bare or len(words) < 2:
        fail(f"bare pass is not a result for {role}; state what was attacked (selected by {reason})")
    finding = re.search(r"(?:^|[\s`(])(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+:[1-9][0-9]*(?:$|[^0-9])", verdict)
    null_report = re.fullmatch(
        r"attacked\s+\S(?:.*\S)?\s+(?:—|--|-)\s+no break found[.!]?",
        verdict.strip(),
        flags=re.IGNORECASE,
    )
    if not finding and not null_report:
        fail(
            f"verdict for {role} must contain a repository-relative file:line finding or "
            f"an 'attacked ... — no break found' null report (selected by {reason})"
        )

print(f"check_role_verdicts: recorded substantive verdicts for {', '.join(sorted(required))}")
PY
