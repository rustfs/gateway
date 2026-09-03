#!/usr/bin/env bash
set -euo pipefail

# WHAT: The last mode gate in `scripts/test_guard_scripts.sh` must be one the default run enters,
#       so that a case written at the end of the suite runs in the default suite.
# WHY:  The last block in that file used to be `if [[ "$ERROR_STATUS_ONLY" == 1 ]]`, which the
#       default run never enters. A case written at the end of the suite therefore ran only in the
#       `error status self-test` job — under a name, a budget and a shard plan belonging to
#       something else — and never in the run `cargo xtask verify` and every local invocation
#       perform. Nine cases had already collected there that mutate two conformance cases, the
#       conformance SUT seam and the response body planner, none of which is an error status;
#       rustfs/gateway#633 and #634 each report a batch of appended cases whose authors found the
#       same trap by grepping the run log for their own case descriptions, after the fact.
#       No count can see this, which is why this guard is not one: the suite's case total rises
#       whichever block a new case lands in, and the coverage proof compares a run against itself,
#       so a run with a swallowed case and a run without it agree on everything. This guard is a
#       statement about which block the end of the file belongs to, and no number of new cases can
#       satisfy it.
# HOW TO EXEMPT: no exemption. Put the mode-gated block above a default-reachable one. That is a
#       pure block move and costs nothing: a block a mode skips contributes no case ordinal to
#       that mode wherever it sits, and the mode that does enter it enters no other block.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SUITE="${ROOT_DIR}/scripts/test_guard_scripts.sh"

if [[ ! -f "$SUITE" ]]; then
    printf 'check_guard_suite_tail_reachable: required input is missing: scripts/test_guard_scripts.sh\n' >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_guard_suite_tail_reachable: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$SUITE" <<'PYEOF'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().split("\n")

# Heredoc bodies sit at column zero, and the suite's heredocs carry Python — which has `if` lines
# of its own — and shell fixtures that this guard's own negative cases append to a sandbox copy of
# the suite. Reading either as structure would make the nesting arithmetic below silently wrong,
# so heredoc bodies are dropped first.
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
# A mode gate is a whole condition built only from the suite's mode switches, e.g.
# `if [[ "$ERROR_STATUS_ONLY" == 1 ]]; then`. The argument validation near the top of the suite
# compares the same variables with `!=`, and is not a gate.
GATE = re.compile(r'^if \[\[ (?P<cond>"\$[A-Z_]+_ONLY" == [01](?: && "\$[A-Z_]+_ONLY" == [01])*) \]\]; then$')
TERM = re.compile(r'"\$([A-Z_]+_ONLY)" == ([01])')
# A top-level compound statement that branches on a mode switch and is not a gate must be one of
# the two argument validations at the top of the suite. Anything else is a spelling this guard
# cannot evaluate, and an unreadable gate must fail rather than be passed over — otherwise the
# check quietly reports on the previous gate and a mode-gated tail spelled some other way walks
# through. `if` is the only head this file uses to branch on a mode, but `case`, `while`, `until`
# and `for` would gate a block just as well, so all of them are read the same way.
VALIDATION = re.compile(r"^if \[\[ .*_ONLY.*(?:!=|-gt) ")
CANDIDATE = re.compile(r"^(?:if|case|while|until|for) .*_ONLY")

code: list[tuple[int, str]] = []
index = 0
while index < len(lines):
    line = lines[index]
    code.append((index + 1, line))
    opener = HEREDOC.search(line)
    if opener is not None:
        tag = opener.group(2)
        index += 1
        while index < len(lines) and lines[index].strip() != tag:
            index += 1
    index += 1


def refuse(message: str) -> None:
    print(f"check_guard_suite_tail_reachable: {message}", file=sys.stderr)
    raise SystemExit(1)


# Every block in the suite is written flush against the left margin and every function body is
# indented, so a column-zero `if`/`fi` pair is a top-level block and nothing else is.
depth = 0
gates: list[tuple[int, int, str]] = []
for lineno, line in code:
    match = GATE.match(line)
    if match is not None:
        gates.append((lineno, depth, match.group("cond")))
    elif CANDIDATE.match(line) and not VALIDATION.match(line):
        refuse(
            f"line {lineno} of scripts/test_guard_scripts.sh opens a top-level block on a mode "
            f"switch in a spelling this guard cannot read: `{line}`. Write a mode gate as one "
            f'`if [[ "$X_ONLY" == 0 ]]; then` line, or which block the end of the suite belongs '
            f"to cannot be decided"
        )
    if line.startswith("if "):
        depth += 1
    elif line == "fi":
        depth -= 1
        if depth < 0:
            refuse(
                f"the top-level blocks of scripts/test_guard_scripts.sh do not nest cleanly: "
                f"line {lineno} closes a block that was never opened, so which block the end of "
                f"the suite belongs to cannot be decided"
            )

if depth != 0:
    refuse(
        f"the top-level blocks of scripts/test_guard_scripts.sh do not nest cleanly: {depth} "
        f"block(s) are still open at the end of the file, so which block the end of the suite "
        f"belongs to cannot be decided"
    )

if not gates:
    refuse(
        "scripts/test_guard_scripts.sh declares no mode gate, so the end of the suite cannot be "
        "shown to run in the default mode"
    )

lineno, gate_depth, condition = gates[-1]
if gate_depth != 0:
    refuse(
        f"the last mode gate of scripts/test_guard_scripts.sh, `{condition}` at line {lineno}, is "
        f"nested inside another block, so what the default run does with the end of the suite "
        f"cannot be read off the gate itself"
    )

# The default run is the one with every mode switch off.
if any(value != "0" for _, value in TERM.findall(condition)):
    refuse(
        f"the last mode gate of scripts/test_guard_scripts.sh, `{condition}` at line {lineno}, is "
        f"a gate the default run does not enter, so a case written at the end of the suite never "
        f"runs in the default mode. Move that block above a default-reachable one"
    )

print(
    f"OK: the suite's last mode gate is `{condition}` at line {lineno}, which the default run enters"
)
PYEOF
