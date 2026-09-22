#!/usr/bin/env python3
"""Prove reset probes retain the caller's reusable sandbox and pending reset journal."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

source = Path(__file__).with_name("test_guard_scripts.sh").read_text()
functions = []
for name in ("literalize_nul_paths", "clean_after_ignore_reset", "reset_sandbox_changes", "stage_sandbox_changes",
             "make_sandbox",
             "probe_cached_sandbox_reset", "probe_cached_reset_failures"):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", source, re.M | re.S)
    assert match is not None, name
    functions.append(match.group())
program = "set -euo pipefail\n" + "\n".join(functions) + '''
failures=0
cases=0
pass_msg() { :; }
fail_msg() { printf '%s\\n' "$*" >&2; failures=$((failures + 1)); }
guard_case_owned() { [[ "$OWNED" == 1 ]]; }
SANDBOX="$PARENT_REPO"
SANDBOX_BASE="$(git -C "$SANDBOX" rev-parse HEAD)"
SANDBOX_RESET_TRACKED="$PARENT_REPO.tracked"
SANDBOX_RESET_UNTRACKED="$PARENT_REPO.untracked"
SANDBOX_RESET_READY=0
: >"$SANDBOX_RESET_TRACKED"
: >"$SANDBOX_RESET_UNTRACKED"
printf 'changed\\n' >>"$SANDBOX/tracked"
printf 'new\\n' >"$SANDBOX/untracked"
stage_sandbox_changes "$SANDBOX"
cp "$SANDBOX_RESET_TRACKED" "$PARENT_REPO.expected-tracked"
cp "$SANDBOX_RESET_UNTRACKED" "$PARENT_REPO.expected-untracked"
"$PROBE"
[[ "$failures" == 0 ]] || exit 70
[[ "$SANDBOX" == "$PARENT_REPO" ]] || { printf 'parent sandbox discarded\\n' >&2; exit 71; }
[[ "$SANDBOX_RESET_TRACKED" == "$PARENT_REPO.tracked" ]] || exit 72
[[ "$SANDBOX_RESET_UNTRACKED" == "$PARENT_REPO.untracked" ]] || exit 73
[[ "$SANDBOX_RESET_READY" == 1 ]] || exit 74
cmp "$SANDBOX_RESET_TRACKED" "$PARENT_REPO.expected-tracked" || exit 75
cmp "$SANDBOX_RESET_UNTRACKED" "$PARENT_REPO.expected-untracked" || exit 76
[[ "$(git -C "$SANDBOX" rev-parse HEAD)" == "$SANDBOX_BASE" ]] || exit 77
# The next real acquisition must consume the preserved journal in the same repository.
make_sandbox
[[ "$SANDBOX" == "$PARENT_REPO" && "$SANDBOX_RESET_READY" == 0 ]] || exit 78
[[ "$(cat "$SANDBOX/tracked")" == baseline && ! -e "$SANDBOX/untracked" ]] || exit 79
[[ -z "$(git -C "$SANDBOX" status --porcelain)" ]] || exit 80
printf 'preserved %s %s\\n' "$PROBE" "$OWNED"
'''

errors = []
for probe in ("probe_cached_sandbox_reset", "probe_cached_reset_failures"):
    for owned in ("0", "1"):
        with tempfile.TemporaryDirectory(prefix="gateway-probe-isolation-") as directory:
            root = Path(directory)
            repo = root / "parent"
            repo.mkdir()
            (repo / "tracked").write_text("baseline\n")
            for command in (["init", "-q"], ["add", "tracked"],
                            ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"]):
                subprocess.run(["git", "-C", str(repo), *command], check=True)
            result = subprocess.run(["bash", "-c", program], capture_output=True, text=True,
                                    env=dict(os.environ, TMPDIR=directory, PARENT_REPO=str(repo),
                                             REPO_ROOT=str(root / "must-not-rebuild"), PROBE=probe, OWNED=owned))
            if result.returncode != 0:
                errors.append(f"{probe} owned={owned}: exit {result.returncode}: {result.stderr.strip()}")
assert not errors, "\n".join(errors)
print("OK: owned and unowned reset probes preserve and subsequently consume the parent's exact journal")
