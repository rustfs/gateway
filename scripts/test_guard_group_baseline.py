#!/usr/bin/env python3
"""Measure group preparation and prove borrowed fixture objects stay isolated."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


source = Path(__file__).with_name("test_guard_scripts.sh").read_text()
definitions = []
for name in ("guard_group_of", "guard_worker_of", "guard_case_owned", "guard_shard_ledger_report", "run_guard_shards",
             "make_sandbox", "cleanup_sandbox"):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", source, re.M | re.S)
    if match is None:
        raise SystemExit(f"missing fixture helper: {name}")
    definitions.append(match.group())
library = "\n".join(definitions) + r'''
SANDBOX=""
SANDBOX_RESET_TRACKED=""
SANDBOX_RESET_UNTRACKED=""
SANDBOX_RESET_READY=0
SANDBOX_BASE=""
QUIRK_LEDGER_PARSE_CACHE=""
CT_EQ_SANDBOX=""
SEMVER_SANDBOX=""
GUARD_SHARD_COUNT="${GATEWAY_GUARD_SHARD_COUNT:-}"
GUARD_SHARD_INDEX="${GATEWAY_GUARD_SHARD_INDEX:-0}"
GUARD_SHARD_GROUPS=1
GUARD_SHARD_GROUP=0
GUARD_SHARD_LEDGER="${GATEWAY_GUARD_SHARD_LEDGER:-}"
GUARD_SHARD_SUMMARY="${GATEWAY_GUARD_SHARD_SUMMARY:-}"
GUARD_BUDGET_SECONDS=480
GUARD_BUDGET_STOP=450
GUARD_EXECUTED=0
guard_print_elapsed() { :; }
'''
real_git = shutil.which("git")
if real_git is None:
    raise SystemExit("git is required")

with tempfile.TemporaryDirectory(prefix="gateway-guard-group-") as directory:
    root = Path(directory)
    seed, tools, events, reports = (root / name for name in ("source", "bin", "events", "reports"))
    for path in (seed, tools, reports):
        path.mkdir()
    helper = root / "helpers.sh"
    helper.write_text(library)
    observer = tools / "git"
    observer.write_text(r'''#!/bin/bash
if [[ "$1" == clone ]]; then
    destination="${!#}"
    case "${FAULT:-}" in
        clone_failure) exit 71;;
        partial_clone_failure) mkdir -p "$destination/partial"; exit 72;;
    esac
fi
if [[ "$1" == -C && "$3" == rev-parse ]]; then
    [[ "${FAULT:-}" != head_read_failure || "$2" != "$BASELINE" ]] || exit 73
    [[ "${FAULT:-}" != clone_head_read_failure || "$2" == "$BASELINE" ]] || exit 73
fi
if [[ "$1" == -C && "$3" == status && "${FAULT:-}" == status_failure ]]; then exit 74; fi
if [[ "$1" == -C && "$3" == config ]]; then
    [[ "${FAULT:-}" != maintenance_failure || "$4" != maintenance.auto ]] || exit 75
    [[ "${FAULT:-}" != gc_failure || "$4" != gc.auto ]] || exit 75
fi
"$REAL_GIT" "$@"
rc=$?
if [[ "$rc" == 0 && "$1" == init && -d .git ]]; then
    printf '%s\n' "$PWD" >>"$EVENTS"
fi
if [[ "$rc" == 0 && "$1" == clone && "${FAULT:-}" == clone_head_mismatch ]]; then
    "$REAL_GIT" -C "$destination" -c user.name=t -c user.email=t@t commit -qm changed --allow-empty || exit
fi
exit "$rc"
''')
    observer.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}",
                       REAL_GIT=real_git, EVENTS=str(events), REPORTS=str(reports),
                       HELPER=str(helper), REPO_ROOT=str(seed),
                       GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="maintenance.auto",
                       GIT_CONFIG_VALUE_0="false", GIT_CONFIG_KEY_1="gc.auto", GIT_CONFIG_VALUE_1="0")
    for key in tuple(environment):
        if key.startswith("GATEWAY_GUARD_"):
            environment.pop(key)

    def git(*arguments, cwd=seed):
        return subprocess.run([real_git, "-C", str(cwd), *arguments], check=True,
                              capture_output=True, text=True, env=environment).stdout.strip()

    git("init", "-q")
    (seed / "tracked.txt").write_text("committed\n")
    (seed / ".gitignore").write_text("ignored.txt\n")
    (seed / "link").symlink_to("tracked.txt")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "source")
    (seed / "tracked.txt").write_text("dirty tracked\n")
    (seed / "untracked.txt").write_text("untracked input\n")
    (seed / "ignored.txt").write_text("excluded\n")
    before = (git("rev-parse", "HEAD"), git("status", "--porcelain"),
              (seed / "tracked.txt").read_text(), (seed / "untracked.txt").read_text())

    def run(program, **extra):
        return subprocess.run(["bash", "-c", 'set -euo pipefail\nsource "$HELPER"\n' + program],
                              capture_output=True, text=True, env=dict(environment, **extra))

    # Count completed repository construction, not an intended command or a guessed duration.
    calibration_tmp = root / "calibration"
    calibration_tmp.mkdir()
    for count in (1, 2):
        result = run('make_sandbox\ncleanup_sandbox\n', TMPDIR=str(calibration_tmp))
        assert result.returncode == 0, ("construction calibration failed", result)
        assert len(events.read_text().splitlines()) == count, "construction observer is constant or incomplete"
    events.unlink()

    worker = root / "worker.sh"
    worker.write_text(r'''#!/bin/bash
set -euo pipefail
source "$HELPER"
trap cleanup_sandbox EXIT
make_sandbox
export SANDBOX
python3 - <<'PY'
import json, os
from pathlib import Path
import subprocess

child = Path(os.environ["SANDBOX"])
baseline = Path(os.environ.get("GATEWAY_GUARD_BASELINE", str(child)))
worker = os.environ["GATEWAY_GUARD_SHARD_INDEX"]
record = {
    "child": str(child), "baseline": str(baseline),
    "tracked": (child / "tracked.txt").read_text(),
    "untracked": (child / "untracked.txt").read_text() if (child / "untracked.txt").exists() else None,
    "symlink": (child / "link").is_symlink(), "ignored": (child / "ignored.txt").exists(),
    "alternates": (child / ".git/objects/info/alternates").read_text()
        if (child / ".git/objects/info/alternates").exists() else "",
}
(child / "tracked.txt").write_text("private mutation " + worker)
def git(*args):
    return subprocess.run([os.environ["REAL_GIT"], "-C", str(child), *args],
                          check=True, capture_output=True, text=True).stdout.strip()
git("add", "tracked.txt")
git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "private " + worker)
private_head = git("rev-parse", "HEAD")
git("update-ref", "refs/heads/private-" + worker, private_head)
record["baseline_tracked"] = (baseline / "tracked.txt").read_text()
record["baseline_status"] = subprocess.run(
    [os.environ["REAL_GIT"], "-C", str(baseline), "status", "--porcelain"],
    check=True, capture_output=True, text=True).stdout
record["private_object_in_baseline"] = subprocess.run(
    [os.environ["REAL_GIT"], "-C", str(baseline), "cat-file", "-e", private_head],
    capture_output=True).returncode == 0
record["private_ref_in_baseline"] = subprocess.run(
    [os.environ["REAL_GIT"], "-C", str(baseline), "show-ref", "--verify", "refs/heads/private-" + worker],
    capture_output=True).returncode == 0
Path(os.environ["REPORTS"], worker).write_text(json.dumps(record))
PY
for ((ordinal = 1; ordinal <= 16; ordinal++)); do guard_case_owned "$ordinal" || :; done
printf '16 %s 0\n' "$GUARD_EXECUTED" >"$GUARD_SHARD_SUMMARY"
''')
    group_tmp = root / "group"
    group_tmp.mkdir()
    result = run('trap cleanup_sandbox EXIT\nrun_guard_shards 2\n',
                 GUARD_SELF=str(worker), TMPDIR=str(group_tmp),
                 GATEWAY_GUARD_BASELINE=str(root / "must-not-use-an-external-seed"))
    assert result.returncode == 0 and "16 of 16 case(s), each executed exactly once" in result.stdout, result
    assert len(events.read_text().splitlines()) == 1, ("one group prepared more than one current-tree baseline", events.read_text())

    records = [json.loads(path.read_text()) for path in sorted(reports.iterdir())]
    assert len(records) == 2 and len({row["child"] for row in records}) == 2, "workers shared a checkout"
    for row in records:
        assert (row["tracked"], row["untracked"], row["symlink"], row["ignored"]) == (
            "dirty tracked\n", "untracked input\n", True, False), "snapshot dropped current-tree inputs"
        assert (row["baseline_tracked"], row["private_object_in_baseline"], row["private_ref_in_baseline"], row["baseline_status"]) == (
            "dirty tracked\n", False, False, ""), "private mutations reached the immutable baseline"
        assert row["alternates"].strip() == str(Path(row["baseline"], ".git/objects")), "worker copied baseline objects"
    assert len({row["baseline"] for row in records}) == 1, "workers borrowed different baselines"
    assert not list(group_tmp.iterdir()), "group or worker fixtures survived cleanup"
    assert before == (git("rev-parse", "HEAD"), git("status", "--porcelain"),
                      (seed / "tracked.txt").read_text(), (seed / "untracked.txt").read_text()), "source was modified"

    # Rejections outnumber successful group runs. No fallback may turn an invalid provided
    # baseline into a new successful snapshot, and failed preparation must publish nothing.
    for mode in ("empty", "missing", "file", "nongit", "unborn", "unstaged", "staged",
                 "untracked", "deleted", "staged_deleted", "head_read_failure", "status_failure",
                 "clone_failure", "partial_clone_failure", "clone_head_mismatch",
                 "clone_head_read_failure", "maintenance_failure", "gc_failure", "mktemp_failure"):
        case_root = root / mode
        case_root.mkdir()
        baseline, temporary = case_root / "baseline", case_root / "tmp"
        temporary.mkdir()
        shutil.copytree(seed, baseline, symlinks=True)
        git("add", "-A", cwd=baseline)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "baseline", cwd=baseline)
        provided = str(baseline)
        if mode == "empty": provided = ""
        elif mode == "missing": provided = str(case_root / "missing")
        elif mode == "file": provided = str(baseline / "tracked.txt")
        elif mode in ("nongit", "unborn"):
            target = case_root / mode
            target.mkdir()
            if mode == "unborn": git("init", "-q", cwd=target)
            provided = str(target)
        elif mode in ("unstaged", "staged"):
            (baseline / "tracked.txt").write_text("changed")
            if mode == "staged": git("add", "tracked.txt", cwd=baseline)
        elif mode == "untracked": (baseline / "extra").touch()
        elif mode == "deleted": (baseline / "tracked.txt").unlink()
        elif mode == "staged_deleted": git("rm", "-q", "tracked.txt", cwd=baseline)
        result = run(r'''
mktemp() { [[ "$FAULT" != mktemp_failure ]] || return 76; command mktemp "$@"; }
rc=0
make_sandbox || rc=$?
printf 'published:%s\n' "$SANDBOX"
exit "$rc"
''', TMPDIR=str(temporary), BASELINE=str(baseline), FAULT=mode,
                     GATEWAY_GUARD_SHARD_COUNT="2", GATEWAY_GUARD_BASELINE=provided)
        diagnostic = "cannot prepare guard group baseline" if mode in (
            "clone_failure", "partial_clone_failure", "clone_head_mismatch", "clone_head_read_failure",
            "maintenance_failure", "gc_failure", "mktemp_failure") else "invalid guard group baseline"
        assert (result.returncode != 0 and diagnostic in result.stderr
                and result.stdout == "published:\n" and not list(temporary.iterdir())), (mode, result)
print("OK: one current-tree group baseline, private worker mutations and 19 fail-closed controls")
