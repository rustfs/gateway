#!/usr/bin/env bash
set -euo pipefail

# The nested signature suite may borrow immutable objects from its parent's clean baseline.
# Exercise the real sandbox helper with tiny repositories, including refusals and ownership.
# This script runs every control; it has no filtering or feature-based omissions.

[[ "$#" -eq 0 ]] || exit 2
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gateway-signature-baseline.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
REAL_GIT="$(command -v git)"
SEED="$WORK/seed"
PREFIX="$WORK/helper.sh"
python3 - "$SCRIPT_DIR/test_sig_case_coverage.sh" "$PREFIX" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
boundary = "\nexpect_fail() {"
if text.count(boundary) != 1 or "\nmake_sandbox() {" not in text:
    raise SystemExit("the signature sandbox helper is missing")
Path(sys.argv[2]).write_text(text.split(boundary, 1)[0])
PY
mkdir "$SEED"
"$REAL_GIT" -C "$SEED" init -q
"$REAL_GIT" -C "$SEED" config maintenance.auto false
"$REAL_GIT" -C "$SEED" config gc.auto 0
printf 'first\n' >"$SEED/tracked.txt"
"$REAL_GIT" -C "$SEED" add tracked.txt
"$REAL_GIT" -C "$SEED" -c user.name=t -c user.email=t@t commit -qm first
OLDER_HEAD="$("$REAL_GIT" -C "$SEED" rev-parse HEAD)"
printf 'baseline\n' >"$SEED/tracked.txt"
"$REAL_GIT" -C "$SEED" add tracked.txt
"$REAL_GIT" -C "$SEED" -c user.name=t -c user.email=t@t commit -qm baseline

probe() (
    local mode="$1" case_root baseline tmp output rc=0 expected leftovers
    case_root="$WORK/$mode"
    baseline="$case_root/base"
    tmp="$case_root/tmp"
    output="$case_root/output"
    mkdir -p "$tmp"
    cp -R "$SEED" "$baseline"
    set --
    source "$PREFIX"
    REPO_ROOT="$baseline"
    TMPDIR="$tmp"
    unset GATEWAY_SIG_GUARD_BASELINE
    export GATEWAY_SIG_GUARD_BASELINE="$baseline"

    case "$mode" in
        empty) GATEWAY_SIG_GUARD_BASELINE="" ;;
        missing) GATEWAY_SIG_GUARD_BASELINE="$case_root/missing" ;;
        file) GATEWAY_SIG_GUARD_BASELINE="$baseline/tracked.txt" ;;
        nongit) mkdir "$case_root/nongit"; GATEWAY_SIG_GUARD_BASELINE="$case_root/nongit" ;;
        unborn)
            mkdir "$case_root/unborn"
            "$REAL_GIT" -C "$case_root/unborn" init -q
            GATEWAY_SIG_GUARD_BASELINE="$case_root/unborn"
            ;;
        unstaged) printf 'dirty\n' >>"$baseline/tracked.txt" ;;
        staged)
            printf 'dirty\n' >>"$baseline/tracked.txt"
            "$REAL_GIT" -C "$baseline" add tracked.txt
            ;;
        untracked) printf 'dirty\n' >"$baseline/untracked.txt" ;;
        deleted) rm "$baseline/tracked.txt" ;;
        staged_deleted) "$REAL_GIT" -C "$baseline" rm -q tracked.txt ;;
        standalone_tracked|standalone_untracked)
            unset GATEWAY_SIG_GUARD_BASELINE
            printf 'untracked source\n' >"$baseline/untracked.txt"
            ;;
    esac

    git() {
        local destination
        if [[ "$1" == clone ]]; then
            destination="${!#}"
            case "$mode" in
                mktemp_failure) : >"$case_root/clone-attempt" ;;
                clone_failure) return 71 ;;
                partial_clone_failure) mkdir -p "$destination/partial"; return 72 ;;
            esac
            "$REAL_GIT" "$@" || return
            if [[ "$mode" == clone_head_mismatch ]]; then
                "$REAL_GIT" -C "$destination" reset -q --hard "$OLDER_HEAD" || return
            fi
            return 0
        fi
        if [[ "$1" == -C && "$3" == rev-parse ]]; then
            if [[ "$mode" == head_read_failure && "$2" == "$baseline" ]] ||
                [[ "$mode" == clone_head_read_failure && "$2" != "$baseline" ]]; then
                return 73
            fi
        fi
        if [[ "$1" == -C && "$3" == status && "$mode" == status_failure ]]; then
            return 74
        fi
        if [[ "$1" == -C && "$3" == config ]]; then
            if [[ "$mode" == maintenance_failure && "$4" == maintenance.auto ]] ||
                [[ "$mode" == gc_failure && "$4" == gc.auto ]]; then
                return 75
            fi
        fi
        "$REAL_GIT" "$@"
    }
    mktemp() {
        if [[ "$mode" == mktemp_failure ]]; then return 76; fi
        command mktemp "$@"
    }

    if make_sandbox >"$output" 2>&1; then rc=0; else rc=$?; fi
    case "$mode" in
        empty|missing|file|nongit|unborn|unstaged|staged|untracked|deleted|staged_deleted|head_read_failure|status_failure)
            expected='invalid signature guard baseline'
            ;;
        clone_failure|partial_clone_failure|clone_head_mismatch|clone_head_read_failure|maintenance_failure|gc_failure|mktemp_failure)
            expected='cannot prepare signature guard baseline'
            ;;
        *) expected="" ;;
    esac
    if [[ -n "$expected" ]]; then
        if ! leftovers="$(find "$tmp" -mindepth 1 -print -quit)" ||
            [[ "$rc" -eq 0 || -n "$SANDBOX" || -n "$leftovers" ]] || ! grep -q "$expected" "$output"; then
            printf 'refusal/publication/cleanup failed for %s (exit %s)\n' "$mode" "$rc" >&2
            cat "$output" >&2
            return 1
        fi
        [[ "$mode" != mktemp_failure || ! -f "$case_root/clone-attempt" ]] || return 1
        return 0
    fi
    if [[ "$rc" -ne 0 || ! -d "$SANDBOX/.git" ]]; then
        cat "$output" >&2
        return 1
    fi

    case "$mode" in
        no_baseline_objects)
            local baseline_objects child_objects
            baseline_objects="$(find "$baseline/.git/objects" -type f ! -path '*/info/*' -print -quit)" || return
            child_objects="$(find "$SANDBOX/.git/objects" -type f ! -path '*/info/*' -print -quit)" || return
            [[ -n "$baseline_objects" && -z "$child_objects" ]]
            ;;
        borrowed_object_access)
            local object
            object="$("$REAL_GIT" -C "$baseline" rev-parse HEAD:tracked.txt)" || return
            "$REAL_GIT" -C "$SANDBOX" cat-file -e "$object"
            ;;
        index_isolation)
            local index_rc=0
            [[ ! "$SANDBOX/.git/index" -ef "$baseline/.git/index" ]] || return 1
            printf 'child index\n' >"$SANDBOX/tracked.txt"
            "$REAL_GIT" -C "$SANDBOX" add tracked.txt || return
            "$REAL_GIT" -C "$SANDBOX" diff --cached --quiet || index_rc=$?
            [[ "$index_rc" -eq 1 ]] || return 1
            "$REAL_GIT" -C "$baseline" diff --cached --quiet
            ;;
        child_worktree_isolation)
            printf 'child worktree\n' >"$SANDBOX/tracked.txt"
            [[ "$(cat "$baseline/tracked.txt")" == baseline ]]
            ;;
        parent_worktree_isolation)
            printf 'parent worktree\n' >"$baseline/tracked.txt"
            [[ "$(cat "$SANDBOX/tracked.txt")" == baseline ]]
            ;;
        child_ref_isolation)
            local ref_rc=0
            "$REAL_GIT" -C "$SANDBOX" update-ref refs/heads/child-only HEAD || return
            "$REAL_GIT" -C "$SANDBOX" show-ref --verify --quiet refs/heads/child-only || return
            "$REAL_GIT" -C "$baseline" show-ref --verify --quiet refs/heads/child-only || ref_rc=$?
            [[ "$ref_rc" -eq 1 ]]
            ;;
        parent_ref_isolation)
            local ref_rc=0
            "$REAL_GIT" -C "$baseline" update-ref refs/heads/parent-only HEAD || return
            "$REAL_GIT" -C "$baseline" show-ref --verify --quiet refs/heads/parent-only || return
            "$REAL_GIT" -C "$SANDBOX" show-ref --verify --quiet refs/heads/parent-only || ref_rc=$?
            [[ "$ref_rc" -eq 1 ]]
            ;;
        private_new_objects)
            local object object_rc=0
            object="$(printf 'child-only object\n' | "$REAL_GIT" -C "$SANDBOX" hash-object -w --stdin)" || return
            "$REAL_GIT" -C "$SANDBOX" cat-file -e "$object" || return
            "$REAL_GIT" -C "$baseline" cat-file -e "$object" 2>/dev/null || object_rc=$?
            [[ "$object_rc" -eq 1 ]]
            ;;
        maintenance_disabled) [[ "$("$REAL_GIT" -C "$SANDBOX" config --local maintenance.auto)" == false ]] ;;
        gc_disabled) [[ "$("$REAL_GIT" -C "$SANDBOX" config --local gc.auto)" == 0 ]] ;;
        standalone_tracked) [[ "$(cat "$SANDBOX/tracked.txt")" == baseline ]] ;;
        standalone_untracked) [[ "$(cat "$SANDBOX/untracked.txt")" == 'untracked source' ]] ;;
        *) return 1 ;;
    esac
)

negative=(empty missing file nongit unborn unstaged staged untracked deleted staged_deleted
    head_read_failure status_failure clone_failure partial_clone_failure clone_head_mismatch
    clone_head_read_failure maintenance_failure gc_failure mktemp_failure)
positive=(no_baseline_objects borrowed_object_access index_isolation child_worktree_isolation
    parent_worktree_isolation child_ref_isolation parent_ref_isolation private_new_objects
    maintenance_disabled gc_disabled standalone_tracked standalone_untracked)
executed=0
failures=0
for control in "${negative[@]}" "${positive[@]}"; do
    executed=$((executed + 1))
    if probe "$control"; then
        printf '  ok   %s\n' "$control"
    else
        printf '  FAIL %s\n' "$control" >&2
        failures=$((failures + 1))
    fi
done
printf '%s baseline controls (%s negative, %s positive), %s failure(s)\n' \
    "$executed" "${#negative[@]}" "${#positive[@]}" "$failures"
[[ "$executed" -eq 31 && "${#negative[@]}" -gt "${#positive[@]}" && "$failures" -eq 0 ]]
