#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# test_guard_scripts.sh
#
# WHAT THIS CHECKS
#   That every guard in `scripts/check_*.sh` (a) passes on the repository as it
#   stands, and (b) actually FAILS when the violation it exists to catch is
#   introduced. Each negative case is run against a throwaway copy of the
#   repository in a temporary directory via `GATEWAY_CHECK_ROOT`; the working
#   tree is never modified.
#
# WHY
#   A guard that cannot fail is worse than no guard: it produces a green check
#   mark that everyone trusts. Every one of these scripts is a few dozen lines
#   of shell and awk, and a typo in a regex turns it into a no-op silently.
#   The negative cases are the only evidence that the guards do anything.
#
# HOW TO EXEMPT
#   Not applicable — this is the test, not a policy guard.
#
# USAGE
#   scripts/test_guard_scripts.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

failures=0
cases=0
QUIRK_LEDGER_ONLY="${GATEWAY_GUARD_QUIRK_LEDGER_ONLY:-0}"
if [[ "$QUIRK_LEDGER_ONLY" != 0 && "$QUIRK_LEDGER_ONLY" != 1 ]]; then
    printf 'test_guard_scripts: GATEWAY_GUARD_QUIRK_LEDGER_ONLY must be 0 or 1\n' >&2
    exit 1
fi

pass_msg() { printf '  ok   %s\n' "$*"; }
fail_msg() {
    printf '  FAIL %s\n' "$*" >&2
    failures=$((failures + 1))
}

# One sandbox, reused. Each negative case mutates it, the guard runs, and only the paths
# changed by that case are checked out before untracked files are cleaned. Checking out
# the whole tree for every case made the reset cost grow with the repository rather than
# with the mutation and pushed the suite past the ten-minute CI budget.
SANDBOX=""
SANDBOX_RESET_TRACKED=""
SANDBOX_RESET_UNTRACKED=""
SANDBOX_RESET_READY=0
QUIRK_LEDGER_PARSE_CACHE=""

literalize_nul_paths() {
    local input="$1" output="$2" path
    : >"$output"
    while IFS= read -r -d '' path; do
        printf ':(literal)%s\0' "$path" >>"$output"
    done <"$input"
}

reset_sandbox_changes() {
    local sandbox="$1" changed changed_literal untracked path
    if [[ "$sandbox" == "$SANDBOX" && "$SANDBOX_RESET_READY" -eq 1 ]]; then
        # Consume before touching Git so an interrupted or failed reset can never leak paths into
        # the next case. The cache contains only literal NUL entries published after staging.
        SANDBOX_RESET_READY=0
        local rc=0
        (
            cd "$sandbox"
            if [[ -s "$SANDBOX_RESET_TRACKED" ]]; then
                git reset -q HEAD --pathspec-from-file="$SANDBOX_RESET_TRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
            fi
            if [[ -s "$SANDBOX_RESET_UNTRACKED" ]]; then
                git reset -q HEAD --pathspec-from-file="$SANDBOX_RESET_UNTRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
                while IFS= read -r -d '' path; do
                    git clean -fdq -- "$path" >/dev/null 2>&1 || exit $?
                done <"$SANDBOX_RESET_UNTRACKED"
            fi
            if [[ -s "$SANDBOX_RESET_TRACKED" ]]; then
                git checkout -f HEAD --pathspec-from-file="$SANDBOX_RESET_TRACKED" \
                    --pathspec-file-nul >/dev/null 2>&1 || exit $?
            fi
        ) || rc=$?
        : >"$SANDBOX_RESET_TRACKED"
        : >"$SANDBOX_RESET_UNTRACKED"
        return "$rc"
    fi

    # Special probes that deliberately bypass staging have no cache. Scan once for those callers;
    # ordinary negative cases always arrive through stage_sandbox_changes and avoid this path.
    changed="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-changed.XXXXXX")"
    changed_literal="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-changed-literal.XXXXXX")"
    untracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-untracked.XXXXXX")"
    local rc=0
    (
        cd "$sandbox"
        git diff --name-only -z HEAD -- >"$changed" || exit $?
        if [[ -s "$changed" ]]; then
            literalize_nul_paths "$changed" "$changed_literal"
            git reset -q HEAD --pathspec-from-file="$changed_literal" \
                --pathspec-file-nul >/dev/null 2>&1 || exit $?
        fi
        git ls-files --others --exclude-standard -z >"$untracked" || exit $?
        while IFS= read -r -d '' path; do
            git clean -fdq -- ":(literal)${path}" >/dev/null 2>&1 || exit $?
        done <"$untracked"
        git diff --name-only -z HEAD -- >"$changed" || exit $?
        if [[ -s "$changed" ]]; then
            literalize_nul_paths "$changed" "$changed_literal"
            git checkout -f HEAD --pathspec-from-file="$changed_literal" \
                --pathspec-file-nul >/dev/null 2>&1 || exit $?
        fi
    ) || rc=$?
    rm -f "$changed" "$changed_literal" "$untracked"
    return "$rc"
}

# Reuse the caller's build directory. A guard that declares REQUIRES-BUILD compiles
# the workspace, and a separate target/ recompiles it after `cargo test --workspace`.
# CI measured that duplication past the ten-minute hard limit. Sandbox mutations still
# rebuild affected workspace crates because Cargo fingerprints their different source
# root, while registry dependencies and the positive control remain reusable.
#
# Sharing is sound because a sandbox differs from the tree only in the one file a case
# mutates: every dependency is already built, and cargo rebuilds the workspace crates
# alone. It is not a correctness shortcut — the guards still read the sandbox, and
# CARGO_TARGET_DIR changes where objects land, not what is compiled.
GUARD_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
export CARGO_TARGET_DIR="$GUARD_TARGET_DIR"

make_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        reset_sandbox_changes "$SANDBOX"
        return
    fi

    local dir list archive
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-test.XXXXXX")"
    # `tar --null -T -` is GNU-only; BSD tar (macOS) rejects it, and letting the failing
    # call write to the pipe before the fallback produces a spurious "tar: Write error"
    # that would mask a real one. A list file is understood by both.
    #
    # The pinned model JSON used to be excluded here as 3.2 MB no guard read.
    # check_route_coverage.sh reads it, and the exclusion made that guard skip
    # its own self-test while reporting success — so the sandbox now carries the
    # whole tree. One sandbox is built per run and reset between cases, so the
    # 3.2 MB is paid once.
    list="${dir}.files"
    archive="${dir}.tar"
    # Include new, unignored files: a guard introduced in the same change must be able to test its
    # own inputs before the author stages them.
    if ! (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && tar -xf "$archive"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! rm -f "$list" "$archive"; then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git init -q .); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git add -A >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
    SANDBOX="$dir"
    SANDBOX_RESET_TRACKED="${dir}.reset-tracked"
    SANDBOX_RESET_UNTRACKED="${dir}.reset-untracked"
    : >"$SANDBOX_RESET_TRACKED"
    : >"$SANDBOX_RESET_UNTRACKED"
    SANDBOX_RESET_READY=0
}

# Stage only paths changed by the current mutation. A repository-wide `git add -A` rescans every
# workspace file for every negative case; the guard reads the same index when the exact tracked and
# untracked paths are staged explicitly.
stage_sandbox_changes() {
    local sandbox="$1" tracked untracked paths
    tracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-tracked.XXXXXX")"
    untracked="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-untracked.XXXXXX")"
    paths="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-stage-paths.XXXXXX")"
    if [[ "$sandbox" == "$SANDBOX" ]]; then
        SANDBOX_RESET_READY=0
        : >"$SANDBOX_RESET_TRACKED"
        : >"$SANDBOX_RESET_UNTRACKED"
    fi
    if ! (
        cd "$sandbox"
        git diff --name-only -z HEAD -- >"$tracked" &&
            git ls-files --others --exclude-standard -z >"$untracked"
    ); then
        rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
        return 1
    fi
    literalize_nul_paths "$tracked" "$paths.tracked"
    literalize_nul_paths "$untracked" "$paths.untracked"
    cat "$paths.tracked" "$paths.untracked" >"$paths"
    if [[ -s "$paths" ]] && ! (
        cd "$sandbox"
        git add -A --pathspec-from-file="$paths" --pathspec-file-nul
    ); then
        rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
        return 1
    fi
    if [[ "$sandbox" == "$SANDBOX" ]]; then
        cp "$paths.tracked" "$SANDBOX_RESET_TRACKED"
        cp "$paths.untracked" "$SANDBOX_RESET_UNTRACKED"
        SANDBOX_RESET_READY=1
    fi
    rm -f "$tracked" "$untracked" "$paths" "$paths.tracked" "$paths.untracked"
}

cleanup_sandbox() {
    # Must return 0: an EXIT trap's status becomes the script's status, so a bare
    # `[[ -n "$SANDBOX" ]] && rm -rf` reports failure whenever no sandbox was made,
    # and the suite would exit 1 while printing "0 failures".
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX"
    fi
    rm -f "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    if [[ -n "$QUIRK_LEDGER_PARSE_CACHE" ]]; then
        rm -f "$QUIRK_LEDGER_PARSE_CACHE"
    fi
    return 0
}
trap cleanup_sandbox EXIT

# expect_fail_unstaged <guard> <description> <mutation-fn>
# Same as expect_fail, but deliberately does NOT `git add` the mutation. This is what
# distinguishes a guard that reads the working tree from one that only reads the index.
expect_fail_unstaged() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches (unstaged): ${desc}"
    else
        fail_msg "${guard} did NOT catch (unstaged): ${desc}"
    fi
}

# expect_english_fail_minimal <description> <mutation-fn> <path> <tracked|untracked>
# The English-only guard needs Git metadata but not the workspace. Keeping these controls in tiny,
# independent repositories preserves the tracked/untracked contract without copying the full tree.
expect_english_fail_minimal() {
    local desc="$1" mutate="$2" path="$3" mode="$4"
    local sandbox output rc=0
    cases=$((cases + 1))
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/gateway-english-test.XXXXXX")"
    mkdir -p "$sandbox/$(dirname "$path")" "$sandbox/scripts/allowances"
    printf 'Visible English — middle · dot.\n' >"$sandbox/visible-control.txt"
    if [[ "$mode" == tracked ]]; then
        printf 'Visible English — middle · dot.\n' >"$sandbox/$path"
    elif [[ "$mode" != untracked ]]; then
        rm -rf "$sandbox"
        fail_msg "check_english_only.sh has an unsupported minimal-test mode: ${mode}"
        return
    fi
    (
        cd "$sandbox"
        git init -q .
        git add -A
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    if ! GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_english_only.sh" >/dev/null 2>&1; then
        rm -rf "$sandbox"
        fail_msg "check_english_only.sh rejects its visible English, em-dash, or middle-dot control: ${desc}"
        return
    fi
    (cd "$sandbox" && "$mutate" >/dev/null)
    if [[ "$mode" == tracked ]]; then
        (cd "$sandbox" && git add -A >/dev/null 2>&1)
    fi
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_english_only.sh" 2>&1)" || rc=$?
    rm -rf "$sandbox"
    if [[ "$rc" -ne 0 && "$output" == *"${path}: contains CJK text"* ]]; then
        if [[ "$mode" == tracked ]]; then
            pass_msg "check_english_only.sh catches: ${desc}"
        else
            pass_msg "check_english_only.sh catches (unstaged): ${desc}"
        fi
    else
        fail_msg "check_english_only.sh did not reject the CJK mutation at ${path}: ${desc}"
    fi
}

# expect_fail <guard> <description> <mutation-fn>
# Runs the mutation inside a sandbox, then asserts the guard exits non-zero.
expect_fail() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox output rc=0
    cases=$((cases + 1))
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    output="$(GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
    local expected_diagnostic="" diagnostic_helper diagnostic_fragment
    if [[ "$guard" == check_quirk_ledger.sh ]]; then
        while IFS=$'\t' read -r diagnostic_helper diagnostic_fragment; do
            if [[ "$diagnostic_helper" == "$mutate" ]]; then
                expected_diagnostic="$diagnostic_fragment"
                break
            fi
        done <<<"$QUIRK_LEDGER_DIAGNOSTICS"
    fi
    if [[ "$rc" -ne 0 && ( "$guard" != check_quirk_ledger.sh || ( -n "$expected_diagnostic" && "$output" == *"$expected_diagnostic"* ) ) ]]; then
        pass_msg "${guard} catches: ${desc}"
    elif [[ "$rc" -ne 0 ]]; then
        fail_msg "${guard} failed without its policy diagnostic: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}

# expect_guard_pass <guard> <description> <mutation-fn>
# Proves token decoys stay ignored while the same syntax in active Rust is rejected separately.
expect_guard_pass() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg "${guard} accepts: ${desc}"
    else
        fail_msg "${guard} rejected its positive control: ${desc}"
    fi
}

# expect_fail_self_mutation <guard> <description> <mutation-fn>
# Runs the sandbox's copy of a guard when the mutation changes the guard policy itself. Calling
# SCRIPT_DIR here would exercise the unmodified source-tree copy and make every such mutation a
# false green.
expect_fail_self_mutation() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "$sandbox/scripts/$guard" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches its own mutation: ${desc}"
    else
        fail_msg "${guard} did NOT catch its own mutation: ${desc}"
    fi
}

# expect_fail_and_missing_grep <guard> <description> <mutation-fn>
# Proves both the policy mutation and the dependency-missing path while keeping them one guard case.
expect_fail_and_missing_grep() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox mutation_rc=0 missing_rc=0 missing_output tool_path clean=1
    cases=$((cases + 1))
    if [[ ! -x "${SCRIPT_DIR}/${guard}" ]]; then
        fail_msg "${guard} is missing or not executable; cannot test: ${desc}"
        return
    fi
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || mutation_rc=$?

    make_sandbox
    sandbox="$SANDBOX"
    if ! (
        cd "$sandbox"
        git diff --quiet HEAD -- &&
            git diff --cached --quiet HEAD -- &&
            [[ -z "$(git ls-files --others --exclude-standard)" ]]
    ); then
        clean=0
    fi
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    missing_output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || missing_rc=$?
    rm -rf "$tool_path"

    if [[ "$mutation_rc" -ne 0 && "$clean" -eq 1 && "$missing_rc" -ne 0 && "$missing_output" == *'required command is missing: grep'* ]]; then
        pass_msg "${guard} catches: ${desc}; missing grep also fails closed"
    else
        fail_msg "${guard} did not catch its mutation or reported green without grep: ${desc}"
    fi
}

# check_monomorphic_dispatch reads compiler output rather than repository source. Feed it a tiny
# LLVM mutation directly so the negative control proves that an indirect handler call is rejected
# without paying for a second release build.
expect_monomorphic_ir_fail() {
    local desc="$1" mutate="$2"
    local sandbox ir rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && "$mutate" >/dev/null)
    ir="$sandbox/scripts/monomorphic-indirect.ll"
    GATEWAY_CHECK_ROOT="$sandbox" GATEWAY_MONOMORPHIC_IR="$ir" \
        "${SCRIPT_DIR}/check_monomorphic_dispatch.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "check_monomorphic_dispatch.sh catches: ${desc}"
    else
        fail_msg "check_monomorphic_dispatch.sh did NOT catch: ${desc}"
    fi
}

# -----------------------------------------------------------------------------
# Positive control: the repository as it stands must be clean.
# -----------------------------------------------------------------------------
if [[ "$QUIRK_LEDGER_ONLY" == 0 ]]; then
printf 'Positive control (repository must be clean)\n'
for guard in "${SCRIPT_DIR}"/check_*.sh; do
    cases=$((cases + 1))
    if "$guard" >/dev/null 2>&1; then
        pass_msg "$(basename "$guard")"
    else
        fail_msg "$(basename "$guard") fails on the current tree"
    fi
done

# -----------------------------------------------------------------------------
# Negative cases
# -----------------------------------------------------------------------------
printf '\nNegative cases (guards must fail)\n'

# The codegen feedback loop must not rebuild product crates before generation starts.
mut_xtask_codegen_alias_restores_full_defaults() {
    perl -0pi -e 's/ --no-default-features//' .cargo/config.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the cargo xtask alias restoring full default features for codegen' \
    mut_xtask_codegen_alias_restores_full_defaults

mut_xtask_codegen_gateway_becomes_nonoptional() {
    perl -0pi -e 's/rustfs-gateway = \{ workspace = true, optional = true \}/rustfs-gateway = { workspace = true }/' \
        xtask/Cargo.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the light codegen runner regaining the facade dependency' \
    mut_xtask_codegen_gateway_becomes_nonoptional

mut_xtask_full_forgets_conformance() {
    perl -0pi -e 's/    "dep:rustfs-gateway-conformance",\n//' xtask/Cargo.toml
}
expect_fail check_xtask_codegen_surface.sh \
    'the full xtask feature dropping a full-only dependency edge' \
    mut_xtask_full_forgets_conformance

mut_xtask_codegen_reexecutes_full_runner() {
    perl -0pi -e 's/Some\("codegen"\) => codegen::codegen\(&rest\)/Some("codegen") => run_full(first.clone(), \&rest)/g' \
        xtask/src/main.rs
}
expect_fail check_xtask_codegen_surface.sh \
    'the codegen command re-entering the full dependency surface' \
    mut_xtask_codegen_reexecutes_full_runner

mut_xtask_codegen_comment_decoy_reexec() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("codegen") => codegen::codegen(&rest),'
positions = [index for index in range(len(text)) if text.startswith(old, index)]
if len(positions) != 2:
    raise SystemExit("expected exactly two codegen dispatch arms")
index = positions[1]
new = 'Some("codegen") => run_full(first.clone(), &rest), // Some("codegen") => codegen::codegen(&rest),'
path.write_text(text[:index] + new + text[index + len(old):])
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a comment decoy hiding light codegen re-execution' \
    mut_xtask_codegen_comment_decoy_reexec

mut_xtask_codegen_target_dependency() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
text += '''
[target.'cfg(unix)'.dependencies]
hidden_gateway = { package = "rustfs-gateway", path = "../crates/gateway" }
'''
path.write_text(text)
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a target-specific dependency restoring the facade on the light runner' \
    mut_xtask_codegen_target_dependency

mut_xtask_full_runner_drops_rest() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "    command.args(rest);"
new = "    let _ = rest; // command.args(rest);"
if text.count(old) != 1:
    raise SystemExit("full runner rest forwarding is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the full runner dropping the remaining arguments' \
    mut_xtask_full_runner_drops_rest

mut_xtask_nonunix_runner_hides_failure() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "        Ok(status) => std::process::exit(status.code().unwrap_or(1)),"
new = "        Ok(_) => std::process::exit(0),"
if text.count(old) != 1:
    raise SystemExit("non-Unix i32 status propagation is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the non-Unix bridge reporting a failing child as success' \
    mut_xtask_nonunix_runner_hides_failure

mut_xtask_codegen_string_token_changes() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("codegen") => codegen::codegen(&rest),'
positions = [index for index in range(len(text)) if text.startswith(old, index)]
if len(positions) != 2:
    raise SystemExit("expected exactly two codegen dispatch arms")
index = positions[1]
new = 'Some("code gen") => codegen::codegen(&rest),'
path.write_text(text[:index] + new + text[index + len(old):])
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'whitespace changing the light codegen command token' \
    mut_xtask_codegen_string_token_changes

mut_xtask_full_feature_string_token_changes() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'command.args(["run", "--quiet", "--package", "xtask", "--features", "full", "--"]);'
new = 'command.args(["run", "--quiet", "--package", "xtask", "--features", "f ull", "--"]);'
if text.count(old) != 1:
    raise SystemExit("full feature runner arguments are missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'whitespace changing the full-runner feature token' \
    mut_xtask_full_feature_string_token_changes

mut_xtask_light_builds_full_catalog_helper() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/catalog.rs")
text = path.read_text()
old = '#[cfg(feature = "full")]\npub(crate) fn nearest'
if text.count(old) != 1:
    raise SystemExit("full-only catalog helper is missing")
path.write_text(text.replace(old, "pub(crate) fn nearest", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light runner compiling a full-only catalog helper' \
    mut_xtask_light_builds_full_catalog_helper

mut_xtask_light_builds_full_usage() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = '#[cfg(feature = "full")]\nconst USAGE: &str'
if text.count(old) != 1:
    raise SystemExit("full-only usage declaration is missing")
path.write_text(text.replace(old, "const USAGE: &str", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light runner compiling the full-only usage text' \
    mut_xtask_light_builds_full_usage

mut_xtask_crate_verify_reexecutes_full_runner() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("verify") if verify::is_crate_request(&rest) => verify::verify(&rest),'
new = 'Some("verify") if verify::is_crate_request(&rest) => run_full(first, &rest),'
if text.count(old) != 1:
    raise SystemExit("expected exactly one light crate-verification dispatch arm")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'exact crate verification re-entering the full runner' \
    mut_xtask_crate_verify_reexecutes_full_runner

mut_xtask_crate_verify_drops_arguments() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = 'Some("verify") if verify::is_crate_request(&rest) => verify::verify(&rest),'
new = 'Some("verify") if verify::is_crate_request(&rest) => verify::verify(&[]),'
if text.count(old) != 1:
    raise SystemExit("expected exactly one light crate-verification dispatch arm")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light crate-verification runner dropping its arguments' \
    mut_xtask_crate_verify_drops_arguments

mut_xtask_process_supervisor_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "command-group.workspace = true"
new = "command-group = { workspace = true, optional = true }"
if text.count(old) != 1:
    raise SystemExit("light process-supervisor dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the crate-verification process supervisor becoming full-only' \
    mut_xtask_process_supervisor_becomes_full_only

mut_xtask_verify_operation_loses_full_gate() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(feature = "full")]\nfn verify_operation'
new = 'fn verify_operation'
if text.count(old) != 1:
    raise SystemExit("full-only operation verifier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'an operation-only verifier leaking into the light crate surface' \
    mut_xtask_verify_operation_loses_full_gate

mut_xtask_full_verify_uses_unstable_slice_conversion() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "fn verify_full(args: &[String], json: bool) -> ExitCode {\n    match args {"
new = "fn verify_full(args: &[String], json: bool) -> ExitCode {\n    match args.as_slice() {"
if text.count(old) != 1:
    raise SystemExit("borrowed full-verification slice match is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'full verification calling unstable as_slice on an existing slice' \
    mut_xtask_full_verify_uses_unstable_slice_conversion

mut_xtask_core_fast_scope_loses_compile_fail_skip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '''    if package == "rustfs-gateway-core" {
        test_step.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
        ]);
    }
'''
if text.count(old) != 1:
    raise SystemExit("core compile-fail fast-scope skip is missing")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope losing its compile-fail skip' \
    mut_xtask_core_fast_scope_loses_compile_fail_skip

mut_xtask_core_fast_scope_renames_compile_fail_skip() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '"compile_fail::compile_time_contracts_are_not_openable".to_owned(),'
new = '"compile_fail::renamed_contract".to_owned(),'
if text.count(old) != 1:
    raise SystemExit("core compile-fail skip name is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core fast scope naming a nonexistent skipped test' \
    mut_xtask_core_fast_scope_renames_compile_fail_skip

mut_xtask_compile_fail_skip_applies_to_every_crate() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = 'if package == "rustfs-gateway-core" {'
new = 'if !package.is_empty() {'
if text.count(old) != 2:
    raise SystemExit("core-only skip and diagnostic conditions are not both present")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the core compile-fail skip leaking into another crate scope' \
    mut_xtask_compile_fail_skip_applies_to_every_crate

mut_xtask_crate_classifier_leaks_into_full_build() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = '#[cfg(not(feature = "full"))]\npub(crate) fn is_crate_request'
new = 'pub(crate) fn is_crate_request'
if text.count(old) != 1:
    raise SystemExit("light-only crate classifier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the light crate classifier leaking as dead code into full builds' \
    mut_xtask_crate_classifier_leaks_into_full_build

mut_xtask_light_gate_result_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "type GateResult = (String, std::io::Result<Output>);"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light gate-result carrier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gate-result carrier becoming unavailable to light crate verification' \
    mut_xtask_light_gate_result_becomes_full_only

mut_xtask_light_gate_command_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "type GateCommand = (String, Vec<String>, String);"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light gate-command carrier is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the gate-command carrier becoming unavailable to light crate verification' \
    mut_xtask_light_gate_command_becomes_full_only

mut_xtask_light_output_import_becomes_full_only() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/verify.rs")
text = path.read_text()
old = "use std::process::{Command, ExitCode, Output};"
new = '#[cfg(feature = "full")]\n' + old
if text.count(old) != 1:
    raise SystemExit("light process-output import is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the process-output import becoming unavailable to light crate verification' \
    mut_xtask_light_output_import_becomes_full_only

mut_xtask_full_forwards_dangerous_dependency_feature() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = '    "dep:rustfs-gateway",'
new = old + '\n    "rustfs-gateway/dangerous-allow-all-authorizer",'
if text.count(old) != 1:
    raise SystemExit("full facade dependency feature is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the full feature forwarding a dangerous facade feature' \
    mut_xtask_full_forwards_dangerous_dependency_feature

mut_xtask_facade_dependency_enables_dangerous_feature() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "rustfs-gateway = { workspace = true, optional = true }"
new = 'rustfs-gateway = { workspace = true, optional = true, features = ["dangerous-allow-all-authorizer"] }'
if text.count(old) != 1:
    raise SystemExit("optional facade dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the local facade dependency enabling its dangerous authorizer feature' \
    mut_xtask_facade_dependency_enables_dangerous_feature

mut_xtask_local_dependency_changes_default_features() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/Cargo.toml")
text = path.read_text()
old = "signal-hook.workspace = true"
new = "signal-hook = { workspace = true, default-features = false }"
if text.count(old) != 1:
    raise SystemExit("light signal-hook dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'a local dependency overriding inherited default features' \
    mut_xtask_local_dependency_changes_default_features

mut_xtask_inherits_dangerous_facade_feature() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
old = 'rustfs-gateway = { path = "crates/gateway", version = "0.5.0" }'
new = 'rustfs-gateway = { path = "crates/gateway", version = "0.5.0", features = ["dangerous-allow-all-authorizer"] }'
if text.count(old) != 1:
    raise SystemExit("workspace facade dependency is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace facade dependency injecting its dangerous authorizer feature' \
    mut_xtask_inherits_dangerous_facade_feature

mut_xtask_inherits_jsonschema_default_features() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
old = 'jsonschema = { version = "0.48.2", default-features = false }'
new = 'jsonschema = { version = "0.48.2", default-features = true }'
if text.count(old) != 1:
    raise SystemExit("workspace jsonschema dependency policy is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the workspace jsonschema dependency restoring default features' \
    mut_xtask_inherits_jsonschema_default_features

mut_xtask_nonunix_runner_truncates_large_status() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("xtask/src/main.rs")
text = path.read_text()
old = "        Ok(status) => std::process::exit(status.code().unwrap_or(1)),"
new = "        Ok(status) => return ExitCode::from(status.code().unwrap_or(1) as u8),"
if text.count(old) != 1:
    raise SystemExit("non-Unix i32 status propagation is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_xtask_codegen_surface.sh \
    'the non-Unix bridge truncating a child status above 255' \
    mut_xtask_nonunix_runner_truncates_large_status

mut_scalar_duplicate_acceptance_id() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_scalar_case_coverage.sh")
text = path.read_text()
old = "for n in 001 002 003 004 005 006 007 008 009 010; do"
new = "for n in 001 002 003 004 005 006 007 008 009 009; do"
if old not in text:
    raise SystemExit("scalar acceptance id loop is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_scalar_case_coverage.sh \
    'one acceptance id replacing another while the total stays 71' mut_scalar_duplicate_acceptance_id

mut_scalar_test_replaced_by_comment_and_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/name_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe()"
new = '''// #[test]
// fn c_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe() {}
const DECOY: &str = "fn c_name_n009_a_";
#[test]
fn removed_name_n009_a_dotted_bucket_is_legal_but_not_vhost_safe()'''
if old not in text:
    raise SystemExit("scalar test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'comments and strings replacing a mapped scalar test' mut_scalar_test_replaced_by_comment_and_string

mut_scalar_objectlock_case_does_not_replace_ts_n006() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/timestamp_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_ts_n006_the_object_lock_header_only_accepts_iso8601()"
new = "#[test]\nfn removed_ts_n006_the_object_lock_header_only_accepts_iso8601()"
if text.count(old) != 1:
    raise SystemExit("c-ts-n006 scalar acceptance test is not unique")
if text.count("fn c_objectlock_0001_the_object_lock_header_only_accepts_iso8601()") != 1:
    raise SystemExit("c-objectlock-0001 quirk case must remain independently registered")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'the object-lock quirk case replacing the independent c-ts-n006 acceptance id' \
    mut_scalar_objectlock_case_does_not_replace_ts_n006

mut_scalar_id_maps_to_two_active_tests() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/name_tests.rs")
text = path.read_text()
text += "\n#[test]\nfn c_name_n009_duplicate_atomic_evidence() {}\n"
path.write_text(text)
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'one scalar id mapping to two active tests' mut_scalar_id_maps_to_two_active_tests

mut_scalar_test_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/timestamp_corpus_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_ts_0001_complete_smithy_timestamp_corpus_matches_gateway_codec()"
new = "#[cfg(any())]\n#[test]\nfn c_ts_0001_complete_smithy_timestamp_corpus_matches_gateway_codec()"
if old not in text:
    raise SystemExit("timestamp corpus test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a cfg-disabled scalar test being counted as executable evidence' mut_scalar_test_disabled_by_cfg

mut_scalar_test_module_unwired() {
    perl -0pi -e 's/^mod timestamp_corpus_tests;\n//m' crates/types/src/scalar/tests/mod.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a scalar test file no longer wired into its parent module' mut_scalar_test_module_unwired

mut_scalar_test_file_disabled_by_cfg() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg(any())]\n$1/' \
        crates/types/src/scalar/tests/timestamp_corpus_tests.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a file-level cfg disabling mapped scalar tests' mut_scalar_test_file_disabled_by_cfg

mut_scalar_test_file_disabled_by_cfg_attr() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/types/src/scalar/tests/timestamp_corpus_tests.rs
}
expect_fail check_scalar_case_coverage.sh \
    'a file-level cfg_attr disabling mapped scalar tests' mut_scalar_test_file_disabled_by_cfg_attr

mut_scalar_test_replaced_by_macro_body() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/tests/range_tests.rs")
text = path.read_text()
old = "#[test]\nfn c_rng_0001_a_closed_range_resolves_to_itself()"
new = '''macro_rules! decoy_scalar_test {
    () => {
        #[test]
        fn c_rng_0001_a_closed_range_resolves_to_itself() {}
    };
}
#[test]
fn removed_rng_0001_a_closed_range_resolves_to_itself()'''
if old not in text:
    raise SystemExit("range test mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a test name surviving only inside an unexpanded macro body' mut_scalar_test_replaced_by_macro_body

mut_scalar_case_id_replaced_by_comment() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("conformance/cases/range/c-range-0015.toml")
text = path.read_text()
old = 'id = "c-range-0015"'
new = '# id = "c-range-0015"\nid = "removed-range-0015"'
if old not in text:
    raise SystemExit("range case id mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_scalar_case_coverage.sh \
    'a commented TOML id replacing the active conformance case id' mut_scalar_case_id_replaced_by_comment

probe_scalar_case_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scalar-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_scalar_case_coverage.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_scalar_case_coverage.sh fails closed without python3'
    else
        fail_msg 'check_scalar_case_coverage.sh reported green without python3'
    fi
}
probe_scalar_case_guard_missing_python

mut_etag_display_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
path.write_text(path.read_text() + "\nimpl std::fmt::Display for ETag { fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) } }\n")
PYEOF
}
expect_fail check_etag_render.sh \
    'ETag acquiring a default Display rendering' mut_etag_display_added

mut_etag_into_string_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
path.write_text(path.read_text() + "\nimpl From<ETag> for String { fn from(_: ETag) -> Self { String::new() } }\n")
PYEOF
}
expect_fail check_etag_render.sh \
    'ETag acquiring a default String conversion' mut_etag_into_string_added

mut_etag_contextual_render_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/etag.rs")
text = path.read_text()
path.write_text(text.replace("pub fn render(&self, ctx: EtagRender)", "pub fn render_default(&self, ctx: EtagRender)", 1))
PYEOF
}
expect_fail check_etag_render.sh \
    'the sole contextual ETag render entry being removed' mut_etag_contextual_render_removed

mut_opaque_date_parser_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/opaque_string.rs")
text = path.read_text()
path.write_text(text.replace("impl OpaqueString {", "impl OpaqueString {\n    pub fn parse_as_date(&self) {}", 1))
PYEOF
}
expect_fail check_opaque_string.sh \
    'OpaqueString acquiring a date parser' mut_opaque_date_parser_added

mut_checksum_default_features_enabled() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("Cargo.toml")
text = path.read_text()
path.write_text(text.replace("default-features = false, features = [\"std\"]", "default-features = true, features = [\"std\"]", 1))
PYEOF
}
expect_fail check_checksum_dependencies.sh \
    'crc-fast default features being enabled' mut_checksum_default_features_enabled

mut_checksum_workspace_inheritance_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("crc-fast = { workspace = true }", "crc-fast = { version = \"1.10\" }", 1))
PYEOF
}
expect_fail check_checksum_dependencies.sh \
    'the types crate bypassing the reviewed crc-fast declaration' mut_checksum_workspace_inheritance_removed

mut_crc_fast_unsafe_record_removed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/allowances/unsafe-code-allowances.txt")
text = path.read_text()
path.write_text("\n".join(line for line in text.splitlines() if not line.startswith("crc-fast|")) + "\n")
PYEOF
}
expect_fail check_unsafe_code_allowances.sh \
    'the crc-fast external unsafe record being removed' mut_crc_fast_unsafe_record_removed

mut_local_unsafe_added() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("fuzz/fuzz_targets/etag_parse.rs")
path.write_text(path.read_text() + "\nunsafe fn mutation_only() {}\n")
PYEOF
}
expect_fail check_unsafe_code_allowances.sh \
    'a local Rust file acquiring unsafe code' mut_local_unsafe_added

mut_second_s3_error_bridge() {
    printf '\nimpl From<rustfs_gateway_core::HandlerError> for S3Error {\n    fn from(_: rustfs_gateway_core::HandlerError) -> Self { todo!() }\n}\n' \
        >>crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a second public bridge constructing S3Error before resolution' mut_second_s3_error_bridge

mut_multiline_nested_s3_error_bridge() {
    printf '\nimpl\n    From<Option<ErrorResolution>> for S3Error\n{\n    fn from(_: Option<ErrorResolution>) -> Self { todo!() }\n}\n' \
        >>crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a multiline nested-generic From bridge constructing S3Error' mut_multiline_nested_s3_error_bridge

mut_s3_error_bridge_takes_handler() {
    perl -0pi -e 's/impl From<ErrorResolution> for S3Error/impl From<HandlerError> for S3Error/' \
        crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'the sole S3Error bridge accepting an unresolved HandlerError' mut_s3_error_bridge_takes_handler

mut_s3_error_resource_writer() {
    perl -0pi -e 's/impl S3Error \{/impl S3Error {\n    pub fn about_resource(self, _: String) -> Self { self }/' \
        crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'S3Error regaining a post-resolution resource writer' mut_s3_error_resource_writer

mut_handler_status_authority() {
    perl -0pi -e 's/impl HandlerError \{/impl HandlerError {\n    pub fn status(\&self) -> StatusCode { StatusCode::BAD_REQUEST }/' \
        crates/core/src/handler.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerError regaining a status authority before resolution' mut_handler_status_authority

mut_stage_filter_resolves_error() {
    perl -0pi -e 's/(fn on_wire\([^\n]+Result<\(\), )HandlerError>/$1S3Error>/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_error_resolution_surface.sh \
    'a StageFilter seam returning an already-resolved S3Error' mut_stage_filter_resolves_error

mut_stage_filter_seam_removed() {
    perl -0pi -e 's/    fn on_response\([^\n]+\n        Ok\(\(\)\)\n    \}\n//' crates/gateway/src/ext/filter.rs
}
expect_fail check_error_resolution_surface.sh \
    'the closed StageFilter seam set losing its response seam' mut_stage_filter_seam_removed

mut_typed_writer_made_public() {
    perl -0pi -e 's/pub\(crate\) fn from_wire_reject/pub fn from_wire_reject/' crates/gateway/src/render.rs
}
expect_fail check_error_resolution_surface.sh \
    'a typed S3Error converter becoming public' mut_typed_writer_made_public

mut_context_carrier_bridge_removed() {
    perl -0pi -e 's/impl From<HandlerErrorContext> for HandlerError/impl From<ErrorContext> for HandlerError/' \
        crates/core/src/handler.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerError regaining an arbitrary ErrorContext carrier bridge' mut_context_carrier_bridge_removed

mut_handler_context_field_public() {
    perl -0pi -e 's/pub struct HandlerErrorContext\(ErrorContext\);/pub struct HandlerErrorContext(pub ErrorContext);/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext exposing its arbitrary ErrorContext field' mut_handler_context_field_public

mut_handler_context_generic_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub fn new(context: ErrorContext) -> Self { Self(context) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a generic ErrorContext factory' mut_handler_context_generic_factory

mut_handler_context_async_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub async fn new(context: ErrorContext) -> Self { Self(context) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining an async generic ErrorContext factory' mut_handler_context_async_factory

mut_handler_context_auth_factory() {
    perl -0pi -e 's/impl HandlerErrorContext \{/impl HandlerErrorContext {\n    pub fn authorization_scope_malformed() -> Self { Self(ErrorContext::authorization_scope_malformed()) }/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining an authorization-scope factory' mut_handler_context_auth_factory

mut_handler_context_multiline_from_impl() {
    printf '\nimpl\n    From<ErrorContext> for HandlerErrorContext {\n    fn from(context: ErrorContext) -> Self { Self(context) }\n}\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a multiline From<ErrorContext> bridge' mut_handler_context_multiline_from_impl

mut_handler_context_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen {\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n}\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a macro-generated From<ErrorContext> bridge' mut_handler_context_macro_generated_from_impl

mut_handler_context_paren_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen (\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n);\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a parenthesized macro-generated From bridge' mut_handler_context_paren_macro_generated_from_impl

mut_handler_context_bracket_macro_generated_from_impl() {
    printf '\nmacro_rules! reopen [\n    () => {\n        impl From<ErrorContext> for HandlerErrorContext {\n            fn from(context: ErrorContext) -> Self { Self(context) }\n        }\n    };\n];\nreopen!();\n' \
        >>crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'HandlerErrorContext gaining a bracketed macro-generated From bridge' mut_handler_context_bracket_macro_generated_from_impl

mut_resolver_entry_renamed() {
    perl -0pi -e 's/pub fn resolve\(context: ErrorContext, response: ResponseKind\)/pub fn resolve_unchecked(context: ErrorContext, response: ResponseKind)/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'core losing the sole public resolution entry' mut_resolver_entry_renamed

mut_resolution_source_removed() {
    rm -f crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'the required resolution source disappearing' mut_resolution_source_removed

mut_owned_bucket_context_takes_a_region() {
    perl -0pi -e 's/pub const fn owned_bucket_recreation\(\) -> Self/pub fn owned_bucket_recreation(_: RegionLabel) -> Self/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_error_resolution_surface.sh \
    'the owned-bucket refusal context regaining a region-selected success path' mut_owned_bucket_context_takes_a_region

mut_owned_bucket_success_enters_the_resolver() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/src/error_resolution.rs")
text = path.read_text()
old = '''        ErrorCase::OwnedBucketRecreation => ordinary_parts(
            ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU,
            Cow::Borrowed("Your previous request to create the named bucket succeeded and you already own it."),
            Vec::new(),
            Vec::new(),
            None,
        ),'''
new = "        ErrorCase::OwnedBucketRecreation => success(StatusCode::OK),"
if old not in text:
    raise SystemExit("owned-bucket conflict arm is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the us-east-1 owned-bucket success entering ErrorContext' mut_owned_bucket_success_enters_the_resolver

mut_core_error_trybuild_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/core/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the core error-resolution trybuild harness disabled by file-level cfg_attr' mut_core_error_trybuild_harness_disabled

mut_gateway_error_trybuild_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg(any())]\n$1/' \
        crates/gateway/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the gateway error-resolution trybuild harness disabled by file-level cfg' mut_gateway_error_trybuild_harness_disabled

mut_gateway_consolidated_harness_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/gateway/tests/integration.rs
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway harness disabled by file-level cfg_attr' mut_gateway_consolidated_harness_disabled

mut_gateway_consolidated_registration_decoys() {
    cat >>crates/gateway/tests/integration.rs <<'RSEOF'

// #[path = "compile_fail.rs"]
// mod compile_fail;
const COMPILE_FAIL_REGISTRATION_DECOY: &str = r#"#[path = "compile_fail.rs"]
mod compile_fail;"#;
RSEOF
}

probe_gateway_consolidated_registration_decoys() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && mut_gateway_consolidated_registration_decoys >/dev/null)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_error_resolution_surface.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_error_resolution_surface.sh ignores consolidated registration comment and raw-string decoys'
    else
        fail_msg 'check_error_resolution_surface.sh rejected consolidated registration comment or raw-string decoys'
    fi
}
probe_gateway_consolidated_registration_decoys

mut_gateway_trybuild_harness_split() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
call = '    cases.compile_fail("tests/trybuild/credential/*.rs");\n'
if text.count(call) != 1:
    raise SystemExit("gateway credential trybuild call is missing")
path.write_text(text.replace(call, "", 1))
Path("crates/gateway/tests/trybuild_credential.rs").write_text(
    "#[test]\n"
    "fn credential_contract() {\n"
    "    let cases = trybuild::TestCases::new();\n"
    f"{call}"
    "}\n"
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway trybuild fixtures being split across synthetic projects' mut_gateway_trybuild_harness_split

mut_gateway_extra_trybuild_harness_added() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    "#[test]\n"
    "fn extra_compile_fail_contract() {\n"
    "    let cases = trybuild::TestCases::new();\n"
    "    cases.compile_fail(\"tests/compile_fail/azc_*.rs\");\n"
    "}\n"
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'an extra gateway trybuild entry point creating a second synthetic project' mut_gateway_extra_trybuild_harness_added

mut_gateway_trybuild_harness_reused_by_path() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    '#[path = "compile_fail.rs"]\nmod duplicate;\n'
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second integration target reusing the unified trybuild harness by path' mut_gateway_trybuild_harness_reused_by_path

mut_gateway_trybuild_harness_reused_by_cfg_attr_path() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("crates/gateway/tests/extra_compile.rs").write_text(
    '#[cfg_attr(all(), path = "compile_fail.rs")]\nmod duplicate;\n'
)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second integration target reusing the unified trybuild harness through cfg_attr' mut_gateway_trybuild_harness_reused_by_cfg_attr_path

mut_gateway_lib_reuses_trybuild_harness() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/src/lib.rs")
text = path.read_text()
text += '''
#[cfg(test)]
#[path = "../tests/compile_fail.rs"]
mod duplicate_compile_fail;
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway library test target reusing the unified trybuild harness' mut_gateway_lib_reuses_trybuild_harness

mut_gateway_manifest_reuses_trybuild_harness() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
text += '''
[[example]]
name = "duplicate-compile-fail"
path = "tests/compile_fail.rs"
test = true
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a testable Cargo example reusing the unified trybuild harness' mut_gateway_manifest_reuses_trybuild_harness

mut_gateway_consolidated_harness_omits_trybuild_module() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/integration.rs")
text = path.read_text()
entry = '#[path = "compile_fail.rs"]\nmod compile_fail;\n'
if text.count(entry) != 1:
    raise SystemExit("gateway compile-fail module registration is missing")
path.write_text(text.replace(entry, "", 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target omitting its unified trybuild module' mut_gateway_consolidated_harness_omits_trybuild_module

mut_gateway_manifest_disables_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
anchor = 'path = "tests/integration.rs"\n'
if text.count(anchor) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(anchor, anchor + "test = false\n", 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target disabling its test harness' mut_gateway_manifest_disables_consolidated_target

mut_gateway_manifest_gates_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
anchor = 'path = "tests/integration.rs"\n'
if text.count(anchor) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(anchor, anchor + 'required-features = ["compat-s3s"]\n', 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target requiring a non-default feature' mut_gateway_manifest_gates_consolidated_target

mut_gateway_manifest_duplicates_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
text += '''
[[test]]
name = "duplicate_integration"
path = "tests/integration.rs"
'''
path.write_text(text)
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'a second Cargo target duplicating the consolidated gateway harness' mut_gateway_manifest_duplicates_consolidated_target

mut_gateway_manifest_redirects_consolidated_target() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
old = 'path = "tests/integration.rs"'
if text.count(old) != 1:
    raise SystemExit("gateway integration target is missing")
path.write_text(text.replace(old, 'path = "tests/facade_probe.rs"', 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the consolidated gateway target being redirected to another path' mut_gateway_manifest_redirects_consolidated_target

mut_gateway_trybuild_receiver_shadowed() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/gateway/tests/compile_fail.rs")
text = path.read_text()
old = "    let cases = trybuild::TestCases::new();\n"
new = old + "    let cases = FakeCases::new();\n"
if text.count(old) != 1:
    raise SystemExit("gateway trybuild constructor is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the gateway trybuild receiver being shadowed after construction' mut_gateway_trybuild_receiver_shadowed

mut_gateway_credential_fixture_pair_removed() {
    rm crates/gateway/tests/trybuild/credential/provider_returns_secret.rs
    rm crates/gateway/tests/trybuild/credential/provider_returns_secret.stderr
}
expect_fail check_error_resolution_surface.sh \
    'a gateway credential source and golden being removed together' mut_gateway_credential_fixture_pair_removed

mut_core_error_trybuild_call_replaced_by_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = '    cases.compile_fail("tests/compile_fail/error_resolution_*.rs");'
new = '    let _ = r#"cases.compile_fail(\\"tests/compile_fail/error_resolution_*.rs\\");"#;'
if old not in text:
    raise SystemExit("core error-resolution trybuild call is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'the core error-resolution trybuild call replaced by a string decoy' mut_core_error_trybuild_call_replaced_by_string

mut_gateway_error_trybuild_call_replaced_by_comment() {
    perl -0pi -e 's/    cases\.compile_fail\("tests\/compile_fail\/error_resolution_\*\.rs"\);/    \/\/ cases.compile_fail("tests\/compile_fail\/error_resolution_*.rs");/' \
        crates/gateway/tests/compile_fail.rs
}
expect_fail check_error_resolution_surface.sh \
    'the gateway error-resolution trybuild call replaced by a comment decoy' mut_gateway_error_trybuild_call_replaced_by_comment

mut_error_trybuild_fixture_disabled() {
    perl -0pi -e 's/^(\/\/ Copyright 2026 RustFS Team)/#![cfg_attr(all(), cfg(any()))]\n$1/' \
        crates/core/tests/compile_fail/error_resolution_context_fields.rs
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail fixture disabled by cfg_attr' mut_error_trybuild_fixture_disabled

mut_error_trybuild_fixture_replaced_by_string() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/tests/compile_fail/error_resolution_context_fields.rs")
text = path.read_text()
old = "    let ErrorContext(_case) = context;"
new = '    let _ = "let ErrorContext(_case) = context;";'
if old not in text:
    raise SystemExit("error-resolution fixture evidence is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail expression replaced by a string decoy' mut_error_trybuild_fixture_replaced_by_string

mut_error_trybuild_golden_removed() {
    rm crates/core/tests/compile_fail/error_resolution_context_fields.stderr
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail golden removed' mut_error_trybuild_golden_removed

mut_error_trybuild_golden_loses_diagnostic() {
    perl -0pi -e 's/cannot match against a tuple struct which contains private fields/forged generic diagnostic/' \
        crates/core/tests/compile_fail/error_resolution_context_fields.stderr
}
expect_fail check_error_resolution_surface.sh \
    'an error-resolution compile-fail golden losing its case-specific diagnostic' mut_error_trybuild_golden_loses_diagnostic

mut_scope_region_opened() {
    perl -0pi -e 's/pub struct ScopeRegion\(Box<str>\);/pub struct ScopeRegion(pub Box<str>);/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRegion gaining a public field' mut_scope_region_opened

mut_scope_rejection_opened() {
    perl -0pi -e 's/pub struct ScopeRejection\(Option<ScopeRegion>\);/pub struct ScopeRejection(pub Option<ScopeRegion>);/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRejection gaining a public field' mut_scope_rejection_opened

mut_scope_return_erased() {
    perl -0pi -e 's/Result<VerifiedScope, ScopeRejection>/Result<VerifiedScope, AuthError>/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'enforce_scope erasing the typed rejection' mut_scope_return_erased

mut_scope_date_carries_region() {
    perl -0pi -e 's/return Err\(ScopeRejection\(None\)\);/return Err(ScopeRejection(expected.regions().regions.first().cloned()));/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a date mismatch carrying a remediation region' mut_scope_date_carries_region

mut_scope_region_loses_remediation() {
    perl -0pi -e 's/ScopeRejection\(expected\.regions\(\)\.regions\.first\(\)\.cloned\(\)\)/ScopeRejection(None)/' \
        crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a region mismatch losing its configured remediation' mut_scope_region_loses_remediation

mut_scope_sort_removed() {
    perl -0pi -e 's/regions\.sort_by\(/regions.sort_by_key(/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured remediation order no longer using the canonical byte sort' mut_scope_sort_removed

mut_scope_dedup_removed() {
    perl -0pi -e 's/regions\.dedup\(\);/\/\/ mutation removed deduplication/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured regions no longer being deduplicated' mut_scope_dedup_removed

mut_scope_alphabet_widened() {
    perl -0pi -e 's/byte\.is_ascii_lowercase\(\)/byte.is_ascii_alphabetic()/' crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'configured regions accepting uppercase request text' mut_scope_alphabet_widened

mut_authentication_outcome_field_public() {
    perl -0pi -e 's/    scope_rejection: Option<ScopeRejection>,/    pub scope_rejection: Option<ScopeRejection>,/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the facade carrier exposing its scope proof field' mut_authentication_outcome_field_public

mut_scope_rejection_trait_bridge() {
    printf '\nimpl From<ScopeRejection> for AuthenticationOutcome {\n    fn from(rejection: ScopeRejection) -> Self { Self::scope_rejected(rejection) }\n}\n' \
        >>crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'ScopeRejection gaining a public trait bridge into AuthenticationOutcome' mut_scope_rejection_trait_bridge

mut_ordinary_outcome_gets_proof() {
    perl -0pi -e 's/scope_rejection: None,/scope_rejection: Some(todo!()),/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'an ordinary custom-authenticator outcome receiving contextual proof' mut_ordinary_outcome_gets_proof

mut_verdict_accessor_rewrites() {
    perl -0pi -e 's/        &self\.verdict\n/        todo!()\n/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the public verdict accessor no longer borrowing the stored verdict' mut_verdict_accessor_rewrites

mut_scope_verdict_replaced() {
    perl -0pi -e 's/verdict: Verdict::reject\(AuthError::AuthorizationHeaderMalformed\)/verdict: Verdict::reject(AuthError::AccessDenied)/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the private scope carrier replacing the fixed public verdict' mut_scope_verdict_replaced

mut_scope_split_public() {
    perl -0pi -e 's/pub\(crate\) fn into_parts/pub fn into_parts/' crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the contextual carrier gaining a public consuming split' mut_scope_split_public

mut_authenticator_returns_bare_verdict() {
    perl -0pi -e 's/Result<AuthenticationOutcome, Unavailable>/Result<Verdict, Unavailable>/' \
        crates/gateway/src/ext/authenticator.rs
}
expect_fail check_scope_rejection_surface.sh \
    'Authenticator returning the old bare verdict' mut_authenticator_returns_bare_verdict

mut_service_drops_scope_proof() {
    perl -0pi -e 's/scope_rejection\.and_then\(\|rejection\| rejection\.expected_region\(\)\.cloned\(\)\)/None/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the service dropping the trusted scope proof' mut_service_drops_scope_proof

mut_service_region_context_swapped() {
    perl -0pi -e 's/ErrorContext::authorization_region_mismatch\(region\)/ErrorContext::authorization_scope_malformed()/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a trusted region mismatch losing its Region detail' mut_service_region_context_swapped

mut_service_no_detail_context_swapped() {
    perl -0pi -e 's/None => ErrorContext::authorization_scope_malformed\(\)/None => ErrorContext::authorization_region_mismatch(todo!())/' \
        crates/gateway/src/service.rs
}
expect_fail check_scope_rejection_surface.sh \
    'a date or service mismatch gaining a Region detail' mut_service_no_detail_context_swapped

mut_core_scope_context_removed() {
    perl -0pi -e 's/pub const fn authorization_scope_malformed/pub const fn removed_scope_malformed/' \
        crates/core/src/error_resolution.rs
}
expect_fail check_scope_rejection_surface.sh \
    'core losing the closed no-detail scope context' mut_core_scope_context_removed

mut_scope_source_removed() {
    rm -f crates/sig/src/scope.rs
}
expect_fail check_scope_rejection_surface.sh \
    'the required typed scope source disappearing' mut_scope_source_removed

probe_error_scope_guards_without_rg() {
    local guard output rc tool_path
    local guards=(check_error_resolution_surface.sh check_scope_rejection_surface.sh)

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-error-scope-guard-path.XXXXXX")"
    ln -s "$(command -v python3)" "${tool_path}/python3"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v awk)" "${tool_path}/awk"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -eq 0 ]]; then
            pass_msg "${guard} runs without ripgrep"
        else
            fail_msg "${guard} requires ripgrep: ${output}"
        fi
    done
    rm -rf "$tool_path"
}
probe_error_scope_guards_without_rg

probe_error_scope_guards_missing_python() {
    local guard output rc tool_path
    local guards=(check_error_resolution_surface.sh check_scope_rejection_surface.sh)

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-error-scope-guard-path.XXXXXX")"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v awk)" "${tool_path}/awk"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
            pass_msg "${guard} fails closed without python3"
        else
            fail_msg "${guard} reported green without python3"
        fi
    done
    rm -rf "$tool_path"
}
probe_error_scope_guards_missing_python

mut_assembly_case_id_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/check_monomorphic_dispatch.sh")
path.write_text(path.read_text().replace("a-asm-0007", "removed-asm-0007", 1))
PYEOF
}
expect_fail check_assembly_case_coverage.sh \
    'the static-dispatch case losing its LLVM guard mapping' mut_assembly_case_id_deleted

mut_monomorphic_handler_is_indirect() {
    python3 - <<'PYEOF'
from pathlib import Path

Path("scripts/monomorphic-indirect.ll").write_text("""\
define internal void @_RNCINvMNtCstatic_dispatchStaticOperationintegration7support4Ping8dispatch7Backend() {
; <integration::support::Backend as rustfs_gateway_core::handler::Handler<integration::support::Ping>>::call
  %result = call ptr %handler()
}
; rustfs_gateway_core::static_dispatch::decode::<integration::support::Ping>
define internal void @_Rdecode() {
; <integration::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode
  call void @_Rcodec()
}
""")
PYEOF
}
expect_monomorphic_ir_fail \
    'the concrete Handler<Ping> call becoming indirect' mut_monomorphic_handler_is_indirect

# ── check_minimal_assembly_lines.sh (P7-01) ───────────────────────────────────

mut_minimal_assembly_exceeds_twenty_lines() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
text = path.read_text()
extra = "".join(f"    let _extra_{index} = {index};\n" for index in range(21))
path.write_text(text.replace("    // END MINIMAL ASSEMBLY", extra + "    // END MINIMAL ASSEMBLY", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the minimal ServiceBuilder assembly grows beyond twenty effective lines' mut_minimal_assembly_exceeds_twenty_lines

mut_minimal_assembly_marker_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/examples/minimal.rs")
path.write_text(path.read_text().replace("    // BEGIN MINIMAL ASSEMBLY\n", "", 1))
PY
}
expect_fail check_minimal_assembly_lines.sh \
    'the assembly measurement loses its opening marker' mut_minimal_assembly_marker_removed

# Exercise selective staging in a tiny repository so the control measures only index semantics.
# The Git shim records every invocation and rejects a regression to repository-wide `git add -A`.
stage_helper_contract() {
    local helper="$1" repo shim log expected real_git output rc=0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stage-helper.XXXXXX")"
    shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stage-git.XXXXXX")"
    log="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-log.XXXXXX")"
    expected="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-expected.XXXXXX")"
    real_git="$(command -v git)"
    write_stage_contract_pathspec "$expected"
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'keep\n' >modified.txt
        printf 'delete\n' >deleted.txt
        printf 'magic\n' >':(glob)decoy'
        printf 'bracket\n' >'tracked[one].txt'
        printf 'unchanged\n' >unchanged.txt
        "$real_git" add modified.txt deleted.txt unchanged.txt -- \
            ':(literal):(glob)decoy' ':(literal)tracked[one].txt'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
        printf 'changed\n' >>modified.txt
        rm deleted.txt
        printf 'changed\n' >>':(glob)decoy'
        rm 'tracked[one].txt'
        printf 'new\n' >untracked.txt
        printf 'new magic\n' >':(glob)untracked'
        printf 'new bracket\n' >'untracked[two].txt'
    )
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "CALL\0" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'printf "%s\0" "$@" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'printf "END\0" >>"$GATEWAY_STAGE_GIT_LOG"' \
        'case "${1-}" in' \
        '    add)' \
        '        [ "$#" -eq 4 ] && [ "${2-}" = -A ] && [ "${4-}" = --pathspec-file-nul ] || exit 97' \
        '        case "${3-}" in --pathspec-from-file=*) pathspec=${3#*=} ;; *) exit 97 ;; esac' \
        '        [ -n "$pathspec" ] && [ "$pathspec" != - ] || exit 97' \
        '        "$GATEWAY_STAGE_VALIDATE" "$GATEWAY_STAGE_EXPECTED" "$pathspec" || exit 97' \
        '        ;;' \
        '    diff)' \
        '        [ "$#" -eq 5 ] && [ "${2-}" = --name-only ] && [ "${3-}" = -z ] &&' \
        '            [ "${4-}" = HEAD ] && [ "${5-}" = -- ] || exit 97' \
        '        ;;' \
        '    ls-files)' \
        '        [ "$#" -eq 4 ] && [ "${2-}" = --others ] &&' \
        '            [ "${3-}" = --exclude-standard ] && [ "${4-}" = -z ] || exit 97' \
        '        ;;' \
        '    *) exit 97 ;;' \
        'esac' \
        'exec "$GATEWAY_STAGE_REAL_GIT" "$@"' >"$shim/git"
    printf '%s\n' \
        '#!/usr/bin/env python3' \
        'import pathlib' \
        'import sys' \
        '' \
        'def entries(path):' \
        '    data = pathlib.Path(path).read_bytes()' \
        '    if not data or not data.endswith(b"\0"):' \
        '        raise SystemExit(1)' \
        '    values = data[:-1].split(b"\0")' \
        '    if any(not value for value in values):' \
        '        raise SystemExit(1)' \
        '    return values' \
        '' \
        'expected = entries(sys.argv[1])' \
        'actual = entries(sys.argv[2])' \
        'if len(actual) != len(set(actual)):' \
        '    raise SystemExit(1)' \
        'if any(not value.startswith(b":(literal)") for value in actual):' \
        '    raise SystemExit(1)' \
        'if set(actual) != set(expected):' \
        '    raise SystemExit(1)' >"$shim/validate"
    chmod +x "$shim/git"
    chmod +x "$shim/validate"
    PATH="$shim:$PATH" GATEWAY_STAGE_GIT_LOG="$log" GATEWAY_STAGE_EXPECTED="$expected" \
        GATEWAY_STAGE_VALIDATE="$shim/validate" GATEWAY_STAGE_REAL_GIT="$real_git" \
        "$helper" "$repo" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        output="$(cd "$repo" && "$real_git" diff --cached --name-only -z | python3 -c 'import sys; print("\n".join(sorted(part.decode() for part in sys.stdin.buffer.read().split(b"\0") if part)))')"
        if [[ "$output" != $':(glob)decoy\n:(glob)untracked\ndeleted.txt\nmodified.txt\ntracked[one].txt\nuntracked.txt\nuntracked[two].txt' ]] ||
            ! (cd "$repo" && "$real_git" diff --quiet) ||
            [[ -n "$(cd "$repo" && "$real_git" ls-files --others --exclude-standard)" ]]; then
            rc=1
        fi
    fi
    if [[ "$rc" -eq 0 ]] && python3 - "$log" <<'PYEOF'
import pathlib
import sys

records = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
calls = []
current = None
for record in records:
    if record == b"CALL":
        if current is not None:
            raise SystemExit(1)
        current = []
    elif record == b"END":
        if current is None:
            raise SystemExit(1)
        calls.append(current)
        current = None
    elif record and current is not None:
        current.append(record)
if current is not None or not calls:
    raise SystemExit(1)
for call in calls:
    allowed_query = call in (
        [b"diff", b"--name-only", b"-z", b"HEAD", b"--"],
        [b"ls-files", b"--others", b"--exclude-standard", b"-z"],
    )
    allowed_add = (
        len(call) == 4
        and call[0] == b"add"
        and call[1] == b"-A"
        and call[2].startswith(b"--pathspec-from-file=")
        and call[3] == b"--pathspec-file-nul"
    )
    if not (allowed_query or allowed_add):
        raise SystemExit(1)
PYEOF
    then
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
        PATH="$shim:$PATH" GATEWAY_STAGE_GIT_LOG="$log" GATEWAY_STAGE_EXPECTED="$expected" \
            GATEWAY_STAGE_VALIDATE="$shim/validate" GATEWAY_STAGE_REAL_GIT="$real_git" \
            "$helper" "$repo" || rc=$?
        if [[ "$rc" -eq 0 ]] && ! (cd "$repo" && "$real_git" status --porcelain | grep -q .); then
            rc=0
        else
            rc=1
        fi
    else
        rc=1
    fi
    rm -rf "$repo" "$shim"
    rm -f "$log" "$expected"
    return "$rc"
}

write_stage_contract_pathspec() {
    printf '%s\0' \
        ':(literal):(glob)decoy' \
        ':(literal):(glob)untracked' \
        ':(literal)deleted.txt' \
        ':(literal)modified.txt' \
        ':(literal)tracked[one].txt' \
        ':(literal)untracked.txt' \
        ':(literal)untracked[two].txt' >"$1"
}

stage_mutant_adds_whole_tree() {
    (cd "$1" && git add -A)
}

stage_mutant_adds_dot() {
    (cd "$1" && git add .)
}

stage_mutant_adds_dot_with_global_directory() {
    git -C "$1" add .
}

stage_mutant_adds_whole_tree_then_targeted() {
    (cd "$1" && git add -A) || return
    stage_sandbox_changes "$1"
}

stage_mutant_adds_whole_tree_via_file() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    printf '.\0' >"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_uses_glob_via_file() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    printf ':(glob)*\0' >"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_duplicates_pathspec() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    write_stage_contract_pathspec "$pathspec"
    printf ':(literal)modified.txt\0' >>"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_adds_extra_pathspec() {
    local pathspec rc=0
    pathspec="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    write_stage_contract_pathspec "$pathspec"
    printf ':(literal)unchanged.txt\0' >>"$pathspec"
    (cd "$1" && git add -A --pathspec-from-file="$pathspec" --pathspec-file-nul) || rc=$?
    rm -f "$pathspec"
    return "$rc"
}

stage_mutant_misses_tracked() {
    local list paths
    list="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    paths="${list}.paths"
    (cd "$1" && git ls-files --others --exclude-standard -z >"$list")
    literalize_nul_paths "$list" "$paths"
    [[ ! -s "$paths" ]] ||
        (cd "$1" && git add -A --pathspec-from-file="$paths" --pathspec-file-nul)
    rm -f "$list" "$paths"
}

stage_mutant_misses_untracked() {
    local list paths
    list="$(mktemp "${TMPDIR:-/tmp}/gateway-stage-mutant.XXXXXX")"
    paths="${list}.paths"
    (cd "$1" && git diff --name-only -z HEAD -- >"$list")
    literalize_nul_paths "$list" "$paths"
    [[ ! -s "$paths" ]] ||
        (cd "$1" && git add -A --pathspec-from-file="$paths" --pathspec-file-nul)
    rm -f "$list" "$paths"
}

stage_mutant_rejects_empty() {
    stage_sandbox_changes "$1"
    [[ -n "$(cd "$1" && git status --porcelain)" ]]
}

probe_selective_staging() {
    local mutant desc
    cases=$((cases + 1))
    if stage_helper_contract stage_sandbox_changes; then
        pass_msg 'selective staging covers modified, deleted, untracked and empty mutations'
    else
        fail_msg 'selective staging lost a changed path or scanned the whole repository'
    fi
    while IFS='|' read -r mutant desc; do
        cases=$((cases + 1))
        if stage_helper_contract "$mutant"; then
            fail_msg "selective staging accepted its mutation: ${desc}"
        else
            pass_msg "selective staging catches its own mutation: ${desc}"
        fi
    done <<'EOF'
stage_mutant_adds_whole_tree|repository-wide git add restored
stage_mutant_adds_dot|repository-wide git add dot restored
stage_mutant_adds_dot_with_global_directory|repository-wide git add dot hidden after a global directory argument
stage_mutant_adds_whole_tree_then_targeted|repository-wide git add hidden before targeted staging
stage_mutant_adds_whole_tree_via_file|repository-wide dot path hidden in a pathspec file
stage_mutant_uses_glob_via_file|repository-wide glob hidden in a pathspec file
stage_mutant_duplicates_pathspec|a duplicate literal path hidden in a pathspec file
stage_mutant_adds_extra_pathspec|an unchanged extra path hidden in a pathspec file
stage_mutant_misses_tracked|tracked modifications and deletions omitted
stage_mutant_misses_untracked|untracked additions omitted
stage_mutant_rejects_empty|an empty mutation reported as failure
EOF
}
probe_selective_staging

reset_helper_contract() {
    local helper="$1" repo real_git rc=0
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-helper.XXXXXX")"
    real_git="$(command -v git)"
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'magic baseline\n' >':(glob)decoy'
        printf 'bracket baseline\n' >'tracked[one].txt'
        "$real_git" add -- ':(literal):(glob)decoy' ':(literal)tracked[one].txt'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
        printf 'changed\n' >>':(glob)decoy'
        rm 'tracked[one].txt'
        printf 'untracked magic\n' >':(glob)untracked'
        printf 'untracked bracket\n' >'untracked[two].txt'
        "$real_git" add -- ':(literal):(glob)decoy' ':(literal)untracked[two].txt'
    )
    "$helper" "$repo" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]] &&
        [[ "$(cd "$repo" && "$real_git" status --porcelain)" == "" ]] &&
        [[ "$(<"$repo/:(glob)decoy")" == 'magic baseline' ]] &&
        [[ "$(<"$repo/tracked[one].txt")" == 'bracket baseline' ]] &&
        [[ ! -e "$repo/:(glob)untracked" ]] &&
        [[ ! -e "$repo/untracked[two].txt" ]]; then
        rc=0
    else
        rc=1
    fi
    rm -rf "$repo"
    return "$rc"
}

reset_mutant_uses_raw_pathspecs() {
    local repo="$1" changed untracked
    changed="$(mktemp "${TMPDIR:-/tmp}/gateway-reset-mutant.XXXXXX")"
    untracked="${changed}.untracked"
    (
        cd "$repo"
        git diff --name-only -z HEAD -- >"$changed"
        [[ ! -s "$changed" ]] || xargs -0 git reset -q HEAD -- <"$changed"
        git ls-files --others --exclude-standard -z >"$untracked"
        [[ ! -s "$untracked" ]] || xargs -0 git clean -fdq -- <"$untracked"
        git diff --name-only -z HEAD -- >"$changed"
        [[ ! -s "$changed" ]] || xargs -0 git checkout -f HEAD -- <"$changed"
    )
    local rc=$?
    rm -f "$changed" "$untracked"
    return "$rc"
}

probe_literal_reset_paths() {
    cases=$((cases + 1))
    if reset_helper_contract reset_sandbox_changes; then
        pass_msg 'selective reset treats glob-like and bracket paths literally'
    else
        fail_msg 'selective reset lost a literal tracked or untracked path'
    fi
    cases=$((cases + 1))
    if reset_helper_contract reset_mutant_uses_raw_pathspecs; then
        fail_msg 'selective reset accepted raw Git pathspec magic'
    else
        pass_msg 'selective reset catches its own mutation: raw Git pathspec magic restored'
    fi
}
probe_literal_reset_paths

# Prove that a successful stage publishes the exact literal path sets for one reset, that the
# reset consumes them without rescanning the repository, and that failure/empty/fallback paths do
# not leak state into the next case.
probe_cached_sandbox_reset() {
    local repo shim log real_git rc=0
    cases=$((cases + 1))
    repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-cache.XXXXXX")"
    shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-cache-git.XXXXXX")"
    log="$(mktemp "${TMPDIR:-/tmp}/gateway-reset-cache-log.XXXXXX")"
    real_git="$(command -v git)"
    SANDBOX="$repo"
    SANDBOX_RESET_TRACKED="${repo}.tracked"
    SANDBOX_RESET_UNTRACKED="${repo}.untracked"
    SANDBOX_RESET_READY=0
    (
        cd "$repo"
        "$real_git" init -q .
        printf 'modified baseline\n' >modified.txt
        printf 'deleted baseline\n' >deleted.txt
        printf 'magic baseline\n' >':(glob)tracked'
        printf 'fallback baseline\n' >fallback.txt
        "$real_git" add -- modified.txt deleted.txt fallback.txt ':(literal):(glob)tracked'
        "$real_git" -c user.name=t -c user.email=t@t commit -qm base
    )
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "%s\n" "${1-}" >>"$GATEWAY_RESET_CACHE_LOG"' \
        'if [ "${GATEWAY_RESET_FAIL_ADD-0}" -eq 1 ] && [ "${1-}" = add ]; then exit 71; fi' \
        'exec "$GATEWAY_RESET_REAL_GIT" "$@"' >"$shim/git"
    chmod +x "$shim/git"

    (
        cd "$repo"
        printf 'changed\n' >>modified.txt
        rm deleted.txt
        printf 'changed\n' >>':(glob)tracked'
        printf 'untracked magic\n' >':(glob)untracked'
        printf 'untracked bracket\n' >'untracked[one].txt'
    )
    PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
        stage_sandbox_changes "$repo" || rc=$?
    : >"$log"
    if [[ "$rc" -eq 0 ]]; then
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
    fi
    if [[ "$rc" -eq 0 ]] &&
        grep -Eq '^(diff|ls-files)$' "$log"; then
        rc=1
    fi
    if [[ "$rc" -eq 0 ]] && ! (
        cd "$repo"
        [[ -z "$("$real_git" status --porcelain)" ]] &&
            [[ "$(<modified.txt)" == 'modified baseline' ]] &&
            [[ "$(<deleted.txt)" == 'deleted baseline' ]] &&
            [[ "$(<':(glob)tracked')" == 'magic baseline' ]] &&
            [[ ! -e ':(glob)untracked' ]] &&
            [[ ! -e 'untracked[one].txt' ]]
    ); then
        rc=1
    fi
    if [[ "$rc" -eq 0 && "$SANDBOX_RESET_READY" -ne 0 ]]; then
        rc=1
    fi

    # An unstaged special probe has no cache and must take the explicit scan fallback once.
    if [[ "$rc" -eq 0 ]]; then
        printf 'fallback change\n' >>"$repo/fallback.txt"
        printf 'fallback untracked\n' >"$repo/fallback-new.txt"
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
        if ! grep -qx diff "$log" || ! grep -qx ls-files "$log" ||
            [[ -n "$(cd "$repo" && "$real_git" status --porcelain)" ]]; then
            rc=1
        fi
    fi

    # Empty staging still publishes a consumable empty set, avoiding a scan on the next reset.
    if [[ "$rc" -eq 0 ]]; then
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            stage_sandbox_changes "$repo" || rc=$?
        : >"$log"
        PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" GATEWAY_RESET_REAL_GIT="$real_git" \
            reset_sandbox_changes "$repo" || rc=$?
        if grep -Eq '^(diff|ls-files)$' "$log"; then
            rc=1
        fi
    fi

    # A failed stage must not publish a cache for a later case.
    if [[ "$rc" -eq 0 ]]; then
        printf 'failed stage\n' >>"$repo/modified.txt"
        GATEWAY_RESET_FAIL_ADD=1 PATH="$shim:$PATH" GATEWAY_RESET_CACHE_LOG="$log" \
            GATEWAY_RESET_REAL_GIT="$real_git" stage_sandbox_changes "$repo" >/dev/null 2>&1 && rc=1
        if [[ "$SANDBOX_RESET_READY" -ne 0 ]]; then
            rc=1
        fi
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
    fi

    rm -rf "$repo" "$shim"
    rm -f "$log" "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    SANDBOX=""
    SANDBOX_RESET_TRACKED=""
    SANDBOX_RESET_UNTRACKED=""
    SANDBOX_RESET_READY=0
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'cached sandbox reset consumes exact literal paths once and keeps fallback isolated'
    else
        fail_msg 'cached sandbox reset rescanned, leaked, or lost a modified/deleted/untracked path'
    fi
}
probe_cached_sandbox_reset

probe_cached_reset_failures() {
    local command repo shim marker real_git helper_rc
    for command in reset clean checkout; do
        cases=$((cases + 1))
        repo="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-failure.XXXXXX")"
        shim="$(mktemp -d "${TMPDIR:-/tmp}/gateway-reset-failure-git.XXXXXX")"
        marker="${repo}.failed"
        real_git="$(command -v git)"
        SANDBOX="$repo"
        SANDBOX_RESET_TRACKED="${repo}.tracked"
        SANDBOX_RESET_UNTRACKED="${repo}.untracked"
        SANDBOX_RESET_READY=0
        (
            cd "$repo"
            "$real_git" init -q .
            printf 'baseline\n' >tracked.txt
            "$real_git" add tracked.txt
            "$real_git" -c user.name=t -c user.email=t@t commit -qm base
            printf 'changed\n' >>tracked.txt
            printf 'untracked\n' >untracked.txt
        )
        printf '%s\n' \
            '#!/bin/sh' \
            'if [ "${1-}" = "$GATEWAY_RESET_FAIL_COMMAND" ] && [ ! -e "$GATEWAY_RESET_FAIL_MARKER" ]; then' \
            '    : >"$GATEWAY_RESET_FAIL_MARKER"' \
            '    exit 72' \
            'fi' \
            'exec "$GATEWAY_RESET_REAL_GIT" "$@"' >"$shim/git"
        chmod +x "$shim/git"
        stage_sandbox_changes "$repo"
        helper_rc=0
        GATEWAY_RESET_FAIL_COMMAND="$command" GATEWAY_RESET_FAIL_MARKER="$marker" \
            GATEWAY_RESET_REAL_GIT="$real_git" PATH="$shim:$PATH" \
            reset_sandbox_changes "$repo" >/dev/null 2>&1 || helper_rc=$?
        if [[ "$helper_rc" -ne 0 && "$SANDBOX_RESET_READY" -eq 0 &&
            ! -s "$SANDBOX_RESET_TRACKED" && ! -s "$SANDBOX_RESET_UNTRACKED" ]]; then
            pass_msg "cached sandbox reset fails closed when git ${command} fails"
        else
            fail_msg "cached sandbox reset swallowed a git ${command} failure or leaked its cache"
        fi
        (cd "$repo" && "$real_git" reset -q --hard HEAD && "$real_git" clean -fdq)
        rm -rf "$repo" "$shim"
        rm -f "$marker" "$SANDBOX_RESET_TRACKED" "$SANDBOX_RESET_UNTRACKED"
    done
    SANDBOX=""
    SANDBOX_RESET_TRACKED=""
    SANDBOX_RESET_UNTRACKED=""
    SANDBOX_RESET_READY=0
}
probe_cached_reset_failures

# Prove the selective reset itself before relying on it for the remaining cases. The probe dirties
# the index, a tracked file and an untracked file, then asks the next sandbox acquisition for the
# same clean baseline every guard case expects.
probe_selective_reset() {
    local sandbox
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (
        cd "$sandbox"
        printf '\n# reset probe\n' >>Cargo.toml
        printf 'probe\n' >reset-probe.txt
    )
    stage_sandbox_changes "$sandbox" >/dev/null 2>&1
    make_sandbox
    if (
        cd "$sandbox"
        git diff --quiet HEAD -- &&
            git diff --cached --quiet HEAD -- &&
            [[ -z "$(git ls-files --others --exclude-standard)" ]]
    ); then
        pass_msg 'selective sandbox reset restores the tracked, staged and untracked baseline'
    else
        fail_msg 'selective sandbox reset left state from the preceding mutation'
    fi
}
probe_selective_reset

mut_reverse_edge() {
    printf 'rustfs-gateway-types = { workspace = true }\n' >>crates/xml/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'reverse edge rustfs-gateway-xml -> rustfs-gateway-types' mut_reverse_edge

mut_conformance_internal() {
    printf 'rustfs-gateway-core = { workspace = true }\n' >>crates/conformance/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'conformance reaching past the facade into rustfs-gateway-core' mut_conformance_internal

mut_unregistered_crate() {
    mkdir -p crates/newthing
    printf '[package]\nname = "rustfs-gateway-newthing"\n\n[dependencies]\n' >crates/newthing/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'a new crate that is not registered in the allow matrix' mut_unregistered_crate

mut_xtask_dispatch_layer_registration_deleted() {
    sed '/    "rustfs-gateway-xtask-dispatch|"/d' scripts/check_layer_dependencies.sh \
        >scripts/check_layer_dependencies.sh.mut
    mv scripts/check_layer_dependencies.sh.mut scripts/check_layer_dependencies.sh
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the std-only xtask dispatcher losing its pre-registered layer row' \
    mut_xtask_dispatch_layer_registration_deleted

mut_xtask_dispatch_layer_allows_dependency() {
    perl -0pi -e 's/rustfs-gateway-xtask-dispatch\|"/rustfs-gateway-xtask-dispatch|rustfs-gateway-model"/' \
        scripts/check_layer_dependencies.sh
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the std-only xtask dispatcher layer row allowing a dependency' \
    mut_xtask_dispatch_layer_allows_dependency

mut_xtask_dispatch_audit_exits_without_output() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("scripts/check_layer_dependencies.sh")
text = path.read_text()
old = "raise SystemExit(bool(errors))"
if text.count(old) != 1:
    raise SystemExit("dispatcher audit exit mutation subject is not exact")
path.write_text(text.replace(old, "raise SystemExit(1)", 1))
PYEOF
}
expect_fail_self_mutation check_layer_dependencies.sh \
    'the structured dispatcher audit failing without diagnostic output' \
    mut_xtask_dispatch_audit_exits_without_output

mut_xtask_dispatch_agents_registration_deleted() {
    sed '/rustfs-gateway-xtask-dispatch.*std-only cargo xtask process selection/d' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_layer_dependencies.sh \
    'the std-only xtask dispatcher leaving the AGENTS dependency graph' \
    mut_xtask_dispatch_agents_registration_deleted

write_future_xtask_dispatch_manifest() {
    mkdir -p crates/xtask-dispatch
    cat >crates/xtask-dispatch/Cargo.toml <<'TOMLEOF'
[package]
name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"

[package.metadata.gateway]
ring = 0
TOMLEOF
}

probe_xtask_dispatch_manifest_without_dependencies() {
    local sandbox layer_rc=0 ring_rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    (cd "$sandbox" && write_future_xtask_dispatch_manifest)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_layer_dependencies.sh" >/dev/null 2>&1 || layer_rc=$?
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_ring_boundaries.sh" >/dev/null 2>&1 || ring_rc=$?
    if [[ "$layer_rc" -eq 0 && "$ring_rc" -eq 0 ]]; then
        pass_msg 'layer and ring guards accept the canonical std-only dispatcher manifest'
    else
        fail_msg 'a dependency guard rejected the canonical std-only dispatcher manifest'
    fi
}
probe_xtask_dispatch_manifest_without_dependencies

probe_xtask_dispatch_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-dispatch-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_layer_dependencies.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_layer_dependencies.sh fails closed without python3'
    else
        fail_msg 'check_layer_dependencies.sh reported green without python3'
    fi
}
probe_xtask_dispatch_guard_missing_python

mut_xtask_dispatch_normal_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a normal dependency' \
    mut_xtask_dispatch_normal_dependency

mut_xtask_dispatch_target_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[target.'\''cfg(unix)'\''.dependencies]\nserde = "1"\n' \
        >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a target dependency' \
    mut_xtask_dispatch_target_dependency

mut_xtask_dispatch_dev_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dev-dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a dev dependency' \
    mut_xtask_dispatch_dev_dependency

mut_xtask_dispatch_build_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[build-dependencies]\nserde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the std-only dispatcher declaring a build dependency' \
    mut_xtask_dispatch_build_dependency

mut_xtask_dispatch_wrong_manifest_path() {
    mkdir -p tools/dispatcher-shadow
    cat >tools/dispatcher-shadow/Cargo.toml <<'TOMLEOF'
[package]
name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"
TOMLEOF
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher package appearing outside its canonical manifest path' \
    mut_xtask_dispatch_wrong_manifest_path

mut_xtask_dispatch_indented_dependency() {
    write_future_xtask_dispatch_manifest
    printf '\n[dependencies]\n    serde = "1"\n' >>crates/xtask-dispatch/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher hiding an indented normal dependency' \
    mut_xtask_dispatch_indented_dependency

mut_xtask_dispatch_indented_wrong_manifest_name() {
    mkdir -p tools/dispatcher-shadow
    cat >tools/dispatcher-shadow/Cargo.toml <<'TOMLEOF'
[package]
    name = "rustfs-gateway-xtask-dispatch"
version = "0.1.1"
edition = "2024"
TOMLEOF
}
expect_fail check_layer_dependencies.sh \
    'the dispatcher hiding an indented package name outside its canonical path' \
    mut_xtask_dispatch_indented_wrong_manifest_name

mut_stream_unapproved_external_dependency() {
    printf '\nserde = "1"\n' >>crates/stream/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'the stream kernel adding an external dependency outside its whitelist' \
    mut_stream_unapproved_external_dependency

mut_stream_shared_trailer_slot() {
    printf '\nstruct SharedTrailers(std::sync::Mutex<Option<crate::TrailingHeaders>>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared mutable slot' mut_stream_shared_trailer_slot

mut_stream_rwlock_trailer_slot() {
    printf '\nstruct SharedTrailers(std::sync::RwLock<Option<crate::TrailingHeaders>>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared rwlock slot' mut_stream_rwlock_trailer_slot

mut_stream_once_cell_trailers() {
    printf '\nstruct SharedTrailers(std::cell::OnceCell<crate::TrailingHeaders>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-cell slot' mut_stream_once_cell_trailers

mut_stream_once_lock_trailers() {
    printf '\nstruct SharedTrailers(std::sync::OnceLock<crate::TrailingHeaders>);\n' \
        >>crates/stream/src/trailers.rs
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-lock slot' mut_stream_once_lock_trailers

mut_stream_aliased_shared_trailer_slot() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(std::sync::Mutex<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a shared slot hidden behind an alias' \
    mut_stream_aliased_shared_trailer_slot

mut_stream_transitively_aliased_once_lock() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type TrailerMap = crate::TrailingHeaders;
type TrailerMapAlias = TrailerMap;
struct SharedTrailers(std::sync::OnceLock<TrailerMapAlias>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning to a once-lock hidden behind transitive aliases' \
    mut_stream_transitively_aliased_once_lock

mut_stream_generic_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T> = std::sync::Mutex<T>;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a generic lock alias' \
    mut_stream_generic_wrapper_alias

mut_stream_defaulted_generic_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T = ()> = std::sync::Mutex<T>;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a defaulted generic lock alias' \
    mut_stream_defaulted_generic_wrapper_alias

mut_stream_extra_defaulted_wrapper_parameter() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

type Lock<T, Marker = ()> = std::sync::Mutex<T>;
struct SharedTrailers(Lock<Option<crate::TrailingHeaders>>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through a lock alias with an extra defaulted parameter' \
    mut_stream_extra_defaulted_wrapper_parameter

mut_stream_imported_wrapper_alias() {
    cat >>crates/stream/src/trailers.rs <<'RUST'

use std::sync::Mutex as Lock;
type SharedTrailerSlot = Option<crate::TrailingHeaders>;
struct SharedTrailers(Lock<SharedTrailerSlot>);
RUST
}
expect_fail check_no_shared_trailers.sh \
    'stream trailers returning through an imported lock alias' \
    mut_stream_imported_wrapper_alias

mut_stream_as_any_escape_hatch() {
    printf '\ntrait EscapeHatch { fn as_any(&self) -> &dyn std::any::Any; }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload exposing an as_any escape hatch' mut_stream_as_any_escape_hatch

mut_stream_downcast_ref_escape_hatch() {
    printf '\nfn escape(value: &dyn std::any::Any) { let _ = value.downcast_ref::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using downcast_ref for negotiation' mut_stream_downcast_ref_escape_hatch

mut_stream_downcast_mut_escape_hatch() {
    printf '\nfn escape(value: &mut dyn std::any::Any) { let _ = value.downcast_mut::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using downcast_mut for negotiation' mut_stream_downcast_mut_escape_hatch

mut_stream_generic_downcast_escape_hatch() {
    printf '\nfn escape(value: Box<dyn std::any::Any>) { let _ = value.downcast::<u8>(); }\n' \
        >>crates/stream/src/payload.rs
}
expect_fail check_no_as_any.sh \
    'stream payload using owned Any downcast for negotiation' mut_stream_generic_downcast_escape_hatch

mut_stream_protocol_vocabulary() {
    printf '\n// Checksum belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'protocol vocabulary entering the stream kernel' mut_stream_protocol_vocabulary

mut_stream_etag_vocabulary() {
    printf '\n// ETag belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'ETag vocabulary entering the stream kernel' mut_stream_etag_vocabulary

mut_stream_bucket_vocabulary() {
    printf '\n// Bucket belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'bucket vocabulary entering the stream kernel' mut_stream_bucket_vocabulary

mut_stream_multipart_vocabulary() {
    printf '\n// Multipart belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'multipart vocabulary entering the stream kernel' mut_stream_multipart_vocabulary

mut_stream_object_key_vocabulary() {
    printf '\n// ObjectKey belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'object-key vocabulary entering the stream kernel' mut_stream_object_key_vocabulary

mut_stream_hyphenated_object_key_vocabulary() {
    printf '\n// Object-key belongs above the stream kernel.\n' >>crates/stream/src/stream.rs
}
expect_fail check_stream_vocabulary.sh \
    'hyphenated object-key vocabulary entering the stream kernel' mut_stream_hyphenated_object_key_vocabulary

probe_stream_vocabulary_allows_plain_object() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n// A trait object is ordinary stream-kernel vocabulary.\n' >>"${sandbox}/crates/stream/src/stream.rs"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_stream_vocabulary.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_stream_vocabulary.sh permits ordinary object vocabulary'
    else
        fail_msg 'check_stream_vocabulary.sh overfits ordinary object vocabulary'
    fi
}
probe_stream_vocabulary_allows_plain_object

probe_pipeline_borrowed_view_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    cat >>"${sandbox}/crates/stream/src/read.rs" <<'RUST'

pub struct BorrowedView<'a>(&'a [u8]);
RUST
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_pipeline_stage_shape.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_pipeline_stage_shape.sh permits a non-stage borrowed view'
    else
        fail_msg 'check_pipeline_stage_shape.sh rejects a non-stage borrowed view'
    fi
}
probe_pipeline_borrowed_view_allowed

mut_pipeline_new_stage_has_lifetime() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
path.write_text(path.read_text() + """
pub(crate) struct BorrowedStage<'a>(&'a [u8]);
impl RequestConfig<InputAuthorized> {
    pub(crate) fn borrowed<'a>(self) -> RequestConfig<BorrowedStage<'a>> { self.advance() }
}
""")
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a newly added real request stage carrying a lifetime' mut_pipeline_new_stage_has_lifetime

probe_pipeline_non_unit_stage_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    GATEWAY_SANDBOX="$sandbox" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["GATEWAY_SANDBOX"]) / "crates/gateway/src/request_config.rs"
text = path.read_text().replace(
    "pub(crate) struct Entered;",
    "pub(crate) struct Entered { marker: core::marker::PhantomData<()> }",
    1,
)
path.write_text(text)
PY
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_pipeline_stage_shape.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_pipeline_stage_shape.sh permits a non-unit stage'
    else
        fail_msg 'check_pipeline_stage_shape.sh requires unit stage markers'
    fi
}
probe_pipeline_non_unit_stage_allowed

probe_pipeline_multiple_roots_allowed() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    GATEWAY_SANDBOX="$sandbox" python3 - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["GATEWAY_SANDBOX"]) / "crates/gateway/src/request_config.rs"
path.write_text(path.read_text() + """
pub(crate) struct Alternative;
impl RequestConfig<Alternative> {
    pub(crate) fn input_authorized(self) -> RequestConfig<InputAuthorized> { self.advance() }
}
""")
PY
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_pipeline_stage_shape.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_pipeline_stage_shape.sh permits multiple transition roots'
    else
        fail_msg 'check_pipeline_stage_shape.sh requires one exact transition chain'
    fi
}
probe_pipeline_multiple_roots_allowed

mut_pipeline_stage_borrows_request() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "pub(crate) struct RequestConfig<'a, S> {\n    wire: &'a rustfs_gateway_http::OwnedWireRequest,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier borrowing its wire request' mut_pipeline_stage_borrows_request

mut_pipeline_stage_uses_borrowed_alias() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "type BorrowedWire<'a> = &'a rustfs_gateway_http::OwnedWireRequest;\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire<'static>,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind a type alias' \
    mut_pipeline_stage_uses_borrowed_alias

mut_pipeline_stage_uses_borrowed_newtype() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "struct BorrowedWire(&'static rustfs_gateway_http::OwnedWireRequest);\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind a newtype' \
    mut_pipeline_stage_uses_borrowed_newtype

mut_pipeline_stage_uses_borrowed_enum() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct RequestConfig<S> {",
    "enum BorrowedWire { Value(&'static rustfs_gateway_http::OwnedWireRequest) }\n"
    "pub(crate) struct RequestConfig<S> {\n    wire: BorrowedWire,",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'the request stage carrier hiding a borrowed wire behind an enum variant' \
    mut_pipeline_stage_uses_borrowed_enum

mut_pipeline_stage_marker_has_lifetime() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/gateway/src/request_config.rs")
text = path.read_text().replace(
    "pub(crate) struct Entered;",
    "pub(crate) struct Entered<'a>;",
    1,
)
path.write_text(text)
PY
}
expect_fail check_pipeline_stage_shape.sh \
    'a request stage marker carrying a lifetime' mut_pipeline_stage_marker_has_lifetime

probe_stream_guards_fail_closed() {
    local guard output rc tool_path empty_root
    local guards=(
        check_no_shared_trailers.sh
        check_no_as_any.sh
        check_stream_vocabulary.sh
        check_pipeline_stage_shape.sh
    )

    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stream-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        rc=0
        output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
            "${SCRIPT_DIR}/${guard}" 2>&1)" || rc=$?
        if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
            pass_msg "${guard} fails closed without python3"
        else
            fail_msg "${guard} reported green without python3"
        fi
    done
    rm -rf "$tool_path"

    empty_root="$(mktemp -d "${TMPDIR:-/tmp}/gateway-stream-guard-empty.XXXXXX")"
    for guard in "${guards[@]}"; do
        cases=$((cases + 1))
        rc=0
        GATEWAY_CHECK_ROOT="$empty_root" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            pass_msg "${guard} fails closed without its required source"
        else
            fail_msg "${guard} reported green without its required source"
        fi
    done
    rm -rf "$empty_root"
}
probe_stream_guards_fail_closed
mut_smithy_timestamp_digest_byte() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/types/tests/data/date_time_format_test_suite.json")
text = path.read_text()
old = '"smithy_format_value": "0001-01-25T11:23:19.123456Z"'
new = '"smithy_format_value": "0001-01-25T11:23:19.123457Z"'
if old not in text:
    raise SystemExit("expected Smithy timestamp vector is missing")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'one vendored corpus byte changing its pinned digest' mut_smithy_timestamp_digest_byte

mut_smithy_timestamp_case_count() {
    python3 - <<'PY'
import hashlib
import json
from pathlib import Path

corpus_path = Path("crates/types/tests/data/date_time_format_test_suite.json")
suite = json.loads(corpus_path.read_text())
suite["parse_http_date"].pop()
corpus_path.write_text(json.dumps(suite, indent=2) + "\n")
corpus = corpus_path.read_bytes()

guard_path = Path("scripts/check_smithy_timestamp_corpus.sh")
guard = guard_path.read_text()
guard = guard.replace("expected_bytes = 152_448", f"expected_bytes = {len(corpus)}", 1)
guard = guard.replace(
    'expected_sha256 = "95adad86782f37c5eff4601cccaeb76b5ef827121ad7b2f7030224d231a746bd"',
    f'expected_sha256 = "{hashlib.sha256(corpus).hexdigest()}"',
    1,
)
guard_path.write_text(guard)
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'one section dropping a vector even after refreshing the byte pin' mut_smithy_timestamp_case_count

mut_smithy_timestamp_notice_commit() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("2744eb413935073aa43800e58e36268cd90b3a83", "0" * 40, 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the legal notice losing the pinned source commit' mut_smithy_timestamp_notice_commit

mut_smithy_timestamp_mapping() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/types/tests/data/README.md")
text = path.read_text()
date_time = "| `date-time` | `TimestampFormat::Iso8601` |"
epoch_seconds = "| `epoch-seconds` | `TimestampFormat::EpochSeconds` |"
if date_time not in text or epoch_seconds not in text:
    raise SystemExit("expected timestamp mapping rows are missing")
text = text.replace(date_time, "__DATE_TIME_ROW__", 1)
text = text.replace(epoch_seconds, "| `epoch-seconds` | `TimestampFormat::Iso8601` |", 1)
path.write_text(text.replace("__DATE_TIME_ROW__", "| `date-time` | `TimestampFormat::EpochSeconds` |", 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the upstream-to-gateway format mapping changing' mut_smithy_timestamp_mapping

mut_smithy_timestamp_third_party_license() {
    python3 - <<'PY'
from pathlib import Path

path = Path("THIRD-PARTY-NOTICES.md")
text = path.read_text()
old = "Apache License 2.0. The exact source revision and digest"
if old not in text:
    raise SystemExit("expected Smithy third-party license attribution is missing")
path.write_text(text.replace(old, "the upstream license. The exact source revision and digest", 1))
PY
}
expect_fail check_smithy_timestamp_corpus.sh \
    'the third-party summary losing the Smithy license' mut_smithy_timestamp_third_party_license

probe_smithy_timestamp_guard_missing_python() {
    local output rc=0 tool_path
    cases=$((cases + 1))
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-smithy-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    output="$(GATEWAY_CHECK_ROOT="$REPO_ROOT" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_smithy_timestamp_corpus.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: python3'* ]]; then
        pass_msg 'check_smithy_timestamp_corpus.sh fails closed without python3'
    else
        fail_msg 'check_smithy_timestamp_corpus.sh reported green without python3'
    fi
}
probe_smithy_timestamp_guard_missing_python

mut_rust_toolchain_moving_channel() {
    python3 - <<'PY'
from pathlib import Path

path = Path("rust-toolchain.toml")
path.write_text(path.read_text().replace('channel = "1.97.1"', 'channel = "stable"', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the development compiler becoming a moving stable channel' mut_rust_toolchain_moving_channel

mut_rust_toolchain_cargo_floor_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("Cargo.toml")
path.write_text(path.read_text().replace('rust-version = "1.97.1"', 'rust-version = "1.97.2"', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the Cargo compiler floor drifting from the pinned toolchain' mut_rust_toolchain_cargo_floor_drift

mut_rust_toolchain_component_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("rust-toolchain.toml")
path.write_text(path.read_text().replace(', "rust-analyzer"', '', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'one required development component disappearing' mut_rust_toolchain_component_removed

mut_rust_toolchain_readme_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
path.write_text(path.read_text().replace('**Development toolchain: 1.97.1**', '**Development toolchain: stable**', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the README claiming a different development compiler' mut_rust_toolchain_readme_drift

mut_rust_toolchain_msrv_doc_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path("docs/msrv.md")
path.write_text(path.read_text().replace('**MSRV = 1.97.1**', '**MSRV = 1.97.0**', 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV policy naming a different compiler floor' mut_rust_toolchain_msrv_doc_drift

mut_rust_toolchain_ci_version_drift() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end].replace("toolchain: 1.97.1", "toolchain: stable", 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV CI job installing a moving compiler' mut_rust_toolchain_ci_version_drift

mut_rust_toolchain_ci_workspace_check_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
path.write_text(path.read_text().replace("cargo check --workspace --all-targets", "cargo check -p xtask", 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV CI job no longer compiling the whole workspace' mut_rust_toolchain_ci_workspace_check_removed

mut_rust_toolchain_ci_job_disabled() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end]
anchor = "    runs-on: ubuntu-latest\n"
if block.count(anchor) != 1:
    raise SystemExit("MSRV job runner is missing or ambiguous")
block = block.replace(anchor, anchor + "    if: false\n", 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the entire MSRV CI job being disabled with a boolean if' mut_rust_toolchain_ci_job_disabled

mut_rust_toolchain_ci_check_allowed_to_fail() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = "      - run: cargo check --workspace --all-targets\n"
new = old + '        continue-on-error: "true"\n'
if text.count(old) != 1:
    raise SystemExit("MSRV workspace check step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'the MSRV workspace check being allowed to fail with a string boolean' mut_rust_toolchain_ci_check_allowed_to_fail

mut_rust_toolchain_ci_job_disabled_with_quoted_key() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  msrv:")
end = text.index("\n  clippy:", start)
block = text[start:end]
anchor = "    runs-on: ubuntu-latest\n"
if block.count(anchor) != 1:
    raise SystemExit("MSRV job runner is missing or ambiguous")
block = block.replace(anchor, anchor + '    "if": false\n', 1)
path.write_text(text[:start] + block + text[end:])
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a double-quoted YAML key disabling the entire MSRV job' mut_rust_toolchain_ci_job_disabled_with_quoted_key

mut_rust_toolchain_ci_check_allowed_to_fail_with_quoted_key() {
    python3 - <<'PY'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
old = "      - run: cargo check --workspace --all-targets\n"
new = old + "        'continue-on-error': true\n"
if text.count(old) != 1:
    raise SystemExit("MSRV workspace check step is missing or ambiguous")
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_rust_toolchain_msrv.sh \
    'a single-quoted YAML key allowing the MSRV check to fail' mut_rust_toolchain_ci_check_allowed_to_fail_with_quoted_key

mut_governance_relationship_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
path.write_text(text.replace("repository is not a fork", "repository has a separate history", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the README no longer saying this repository is not a fork' mut_governance_relationship_removed

mut_governance_relationship_hidden_in_comment() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n<!-- repository is not a fork -->",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in an HTML comment' mut_governance_relationship_hidden_in_comment

mut_governance_relationship_hidden_in_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n```text\nrepository is not a fork\n```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a fenced block' mut_governance_relationship_hidden_in_fence

mut_governance_relationship_hidden_in_blockquote_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n> ```text\n> repository is not a fork\n> ```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a blockquote fenced block' mut_governance_relationship_hidden_in_blockquote_fence

mut_governance_relationship_hidden_in_list_fence() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n- ```text\n  repository is not a fork\n  ```",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in a list fenced block' mut_governance_relationship_hidden_in_list_fence

mut_governance_relationship_hidden_in_space_indented_code() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n    repository is not a fork",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in four-space indented code' mut_governance_relationship_hidden_in_space_indented_code

mut_governance_relationship_hidden_in_tab_indented_code() {
    python3 - <<'PY'
from pathlib import Path

path = Path("README.md")
text = path.read_text()
text = text.replace("repository is not a fork", "repository has a separate history", 1)
text = text.replace(
    "## Relationship to s3s\n",
    "## Relationship to s3s\n\n\trepository is not a fork",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the README relationship surviving only in tab-indented code' mut_governance_relationship_hidden_in_tab_indented_code

mut_governance_notice_revision_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("2880e0785db4cf2ceb086cfeba86a4cbdeb14176", "0" * 40, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the aws-sigv4 NOTICE revision drifting from its source snapshot' mut_governance_notice_revision_changed

mut_governance_notice_commit_survives_only_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
revision = "2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
text = text.replace(f"   Commit:  {revision}", "   Commit:  " + "0" * 40, 1)
text = text.replace(
    "   Notes:   rustfs-gateway",
    f"   Notes:   Commit:  {revision}\n            rustfs-gateway",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the NOTICE commit surviving only inside Notes' mut_governance_notice_commit_survives_only_in_notes

mut_governance_notice_source_field_duplicated() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
source = "   Source:  https://github.com/smithy-lang/smithy-rs\n"
if text.count(source) < 2:
    raise SystemExit("smithy-rs NOTICE source fields are missing")
path.write_text(text.replace(source, source + source, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the NOTICE aws-sigv4 entry repeating a formal source field' mut_governance_notice_source_field_duplicated

mut_governance_registry_entry_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
path.write_text(text.replace("crates/sig/src/derive.rs", "crates/sig/src/missing.rs", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the adapted source disappearing from the copied-code registry' mut_governance_registry_entry_removed

mut_governance_registry_revision_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
new = "  Upstream revision: " + "0" * 40 + "\n  Notes:             2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the registry revision surviving only in Notes' mut_governance_registry_revision_in_notes

mut_governance_registry_facts_split_across_entries() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
text = text.replace(
    "  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176",
    "  Upstream revision: " + "0" * 40,
    1,
)
text += """

  Local path:        crates/sig/src/other.rs
  Upstream project:  https://github.com/smithy-lang/smithy-rs
  Upstream revision: 2880e0785db4cf2ceb086cfeba86a4cbdeb14176
  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/v4.rs
  License:           Apache-2.0
"""
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the registry facts being split across different entries' mut_governance_registry_facts_split_across_entries

mut_governance_registry_path_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
path.write_text(text.replace(old, "  Upstream path:     aws/rust-runtime/aws-sigv4/src/sign/other.rs", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the copied-code registry losing the exact upstream path' mut_governance_registry_path_changed

mut_governance_registry_license_in_notes() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "  License:           Apache-2.0"
new = "  License:           MIT\n  Notes:             Apache-2.0"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the registry license surviving only in Notes' mut_governance_registry_license_in_notes

mut_governance_notice_copyright_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("NOTICE")
text = path.read_text()
old = "   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved."
new = "   Copyright attribution omitted."
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the aws-sigv4 NOTICE entry losing its copyright attribution' mut_governance_notice_copyright_changed

mut_governance_source_revision_removed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
path.write_text(text.replace("2880e0785db4cf2ceb086cfeba86a4cbdeb14176", "revision omitted", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'the in-file attribution losing the reviewed upstream revision' mut_governance_source_revision_removed

mut_governance_source_revision_survives_only_outside_attribution() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
revision = "2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
old = f"//     Revision: {revision} (aws-sigv4 1.5.1)"
new = "//     Revision: " + "0" * 40 + " (aws-sigv4 1.5.1)"
text = text.replace(old, new, 1)
text = text.replace(
    "// ---------------------------------------------------------------------------\n\n//!",
    f"// ---------------------------------------------------------------------------\n// Decoy revision outside ATTRIBUTION: {revision}\n\n//!",
    1,
)
path.write_text(text)
PY
}
expect_fail check_governance_attribution.sh \
    'the source revision surviving only outside ATTRIBUTION' mut_governance_source_revision_survives_only_outside_attribution

mut_governance_source_attribution_block_duplicated() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
divider = "// ---------------------------------------------------------------------------\n"
start = text.index(divider + "// ATTRIBUTION\n")
end = text.index(divider, start + len(divider)) + len(divider)
block = text[start:end]
path.write_text(text.replace("//! The SigV4", block + "\n//! The SigV4", 1))
PY
}
expect_fail check_governance_attribution.sh \
    'derive.rs containing more than one ATTRIBUTION block' mut_governance_source_attribution_block_duplicated

mut_governance_source_function_mapping_changed() {
    python3 - <<'PY'
from pathlib import Path

path = Path("crates/sig/src/derive.rs")
text = path.read_text()
old = "//     Function mapping: signing_key <- generate_signing_key"
new = "//     Function mapping: signing_key <- unrelated_function"
path.write_text(text.replace(old, new, 1))
PY
}
expect_fail check_governance_attribution.sh \
    'derive.rs changing a reviewed function mapping' mut_governance_source_function_mapping_changed

mut_rustfs_dep() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/Cargo.toml")
text = path.read_text()
anchor = "[dependencies]\n"
if text.count(anchor) != 1:
    raise SystemExit("core dependencies table is missing or ambiguous")
path.write_text(text.replace(anchor, anchor + 'rustfs-ecstore = "0.1"\n', 1))
PYEOF
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a rustfs crate' mut_rustfs_dep

mut_ring2_dep() {
    printf 'rustfs-gateway-admin = "0.1"\n' >>crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a ring-2 crate not declared in this workspace' mut_ring2_dep

# After the rename the crate name carries no ring information, so the declaration is
# the only thing the guard can read. A crate without one must fail rather than be
# silently treated as ring 0.
mut_missing_ring_decl() {
    grep -v '^ring = ' crates/http/Cargo.toml >/tmp/.rd.$$ && mv /tmp/.rd.$$ crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'a crate with no [package.metadata.gateway] ring declaration' mut_missing_ring_decl

mut_bad_ring_value() {
    sed 's/^ring = 0$/ring = 2/' crates/http/Cargo.toml >/tmp/.rv.$$ && mv /tmp/.rv.$$ crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'a crate declaring ring 2, which does not live in this repository' mut_bad_ring_value

mut_stray_s3s() {
    printf 's3s = "0.11"\n' >>crates/http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    's3s dependency outside rustfs-gateway-types' mut_stray_s3s

mut_drop_delete_by() {
    grep -v '# DELETE BY' crates/types/Cargo.toml >/tmp/.ct.$$ && mv /tmp/.ct.$$ crates/types/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'compat-s3s losing its "# DELETE BY" expiry marker' mut_drop_delete_by

mut_server_unreviewed_dep() {
    printf 'reqwest = "0.12"\n' >>crates/server/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'ring-1 server gaining a dependency outside its allowlist' mut_server_unreviewed_dep

mut_server_host_write() {
    printf '\nfn normalize_host(request: &mut http::Request<()>) { request.headers_mut().insert(http::header::HOST, http::HeaderValue::from_static("x")); }\n' >>crates/server/src/conn.rs
}
expect_fail_and_missing_grep check_no_host_normalize.sh \
    'ring-1 server writing the Host header' mut_server_host_write

mut_server_handler_timeout() {
    printf '\nconst HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);\n' >>crates/server/src/config.rs
}
expect_fail_and_missing_grep check_timeout_layer_ownership.sh \
    'ring-1 server claiming the handler timeout layer' mut_server_handler_timeout

mut_server_tuning_doc() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/server/src/config.rs")
text = path.read_text().replace(
    "/// Global open-connection ceiling. Increasing raises capacity and memory; decreasing applies earlier backpressure.\n",
    "/// Global open-connection ceiling.\n",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_tuning_doc.sh \
    'a server tuning field losing both tradeoff directions' mut_server_tuning_doc

mut_planning_dir() {
    mkdir -p docs/plans
    printf '# scratch\n' >docs/plans/codegen-rollout.md
}
expect_fail check_no_planning_docs.sh \
    'a document committed under docs/plans/' mut_planning_dir

mut_planning_name() {
    printf '# scratch\n' >MIGRATION_PLAN.md
}
expect_fail check_no_planning_docs.sh \
    'a root-level MIGRATION_PLAN.md' mut_planning_name

mut_inventory() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/core/Cargo.toml")
text = path.read_text()
anchor = "[dependencies]\n"
if text.count(anchor) != 1:
    raise SystemExit("core dependencies table is missing or ambiguous")
path.write_text(text.replace(anchor, anchor + 'inventory = "0.3"\n', 1))
PYEOF
}
expect_fail check_no_global_registry_deps.sh \
    'an `inventory` dependency' mut_inventory

# NOTE: appended to a manifest whose last table is `[dependencies]`. Appending
# to rustfs-gateway-types would land the line in its `[features]` table, where it is
# correctly NOT a dependency.
mut_ctor() {
    printf 'ctor = "0.2"\n' >>crates/xml/Cargo.toml
}
expect_fail check_no_global_registry_deps.sh \
    'a `ctor` dependency' mut_ctor

mut_derived_signature() {
    cat >crates/sig/src/proof.rs <<'RS'
// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fixture.

/// A signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 32]);
RS
}
expect_fail check_ct_eq.sh \
    'a Signature type deriving Debug/PartialEq/Eq' mut_derived_signature

mut_strip_header() {
    grep -v 'Licensed under the Apache License' crates/core/src/lib.rs >/tmp/.lh.$$ &&
        mv /tmp/.lh.$$ crates/core/src/lib.rs
}
expect_fail check_license_headers.sh \
    'a Rust file with the licence header removed' mut_strip_header

mut_restore_license_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'head -n "$HEADER_WINDOW" "$file" | grep -F "$HEADER_MARKER" >/dev/null',
    'head -n "$HEADER_WINDOW" "$file" | grep -qF "$HEADER_MARKER"',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'the license guard restoring an early-exit grep pipeline' mut_restore_license_grep_q_pipeline

mut_restore_secret_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "grep -qE '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'the secret guard restoring an early-exit grep pipeline' mut_restore_secret_grep_q_pipeline

mut_restore_multiline_combined_grep_q_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'head -n "$HEADER_WINDOW" "$file" | grep -F "$HEADER_MARKER" >/dev/null',
    'head -n "$HEADER_WINDOW" "$file" |\n        grep -Fqi "$HEADER_MARKER"',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a multiline pipeline restoring combined quiet grep flags' mut_restore_multiline_combined_grep_q_pipeline

mut_restore_multiline_long_quiet_pipeline() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "printf '%s\\n' \"$credentials_code\" | grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "printf '%s\\n' \"$credentials_code\" |\\n    grep --quiet -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a multiline pipeline restoring the long quiet option' mut_restore_multiline_long_quiet_pipeline

mut_quiet_grep_in_command_substitution() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'status="$(head -n 1 "$0" | grep -qF marker)"\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'a quiet grep inside command substitution' mut_quiet_grep_in_command_substitution

mut_split_grep_and_quiet_flag() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_secret_hygiene.sh")
text = path.read_text().replace(
    "grep -E '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{' >/dev/null",
    "grep \\\n+        -qiE '^impl ([a-z_:]+)?fmt::Debug for Credentials \\{'",
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'grep and its combined quiet flag split across lines' mut_split_grep_and_quiet_flag

mut_grep_e_and_quiet_combined() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'grep -eq pattern input\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'grep combining the expression and quiet flags' mut_grep_e_and_quiet_combined

mut_multiline_grep_e_and_quiet_combined() {
    python3 - <<'PY'
from pathlib import Path

path = Path("scripts/check_license_headers.sh")
text = path.read_text().replace(
    'checked=0',
    'grep \\\n+    -eq pattern input\nchecked=0',
    1,
)
path.write_text(text)
PY
}
expect_fail check_guard_grep_pipelines.sh \
    'multiline grep combining the expression and quiet flags' mut_multiline_grep_e_and_quiet_combined

probe_guard_grep_policy_allows_shell_eq() {
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    printf '\n[[ 1 -eq 1 ]]\n' >>"${sandbox}/scripts/check_license_headers.sh"
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" \
        >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh allows the shell -eq operator'
    else
        fail_msg 'check_guard_grep_pipelines.sh mistook the shell -eq operator for quiet grep'
    fi
}
probe_guard_grep_policy_allows_shell_eq

probe_guard_grep_policy_missing_grep() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v mktemp)" "${tool_path}/mktemp"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: grep'* ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed without grep'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green without grep'
    fi
}
probe_guard_grep_policy_missing_grep

probe_guard_grep_policy_missing_awk() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 && "$output" == *'required command is missing: awk'* ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed without awk'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green without awk'
    fi
}
probe_guard_grep_policy_missing_awk

probe_guard_grep_policy_awk_error() {
    local sandbox tool_path output rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    tool_path="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-path.XXXXXX")"
    ln -s "$(command -v dirname)" "${tool_path}/dirname"
    ln -s "$(command -v grep)" "${tool_path}/grep"
    ln -s "$(command -v mktemp)" "${tool_path}/mktemp"
    ln -s "$(command -v rm)" "${tool_path}/rm"
    printf '#!/bin/sh\nexit 75\n' >"${tool_path}/awk"
    chmod +x "${tool_path}/awk"
    output="$(GATEWAY_CHECK_ROOT="$sandbox" PATH="$tool_path" /bin/bash \
        "${SCRIPT_DIR}/check_guard_grep_pipelines.sh" 2>&1)" || rc=$?
    rm -rf "$tool_path"
    if [[ "$rc" -ne 0 ]]; then
        pass_msg 'check_guard_grep_pipelines.sh fails closed on an awk processing error'
    else
        fail_msg 'check_guard_grep_pipelines.sh reported green after an awk processing error'
    fi
}
probe_guard_grep_policy_awk_error


# -----------------------------------------------------------------------------
# check_ct_eq.sh grew from one rule to seven when P2-02 landed. Each new rule
# needs its own negative control here: a rule with no failing case is a rule
# nobody has ever seen work.
# -----------------------------------------------------------------------------

mut_secret_display() {
    printf '\nimpl core::fmt::Display for SecretBytes {\n    fn fmt(&self, _: &mut core::fmt::Formatter<\x27_>) -> core::fmt::Result { Ok(()) }\n}\n' \
        >>crates/sig/src/secret.rs
}
expect_fail check_ct_eq.sh \
    'a Display impl on a secret-bearing type' mut_secret_display

mut_second_bool_from() {
    printf '\nfn leak(c: subtle::Choice) -> bool { bool::from(c) }\n' \
        >>crates/sig/src/verdict.rs
}
expect_fail check_ct_eq.sh \
    'a second bool::from(Choice), which turns constant time back into a branch' mut_second_bool_from

mut_unwrap_u8() {
    printf '\nfn peek(c: subtle::Choice) -> u8 { c.unwrap_u8() }\n' \
        >>crates/sig/src/verdict.rs
}
expect_fail check_ct_eq.sh \
    'Choice::unwrap_u8, which discards the constant-time wrapper' mut_unwrap_u8

mut_secret_in_log() {
    printf '\nfn oops(s: &SecretBytes) -> String { format!("secret={s:?}") }\n' \
        >>crates/sig/src/secret.rs
}
expect_fail check_ct_eq.sh \
    'a secret interpolated into a formatting macro' mut_secret_in_log

mut_unboxed_key_material() {
    printf '\npub(crate) struct Leaky { signing_key: Vec<u8> }\n' \
        >>crates/sig/src/timing.rs
}
expect_fail check_ct_eq.sh \
    'key material held in Vec<u8> instead of a zeroizing box' mut_unboxed_key_material

mut_strip_negative_floor() {
    # The floor counts across the whole crate, so stripping one file is not enough
    # to trip it — the mutation has to remove the annotations everywhere.
    find crates/sig -name '*.rs' -print0 | while IFS= read -r -d '' f; do
        grep -v '^/// Negative' "$f" >"${f}.nf" && mv "${f}.nf" "$f"
    done
}
expect_fail check_ct_eq.sh \
    'negative-case coverage dropping below its floor' mut_strip_negative_floor

# P2-01 case coverage. Each failure mode has an independent mutation: a mapping can disappear,
# lie about its polarity, point nowhere, name no case, point at no executable assertion, lose its
# golden, reuse another fixture, or stop being wired into trybuild.
mut_sig_case_mapping_deleted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
line = "    'c-sig-0025|negative|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0025_non_canonical_base64_is_rejected'\n"
if line not in text:
    raise SystemExit("missing mapping mutation subject")
path.write_text(text.replace(line, "", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'one of the 25 acceptance mappings being deleted' mut_sig_case_mapping_deleted

mut_sig_case_order_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
first = "    'c-sig-0001|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0001_empty_is_not_framed'"
second = "    'c-sig-0002|positive|crates/sig/tests/frozen_dimensions.rs|fn c_sig_0002_hex_digest_keeps_its_signed_spelling'"
if first not in text or second not in text:
    raise SystemExit("missing order mutation subject")
text = text.replace(first, "__FIRST__", 1).replace(second, first, 1).replace("__FIRST__", second, 1)
path.write_text(text)
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'the acceptance mappings being reordered' mut_sig_case_order_changed

mut_sig_case_polarity_unknown() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "c-sig-0008|positive|"
if old not in text:
    raise SystemExit("missing polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0008|unknown|", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a case mapping using an unknown polarity' mut_sig_case_polarity_unknown

mut_sig_case_polarity_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "c-sig-0008|positive|"
if old not in text:
    raise SystemExit("missing polarity mutation subject")
path.write_text(text.replace(old, "c-sig-0008|negative|", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'the required 8 positive and 17 negative split changing' mut_sig_case_polarity_changed

mut_sig_case_file_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("scripts/check_sig_case_coverage.sh")
text = path.read_text()
old = "crates/sig/tests/frozen_dimensions.rs|fn c_sig_0025"
if old not in text:
    raise SystemExit("missing file mutation subject")
path.write_text(text.replace(old, "crates/sig/tests/missing.rs|fn c_sig_0025", 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a case mapping pointing to a missing file' mut_sig_case_file_missing

mut_sig_case_id_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
if "c-sig-0025" not in text:
    raise SystemExit("missing id mutation subject")
path.write_text(text.replace("c-sig-0025", "removed-sig-0025"))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a mapped file no longer naming its acceptance id' mut_sig_case_id_missing

mut_sig_case_evidence_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "fn c_sig_0025_non_canonical_base64_is_rejected"
if old not in text:
    raise SystemExit("missing evidence mutation subject")
path.write_text(text.replace(old, "fn removed_sig_0025_non_canonical_base64_is_rejected", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a mapping no longer reaching its named executable assertion' mut_sig_case_evidence_missing

mut_sig_runtime_line_comment_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = "// #[test]\n// fn c_sig_0025_non_canonical_base64_is_rejected()\nfn removed_sig_0025_non_canonical_base64_is_rejected()"
if old not in text:
    raise SystemExit("missing line-comment decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a commented-out #[test] and function being used as runtime evidence' mut_sig_runtime_line_comment_decoy

mut_sig_runtime_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = 'const DECOY: &str = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected(";\n#[test]\nfn removed_sig_0025_non_canonical_base64_is_rejected()'
if old not in text:
    raise SystemExit("missing runtime string decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a string containing #[test] and a function name being used as runtime evidence' mut_sig_runtime_string_decoy

mut_sig_runtime_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = "#[cfg(\n    any()\n)]\n#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
if old not in text:
    raise SystemExit("missing disabled test mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled #[test] being counted as executable evidence' mut_sig_runtime_disabled_by_cfg

mut_sig_runtime_macro_body_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/frozen_dimensions.rs")
text = path.read_text()
old = "#[test]\nfn c_sig_0025_non_canonical_base64_is_rejected()"
new = """macro_rules! fake_test {
    () => {
        #[test]
        fn c_sig_0025_non_canonical_base64_is_rejected() {}
    };
}
#[test]
fn removed_sig_0025_non_canonical_base64_is_rejected()"""
if old not in text:
    raise SystemExit("missing runtime macro decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a #[test] function inside a macro body being accepted as runtime evidence' mut_sig_runtime_macro_body_decoy

mut_sig_compile_fixture_not_executable() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
if old not in text:
    raise SystemExit("missing executable mutation subject")
path.write_text(text.replace(old, "fn removed_main()", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail fixture losing its executable entry' mut_sig_compile_fixture_not_executable

mut_sig_compile_block_comment_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = "fn removed_main()\n/* fn main() {} */"
if old not in text:
    raise SystemExit("missing block-comment decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a block-comment fn main decoy being accepted as executable evidence' mut_sig_compile_block_comment_decoy

mut_sig_compile_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = 'const DECOY: &str = "fn main()";\nfn removed_main()'
if old not in text:
    raise SystemExit("missing compile string decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a string containing fn main being accepted as an entry point' mut_sig_compile_string_decoy

mut_sig_compile_main_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = "#[cfg(\n    any()\n)]\nfn main()"
if old not in text:
    raise SystemExit("missing disabled main mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled fn main being counted as an executable fixture' mut_sig_compile_main_disabled_by_cfg

mut_sig_compile_macro_body_main_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "fn main()"
new = """macro_rules! fake_main {
    () => { fn main() {} };
}
fn removed_main()"""
if old not in text:
    raise SystemExit("missing compile macro decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a fn main inside a macro body being accepted as an entry point' mut_sig_compile_macro_body_main_decoy

mut_sig_compile_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
text = path.read_text()
old = "    let _ = left == right;"
new = "    #[cfg(\n        any()\n    )]\n    let _ = left == right;"
if old not in text:
    raise SystemExit("missing disabled evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'mapped compile evidence being disabled inside an active main' mut_sig_compile_evidence_disabled_by_cfg

mut_sig_serialize_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.rs")
text = path.read_text()
old = "    let _ = serde_json::to_string(&token);"
new = "    #[cfg(\n        any()\n    )]\n    let _ = serde_json::to_string(&token);"
if old not in text:
    raise SystemExit("missing disabled serialization evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 evidence being disabled at its statement boundary' mut_sig_serialize_evidence_disabled_by_cfg

mut_sig_family_evidence_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0019_sig_family_exhaustive.rs")
text = path.read_text()
old = "    let _ = match family {"
new = "    #[cfg(\n        any()\n    )]\n    let _ = match family {"
if old not in text:
    raise SystemExit("missing disabled family evidence mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0019 evidence being disabled at its statement boundary' mut_sig_family_evidence_disabled_by_cfg

mut_sig_compile_char_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
guard_text = guard.read_text()
old = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|let _ = left == right;"
new = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|u{10FFFD}"
if old not in guard_text:
    raise SystemExit("missing char-decoy mapping mutation subject")
guard.write_text(guard_text.replace(old, new, 1))

fixture = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
fixture_text = fixture.read_text()
old = "    let _ = left == right;"
new = "    let _ = (left, right);\n    const DECOY: char = '\\u{10FFFD}';\n    let _ = DECOY;"
if old not in fixture_text:
    raise SystemExit("missing char-decoy fixture mutation subject")
fixture.write_text(fixture_text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'a character literal being accepted as compile evidence' mut_sig_compile_char_decoy

mut_sig_compile_golden_missing() {
    rm crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail fixture losing its stderr golden' mut_sig_compile_golden_missing

mut_sig_compile_golden_hollow() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr")
text = path.read_text()
if "error[E" not in text:
    raise SystemExit("missing diagnostic mutation subject")
path.write_text(text.replace("error[E", "diagnostic[E", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail golden containing no rustc error' mut_sig_compile_golden_hollow

mut_sig_compile_golden_unrelated_error() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.stderr")
path.write_text("error[E0425]: cannot find value `unrelated` in this scope\n")
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a compile-fail golden retaining only an unrelated rustc error' mut_sig_compile_golden_unrelated_error

mut_sig_compile_evidence_not_independent() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
text = guard.read_text()
old = "c-sig-0014|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|let _ = left == right;"
new = "c-sig-0014|negative|crates/sig/tests/frozen_dimensions.rs|fn secret_bearing_types_derive_nothing_that_compares_or_prints"
if old not in text:
    raise SystemExit("missing independence mutation subject")
guard.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'one compile-time case being replaced by an unrelated runtime source guard' mut_sig_compile_evidence_not_independent

mut_sig_compile_fixture_reused() {
    python3 - <<'PYEOF'
from pathlib import Path
guard = Path("scripts/check_sig_case_coverage.sh")
text = guard.read_text()
old = "c-sig-0015|negative|crates/sig/tests/compile_fail/c_sig_0015_ctbytes_debug.rs|println!"
new = "c-sig-0015|negative|crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs|println!"
if old not in text:
    raise SystemExit("missing distinct-fixture mutation subject")
guard.write_text(text.replace(old, new, 1))
fixture = Path("crates/sig/tests/compile_fail/c_sig_0014_ctbytes_eq.rs")
fixture_text = fixture.read_text()
old_fixture = "    let _ = left == right;"
new_fixture = "    let _ = left == right;\n    let bytes = left;\n    println!(\"{bytes:?}\");"
if old_fixture not in fixture_text:
    raise SystemExit("missing fixture reuse insertion point")
fixture.write_text(fixture_text.replace(old_fixture, new_fixture, 1) + "\n// c-sig-0015\n")
PYEOF
}
expect_fail_self_mutation check_sig_case_coverage.sh \
    'two compile-time cases reusing one fixture' mut_sig_compile_fixture_reused

mut_sig_trybuild_dependency_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
old = "trybuild = { workspace = true }\n"
if old not in text:
    raise SystemExit("missing dependency mutation subject")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig crate dropping its trybuild dependency' mut_sig_trybuild_dependency_removed

mut_sig_trybuild_harness_removed() {
    rm crates/sig/tests/compile_fail.rs
}
expect_fail check_sig_case_coverage.sh \
    'the independent compile-fail harness being deleted' mut_sig_trybuild_harness_removed

mut_sig_trybuild_harness_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = "#[test]\nfn p2_01_compile_time_boundaries_are_not_openable()"
new = "#[cfg(\n    any()\n)]\n#[test]\nfn p2_01_compile_time_boundaries_are_not_openable()"
if old not in text:
    raise SystemExit("missing disabled harness mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a multiline cfg-disabled sig trybuild harness being counted as active' mut_sig_trybuild_harness_disabled

mut_sig_trybuild_call_outside_test() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = '''    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs");'''
new = '''    run_cases();
}

fn run_cases() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs");'''
if old not in text:
    raise SystemExit("missing harness body mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig compile_fail call moving outside its active test body' mut_sig_trybuild_call_outside_test

mut_sig_trybuild_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_001[4-79]_*.rs")'
if old not in text:
    raise SystemExit("missing harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the harness no longer executing the P2-01 fixtures' mut_sig_trybuild_glob_removed

mut_sig_manifest_gains_serde() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
marker = "[dev-dependencies]\n"
if marker not in text:
    raise SystemExit("missing sig manifest mutation subject")
path.write_text(text.replace(marker, "serde = { workspace = true }\n\n" + marker, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig production manifest gaining serde' mut_sig_manifest_gains_serde

mut_sig_manifest_gains_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/sig/Cargo.toml")
text = path.read_text()
marker = "[dev-dependencies]\n"
if marker not in text:
    raise SystemExit("missing renamed serde mutation subject")
dependency = 'hidden_codec = { package = "serde", version = "1" }\n\n'
path.write_text(text.replace(marker, dependency + marker, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig manifest hiding serde behind a renamed dependency' mut_sig_manifest_gains_renamed_serde

mut_sig_target_manifest_gains_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path

manifest = Path("crates/sig/Cargo.toml")
manifest.write_text(manifest.read_text() + '''
[target.'cfg(target_os = "none")'.dependencies]
hidden_codec = { package = "serde", version = "1" }
''')
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'a target-specific sig dependency hiding serde behind a rename' mut_sig_target_manifest_gains_renamed_serde

mut_sig_manifest_inherits_renamed_serde() {
    python3 - <<'PYEOF'
from pathlib import Path

workspace = Path("Cargo.toml")
workspace_text = workspace.read_text()
marker = "[workspace.dependencies]\n"
if marker not in workspace_text:
    raise SystemExit("missing workspace dependency mutation subject")
workspace.write_text(workspace_text.replace(
    marker,
    marker + 'hidden_codec = { package = "serde", version = "1" }\n',
    1,
))

manifest = Path("crates/sig/Cargo.toml")
manifest_text = manifest.read_text()
marker = "[dev-dependencies]\n"
if marker not in manifest_text:
    raise SystemExit("missing inherited serde mutation subject")
manifest.write_text(manifest_text.replace(
    marker,
    'hidden_codec = { workspace = true }\n\n' + marker,
    1,
))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the sig manifest inheriting a workspace-renamed serde dependency' mut_sig_manifest_inherits_renamed_serde

mut_sig_real_serde_dependency_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/Cargo.toml")
text = path.read_text()
old = "serde_json = { workspace = true }\n"
if old not in text:
    raise SystemExit("missing core serde_json dependency mutation subject")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the real serde_json dev dependency being removed' mut_sig_real_serde_dependency_removed

mut_sig_core_harness_removed() {
    rm crates/core/tests/compile_fail.rs
}
expect_fail check_sig_case_coverage.sh \
    'the c-sig-0018 real-serde harness being deleted' mut_sig_core_harness_removed

mut_sig_core_harness_comment_string_decoy() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = '''#[test]
fn compile_time_contracts_are_not_openable() {'''
new = '''// #[test]
// fn compile_time_contracts_are_not_openable() {}
const DECOY: &str = r#"#[test]
fn compile_time_contracts_are_not_openable() {
    cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");
}"#;
fn removed_compile_time_contracts_are_not_openable() {'''
if old not in text:
    raise SystemExit("missing core harness decoy mutation subject")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'comment and string decoys replacing the active core trybuild harness' mut_sig_core_harness_comment_string_decoy

mut_sig_core_glob_removed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail.rs")
text = path.read_text()
old = 'cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs")'
if old not in text:
    raise SystemExit("missing core harness mutation subject")
path.write_text(text.replace(old, 'cases.compile_fail("tests/compile_fail/never_*.rs")', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'the core harness no longer executing c-sig-0018' mut_sig_core_glob_removed

mut_sig_serialize_trait_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'error[E0277]: the trait bound `SessionToken: serde::Serialize` is not satisfied'
if old not in text:
    raise SystemExit("missing serialization diagnostic mutation subject")
path.write_text(text.replace(old, 'the serialization diagnostic was weakened', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 losing the exact missing-Serialize diagnostic' mut_sig_serialize_trait_diagnostic_changed

mut_sig_serialize_impl_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'the trait `serde_core::ser::Serialize` is not implemented for `SessionToken`'
if old not in text:
    raise SystemExit("missing implementation diagnostic mutation subject")
path.write_text(text.replace(old, 'the implementation diagnostic was weakened', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 losing the exact missing implementation diagnostic' mut_sig_serialize_impl_diagnostic_changed

mut_sig_serialize_call_diagnostic_changed() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/tests/compile_fail/c_sig_0018_session_token_serialize.stderr")
text = path.read_text()
old = 'required by a bound in `serde_json::to_string`'
if old not in text:
    raise SystemExit("missing serialization-bound diagnostic mutation subject")
path.write_text(text.replace(old, 'required by another call', 1))
PYEOF
}
expect_fail check_sig_case_coverage.sh \
    'c-sig-0018 no longer diagnosing its serialization bound' mut_sig_serialize_call_diagnostic_changed

# -----------------------------------------------------------------------------
# ADR-0005. Each of the three mutations below is a way the generated dto silently
# stops being part of the `rustfs-gateway-types` package: the escaping `#[path]`
# is the original defect, the real directory is the well-meaning "fix" that
# duplicates generated output, and the text file is what a Windows checkout
# without `core.symlinks` produces.
# -----------------------------------------------------------------------------
mut_escaping_dto_path() {
    # The spelling the crate had before ADR-0005: reaches the generated tree, but
    # from outside the package, so `cargo package` cannot see it.
    sed -e 's|"../generated/ops/mod.rs"|"../../../generated/dto/ops/mod.rs"|' \
        -e 's|"../generated/flat.rs"|"../../../generated/dto/flat.rs"|' \
        crates/types/src/lib.rs >crates/types/src/lib.rs.mut
    mv crates/types/src/lib.rs.mut crates/types/src/lib.rs
}
expect_fail check_generated_dto_packaged.sh \
    'a #[path] reaching outside the package directory' mut_escaping_dto_path

mut_dto_copy_instead_of_symlink() {
    rm -f crates/types/generated
    cp -R generated/dto crates/types/generated
}
expect_fail check_generated_dto_packaged.sh \
    'the dto mount replaced by a real directory (a second copy of generated output)' \
    mut_dto_copy_instead_of_symlink

mut_dto_symlink_as_text() {
    rm -f crates/types/generated
    printf '../../generated/dto' >crates/types/generated
}
expect_fail check_generated_dto_packaged.sh \
    'the dto symlink materialised as a text file, as on Windows without core.symlinks' \
    mut_dto_symlink_as_text


# -----------------------------------------------------------------------------
# ADR-0004's SemVer policy was prose until now. These two guards are what make
# "a new optional field is a minor change" enforceable rather than aspirational.
# -----------------------------------------------------------------------------

mut_dto_non_exhaustive() {
    f=generated/dto/ops/get_bucket_location.rs
    awk '/^#\[derive\(Debug, Clone, Default\)\]$/ && !done { print "#[non_exhaustive]"; done = 1 } { print }' \
        "$f" >"${f}.mut" && mv "${f}.mut" "$f"
}
expect_fail check_no_dto_non_exhaustive.sh \
    'a dto struct marked #[non_exhaustive], which forbids FRU' mut_dto_non_exhaustive

mut_exhaustive_destructuring() {
    cat >>crates/types/src/lib.rs <<'RS'

#[cfg(test)]
mod destructure_fixture {
    #[test]
    fn fixture() {
        let out = crate::ops::get_bucket_location::Output::default();
        let crate::ops::get_bucket_location::Output { location_constraint } = out;
        let _ = location_constraint;
    }
}
RS
}
expect_fail check_no_exhaustive_destructuring.sh \
    'a dto destructured without a trailing ..' mut_exhaustive_destructuring


# -----------------------------------------------------------------------------
# English-only. The first version of this guard used a grep bracket expression,
# which is interpreted by locale collation rather than by codepoint and matched
# an em dash — it reported every English file in the tree. The negative control
# is what tells the two versions apart.
# -----------------------------------------------------------------------------

# The Chinese is written as UTF-8 byte escapes so this file stays pure ASCII.
# Spelling it literally would make the guard flag its own test, and allowing the
# file would then permit real Chinese to sit here unnoticed forever.
# \xe4\xb8\xad\xe6\x96\x87 is the two-character word for "Chinese".
mut_chinese_comment() {
    printf '\n// \xe4\xb8\xad\xe6\x96\x87\n' >>crates/core/src/lib.rs
}
expect_english_fail_minimal \
    'a Chinese comment in a source file' mut_chinese_comment \
    crates/core/src/lib.rs tracked

mut_chinese_markdown() {
    printf '\n\xe4\xb8\xad\xe6\x96\x87\n' >>docs/msrv.md
}
expect_english_fail_minimal \
    'a Chinese paragraph in a Markdown document' mut_chinese_markdown \
    docs/msrv.md tracked


# -----------------------------------------------------------------------------
# The guards read `git ls-files --cached --others --exclude-standard`, not a bare
# `git ls-files`. The bare form lists only tracked files, so a brand-new file is
# invisible until `git add -A` commits it — which is how CJK text reached commit
# 343f044 through a guard run that had just reported success. These two cases
# fail if anyone drops the flags: the sandbox never stages the mutation, so an
# untracked-blind guard sees nothing and exits 0.
# -----------------------------------------------------------------------------

mut_untracked_chinese_source() {
    # \xe4\xb8\xad\xe6\x96\x87 is the two-character word for "Chinese"; written as
    # bytes so this file stays ASCII and does not trip the guard it is testing.
    printf '// \xe4\xb8\xad\xe6\x96\x87\n' >crates/core/src/brand_new_file.rs
}
expect_english_fail_minimal \
    'CJK in a file that has never been added to the index' mut_untracked_chinese_source \
    crates/core/src/brand_new_file.rs untracked

mut_untracked_missing_header() {
    printf '//! No licence header.\npub fn f() {}\n' >crates/core/src/no_header_yet.rs
}
expect_fail_unstaged check_license_headers.sh \
    'a new .rs file with no licence header, still untracked' mut_untracked_missing_header


# -----------------------------------------------------------------------------
# A `//! Members:` line is how a reader learns which operations share a rule. It
# had already drifted before this guard existed — precondition.rs named seven
# operations while one file in the tree used it — and nothing noticed for four
# commits. Both directions matter: a claimed member that does not use the module
# is a contract wired into nothing, and a user missing from the list hides a
# dependency from the next person to change the rule.
# -----------------------------------------------------------------------------

mut_members_claims_unused() {
    python3 - <<'PYEOF'
import pathlib, re
p = pathlib.Path("crates/core/src/ops/shared/pagination.rs")
t = p.read_text()
t = re.sub(r"^//! Members:.*$", "//! Members: ListBuckets, GetObject", t, count=1, flags=re.M)
p.write_text(t)
PYEOF
}
expect_fail check_shared_members.sh \
    'a Members: line naming an operation that does not use the module' mut_members_claims_unused


# -----------------------------------------------------------------------------
# A shared contract only this workspace can reach is one every backend rewrites.
# It happened to copy_source, to precondition, to Checksummer, and the guard
# caught pagination the moment it existed. The control adds a fifth to prove the
# guard is looking at the facade rather than at a list of the four known names.
# -----------------------------------------------------------------------------

mut_unexported_shared_item() {
    printf '\n/// A contract no backend can reach.\npub fn brand_new_contract() {}\n' \
        >>crates/core/src/ops/shared/pagination.rs
}
expect_fail check_shared_reachable.sh \
    'a new public item in shared/ that the facade does not re-export' mut_unexported_shared_item

# -----------------------------------------------------------------------------
# The route-coverage register has to move in both directions or it stops being a
# measurement. Growing it silently is how `PUT /b/k?acl` came to write the ACL
# document over the object — the row at 560 has since retired that line, which is
# why the mutation below names `RenameObject` instead; shrinking it silently is
# how a closed exposure keeps being counted, and a count that only ever says the
# same number is a count nobody reads.
#
# Both controls therefore mutate the register rather than the tree, because the
# register is the artefact the guard exists to keep honest.
# -----------------------------------------------------------------------------

mut_forgotten_exposure() {
    grep -v 'RenameObject' scripts/allowances/route-coverage-allowances.txt >/tmp/rc-allow.$$
    mv /tmp/rc-allow.$$ scripts/allowances/route-coverage-allowances.txt
}
expect_fail check_route_coverage.sh \
    'a swallowed operation missing from the register' mut_forgotten_exposure

mut_stale_exposure() {
    printf 'NoSuchOperation -> NoSuchNeighbour\n' >>scripts/allowances/route-coverage-allowances.txt
}
expect_fail check_route_coverage.sh \
    'a register entry for an exposure that no longer exists' mut_stale_exposure

# -----------------------------------------------------------------------------
# A conformance case may only declare what the harness reads. Twice already a
# case declared a precondition — `setup.buckets[].object_lock`,
# `connection.pipeline` — that was parsed, schema-checked and then dropped, so
# the case measured a scenario other than the one it described and reported
# green. The guard runs the corpus and audits which schema keys the harness
# actually read.
#
# The controls mutate the SCHEMA in the sandbox rather than the harness,
# because check_case_keys_honoured.sh audits the sandbox's corpus using the
# binary built next to this script: a harness mutation would need a cold
# compile of the whole workspace inside the sandbox, and this suite has a
# ten-minute budget.
#
# The first control is the defect itself: a key the frozen schema allows and
# nothing reads. The second is the guard's other end — an entry in DECLARED
# that no longer names a field, which is how an exemption list rots into a
# list of excuses for fields that stopped existing.
# -----------------------------------------------------------------------------

mut_unread_schema_key() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["$defs"]["expect"]["properties"]["nothing_reads_this"] = {
    "type": "boolean",
    "description": "A declaration no code looks at. The guard must say so.",
}
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_case_keys_honoured.sh \
    'a schema key the harness never reads' mut_unread_schema_key

mut_declaration_for_a_dropped_field() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
# `evidence.kind` is carried in keys::DECLARED as inert. Removing the field
# leaves the entry naming something the schema no longer declares.
del schema["$defs"]["evidence"]["properties"]["kind"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_case_keys_honoured.sh \
    'a DECLARED entry naming a field the schema dropped' mut_declaration_for_a_dropped_field

# -----------------------------------------------------------------------------
# P8-01 freezes the case language and the baseline contract. These controls
# remove one required dimension at a time, weaken evidence, add a regression to
# the baseline, and replace the raw socket write with an HTTP client dependency.
# A green guard without these mutations would only restate the intended policy.
# -----------------------------------------------------------------------------

mut_schema_chunk_timing() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["dataChunk"]["properties"]["delay_ms"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the chunk arrival timing field removed from the frozen schema' mut_schema_chunk_timing

mut_schema_abnormal_close() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["$defs"]["controlChunk"]["properties"]["action"]["enum"].remove("half_close")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'half-close removed from abnormal termination actions' mut_schema_abnormal_close

mut_schema_stream_error() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["body_bytes_before_error"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the mid-stream response byte counter removed' mut_schema_stream_error

mut_schema_stream_error_optional() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
for condition in schema["$defs"]["expect"]["allOf"]:
    if condition.get("if", {}).get("properties", {}).get("kind", {}).get("const") == "stream_error":
        condition["then"]["required"].remove("body_bytes_before_error")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the mid-stream byte counter made optional' mut_schema_stream_error_optional

mut_schema_clock() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["clock"]["properties"]["fixed"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the fixed clock injection field removed' mut_schema_clock

mut_schema_reuse() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["connection"]["properties"]["reuse"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the connection reuse field removed' mut_schema_reuse

mut_schema_events() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["events"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the response event sequence removed' mut_schema_events

mut_schema_events_optional() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
for condition in schema["$defs"]["expect"]["allOf"]:
    if condition.get("if", {}).get("properties", {}).get("kind", {}).get("const") == "event_stream":
        condition["then"]["required"].remove("events")
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the event sequence made optional for an event-stream expectation' mut_schema_events_optional

mut_schema_golden() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["bodyExpectation"]["properties"]["golden"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the byte-exact golden field removed' mut_schema_golden

mut_schema_header_absence() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
del schema["$defs"]["expect"]["properties"]["headers_absent"]
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'the absent-header assertion removed' mut_schema_header_absence

mut_schema_transport_field() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/case.schema.json")
schema = json.loads(path.read_text())
schema["properties"]["transport"] = {"type": "string"}
path.write_text(json.dumps(schema, indent=2))
PYEOF
}
expect_fail check_schema_dimensions.sh \
    'transport made case-selectable instead of runner-injected' mut_schema_transport_field

mut_missing_evidence() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("conformance/cases/acl/c-acl-0002.toml")
text = path.read_text()
start = text.index("[[case.evidence]]")
end = text.find("\n[", start + 2)
path.write_text(text[:start] + (text[end + 1:] if end >= 0 else ""))
PYEOF
}
expect_fail check_evidence_shape.sh \
    'a case with its evidence removed' mut_missing_evidence

mut_pasted_evidence() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("conformance/cases/acl/c-acl-0002.toml")
text = path.read_text()
needle = 'summary = "'
at = text.index(needle) + len(needle)
path.write_text(text[:at] + ("x" * 201) + text[at:])
PYEOF
}
expect_fail check_evidence_shape.sh \
    'an evidence summary longer than the compliance ceiling' mut_pasted_evidence

mut_baseline_regression() {
    python3 - <<'PYEOF'
import json, pathlib
path = pathlib.Path("conformance/baseline.json")
baseline = json.loads(path.read_text())
case = next(case for case, verdict in baseline["cases"].items() if verdict == "passed")
baseline["cases"][case] = "failed"
path.write_text(json.dumps(baseline, indent=2) + "\n")
PYEOF
}
expect_fail check_baseline_ratchet.sh \
    'a newly failing case added to the baseline' mut_baseline_regression

mut_baseline_deleted() {
    rm -f conformance/baseline.json
}
expect_fail check_baseline_ratchet.sh \
    "the guard's baseline input deleted, which must fail rather than skip" mut_baseline_deleted

mut_runner_sdk_dependency() {
    printf 'aws-sdk-s3 = "1"\n' >>crates/conformance/Cargo.toml
}
expect_fail check_runner_raw_bytes.sh \
    'an S3 SDK dependency added to the conformance runner' mut_runner_sdk_dependency

mut_runner_raw_write_removed() {
    sed 's/\.write_all(bytes)/.write_all(\&[])/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the request bytes no longer written verbatim to the socket' mut_runner_raw_write_removed

mut_runner_raw_write_hidden_in_comment() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/conformance/src/socket.rs")
text = path.read_text()
old = "            .write_all(bytes)"
new = "            .write_all(&[]) // .write_all(bytes)"
if old not in text:
    raise SystemExit("raw write call not found")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_runner_raw_bytes.sh \
    'the raw-write marker surviving only inside a comment' mut_runner_raw_write_hidden_in_comment

mut_runner_raw_write_hidden_in_string() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/conformance/src/socket.rs")
text = path.read_text()
old = "            .write_all(bytes)"
new = '            .write_all(&[])\n            .and(Ok({ let _marker = ".write_all(bytes)"; }))?'
if old not in text:
    raise SystemExit("raw write call not found")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_runner_raw_bytes.sh \
    'the raw-write marker surviving only inside a string' mut_runner_raw_write_hidden_in_string

mut_runner_conn_call_bypassed() {
    sed 's/connection\.write(\&head\.bytes)/connection.write(\&[])/' crates/conformance/src/conn.rs \
        >crates/conformance/src/conn.rs.mut
    mv crates/conformance/src/conn.rs.mut crates/conformance/src/conn.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the conn transport bypassing the case head bytes' mut_runner_conn_call_bypassed

mut_runner_body_write_bypassed() {
    sed 's/self\.write(bytes)?/self.write(\&[])?/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'Connection::write_body dropping the declared chunk bytes' mut_runner_body_write_bypassed

mut_runner_chunk_call_bypassed() {
    sed 's/connection\.write_body(bytes)?/connection.write_body(\&[])?/' crates/conformance/src/conn.rs \
        >crates/conformance/src/conn.rs.mut
    mv crates/conformance/src/conn.rs.mut crates/conformance/src/conn.rs
}
expect_fail check_runner_raw_bytes.sh \
    'the conn body loop dropping a declared data chunk' mut_runner_chunk_call_bypassed

mut_runner_raw_connect_bypassed() {
    sed 's/TcpStream::connect(addr)/TcpStream::connect("127.0.0.1:9")/' crates/conformance/src/socket.rs \
        >crates/conformance/src/socket.rs.mut
    mv crates/conformance/src/socket.rs.mut crates/conformance/src/socket.rs
}
expect_fail check_runner_raw_bytes.sh \
    'Connection::open ignoring the selected raw socket address' mut_runner_raw_connect_bypassed

mut_runner_unlisted_client_dependency() {
    printf 'ureq = "3"\n' >>crates/conformance/Cargo.toml
}
expect_fail check_runner_raw_bytes.sh \
    'an unlisted HTTP client dependency bypassing a name deny-list' mut_runner_unlisted_client_dependency

# -----------------------------------------------------------------------------
# check_resolver_pure.sh has four rules and each gets its own control, because
# three of them are regexes over source text and the fourth is an awk field
# extractor — every one of which turns into a no-op from a single typo. The
# properties are worth this much: the resolver runs before authentication, so
# "it cannot await", "it holds no store handle" and "it cannot see a forwarded
# header" are the three sentences standing between an unauthenticated caller and
# either an amplifier or a bucket of somebody else's choosing.
# -----------------------------------------------------------------------------

mut_async_resolver() {
    perl -0pi -e 's/    fn resolve\(&self, query: &HostQuery/    async fn resolve(&self, query: &HostQuery/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a host resolver whose resolve() is async' mut_async_resolver

mut_awaiting_resolver() {
    perl -0pi -e 's/        let host = query\.host\.host_without_port\(\);/        let host = lookup(query).await;/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a host resolver that awaits' mut_awaiting_resolver

mut_resolver_store_handle() {
    perl -0pi -e 's/pub struct VirtualHostStyle \{/pub struct VirtualHostStyle {\n    buckets: std::sync::Arc<dyn BucketStore>,/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a resolver holding a store handle' mut_resolver_store_handle

mut_forwarded_field_on_the_query() {
    perl -0pi -e 's/    \/\/\/ The request method\.\n    pub method: &.a Method,/    \/\/\/ The request method.\n    pub method: &\x27a Method,\n    pub extra: &\x27a str,/' \
        crates/gateway/src/ext/host.rs
}
expect_fail check_resolver_pure.sh \
    'a field added to the resolver input surface' mut_forwarded_field_on_the_query

mut_forwarded_header_read() {
    perl -0pi -e 's/        let host = query\.host\.host_without_port\(\);/        let host = lookup("x-forwarded-host");/' \
        crates/gateway/src/ext/vhost.rs
}
expect_fail check_resolver_pure.sh \
    'a forwarded header named in resolver code' mut_forwarded_header_read

mut_no_resolver_trait_file() {
    rm -f crates/gateway/src/ext/host.rs
}
expect_fail check_resolver_pure.sh \
    'the resolver trait file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_resolver_trait_file

# -----------------------------------------------------------------------------
# check_single_normalization.sh has four rules and each one gets its own
# negative control. The rule this file exists for is the second normalisation:
# a guard that only catches a renamed function would have missed the one that
# was actually here, which was a hand-rolled percent decoder in the conformance
# fixture parsing x-amz-copy-source a second time.
# -----------------------------------------------------------------------------

mut_second_normalisation() {
    printf '\nfn normalize_key(_s: &str) -> String { String::new() }\n' \
        >>crates/core/src/codec/view.rs
}
expect_fail check_single_normalization.sh \
    'a second normalize_key, which is how the two values start to differ' mut_second_normalisation

mut_second_floor() {
    printf '\nfn floor_check_key(_s: &str) -> Result<(), ()> { Ok(()) }\n' \
        >>crates/core/src/codec/value.rs
}
expect_fail check_single_normalization.sh \
    'a second floor_check_key, whose verdict would differ from the real one' mut_second_floor

mut_unallowed_percent_decode() {
    printf '\nfn again(s: &str) -> String {\n    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()\n}\n' \
        >>crates/gateway/src/wire.rs
}
expect_fail check_single_normalization.sh \
    'a percent decoder in a file no allowance covers' mut_unallowed_percent_decode

mut_object_key_deref() {
    printf '\nimpl std::ops::Deref for ObjectKey {\n    type Target = str;\n    fn deref(&self) -> &str { &self.key }\n}\n' \
        >>crates/types/src/scalar/name.rs
}
expect_fail check_single_normalization.sh \
    'a Deref on ObjectKey, which hands the storage layer a &str to re-parse' mut_object_key_deref

mut_lossy_in_scalar() {
    printf '\nfn repair(b: &[u8]) -> String { String::from_utf8_lossy(b).into_owned() }\n' \
        >>crates/types/src/scalar/naming.rs
}
expect_fail check_single_normalization.sh \
    'a lossy decode in the scalar vocabulary, which merges two client inputs' mut_lossy_in_scalar

mut_decoded_utf8_current_is_lossy() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("model/overlays/quirks/naming.toml")
text = path.read_text()
old = 'mutation_dimension = "decoded_utf8"\ncontract_value = "strict"'
new = 'mutation_dimension = "decoded_utf8"\ncontract_value = "lossy"'
if text.count(old) != 1:
    raise SystemExit("decoded_utf8 strict source is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'the typed UTF-8 mutation arm becoming the overlay current' mut_decoded_utf8_current_is_lossy

mut_decoded_utf8_source_is_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("model/overlays/quirks/naming.toml")
text = path.read_text()
old = 'mutation_dimension = "default_slash_policy"'
if text.count(old) != 1:
    raise SystemExit("default slash source is not unique")
path.write_text(text.replace(old, 'mutation_dimension = "decoded_utf8"', 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'a second overlay record claiming the decoded UTF-8 dimension' mut_decoded_utf8_source_is_duplicated

mut_lossy_arm_line_drifts() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path("crates/types/src/scalar/naming.rs")
text = path.read_text()
old = "DecodedUtf8Policy::Lossy => Ok(percent_decode_str(value).decode_utf8_lossy().into_owned()),"
if text.count(old) != 1:
    raise SystemExit("lossy mutation arm is not unique")
path.write_text(text.replace(old, old.replace("Lossy =>", "Lossy  =>"), 1))
PYEOF
}
expect_fail check_single_normalization.sh \
    'the one audited lossy mutation arm drifting from its exact spelling' mut_lossy_arm_line_drifts

mut_drop_percent_decode_allowances() {
    rm -f scripts/allowances/percent-decode-allowances.txt
}
expect_fail check_single_normalization.sh \
    'a missing allowance file, which must fail rather than skip' mut_drop_percent_decode_allowances

# check_authz_consumption.sh guards the type transition, not a call-site convention. Each mutation
# below compiles as plausible framework code and must still make the source guard fail.
mut_dispatch_decoded() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
text = path.read_text()
text = text.replace("authorized: Authorized<O>", "authorized: Decoded<O>", 1)
path.write_text(text)
PYEOF
}
expect_fail check_authz_consumption.sh \
    'dispatch widened back to Decoded<O>' mut_dispatch_decoded

mut_authorized_constructor() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
text = path.read_text()
needle = "impl<O: Operation> Authorized<O> {"
text = text.replace(needle, needle + "\n    pub fn forge(input: O::Input, resources: O::DerivedResources, read: AuthorizedRead) -> Self { Self { input, resources, read } }", 1)
path.write_text(text)
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public Authorized<O> constructor' mut_authorized_constructor

mut_public_read_proof() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
path.write_text(path.read_text().replace("    resources: Vec<OwnedResource>,", "    pub resources: Vec<OwnedResource>,", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a publicly constructible AuthorizedRead proof' mut_public_read_proof

mut_public_authorize_input() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/authz/mod.rs")
path.write_text(path.read_text().replace("pub(crate) fn authorize_input", "pub fn authorize_input", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public function that can mint Authorized<O>' mut_public_authorize_input

mut_public_erased_proof() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/core/src/registry/handlers.rs")
path.write_text(path.read_text().replace("pub struct ErasedRequest(Box<dyn Any + Send>);", "pub struct ErasedRequest(pub Box<dyn Any + Send>);", 1))
PYEOF
}
expect_fail check_authz_consumption.sh \
    'a public erased authorization payload' mut_public_erased_proof
# check_cors_credentials_exclusive.sh has four rules, and the fourth exists only to keep the third
# from being defeated by an import. Each is mutated separately: a single case would leave three of
# them as prose. GHSA-x5xv-223c-8vm7 is the advisory all four are about.

mut_credentials_in_the_reflected_arm() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
# The refactor the guard exists to catch: the credentials writer folded into the function that
# knows about the wildcard forms, with the reflected arm now able to reach it.
text = text.replace(
    "        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard if contracts::cors_wildcard_credentials_omitted() => None,\n        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard => credentials_header(policy, matched.request_origin),",
    "        AllowOrigin::Reflected(value) => Some((ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static(\"true\"))).filter(|_| !value.is_empty()),\n        AllowOrigin::Wildcard => None,",
)
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials header written from the reflected-origin arm' mut_credentials_in_the_reflected_arm

mut_second_credentials_writer() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
text += """
fn a_second_writer() -> (HeaderName, HeaderValue) {
    (ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"))
}
"""
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'a second function writing the credentials header' mut_second_credentials_writer

mut_credentials_written_elsewhere() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text()
text += """
fn a_second_component_writing_credentials() -> &'static str {
    "access-control-allow-credentials"
}
"""
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials header written outside the one answer builder' mut_credentials_written_elsewhere

mut_allow_origin_imported_unqualified() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/core/src/cors/answer.rs")
text = path.read_text()
text = text.replace(
    "use super::rule::{AllowOrigin, RuleMatch};",
    "use super::rule::AllowOrigin::*;\nuse super::rule::{AllowOrigin, RuleMatch};",
)
path.write_text(text)
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    "AllowOrigin's variants imported unqualified, which would blind rule 3" mut_allow_origin_imported_unqualified

mut_credentials_constant_renamed() {
    python3 - <<'PYEOF'
import pathlib
# The guard's subject renamed out from under it. Rules 2 and 3 would then be checking nothing,
# which must be a failure and not a pass.
for name in ("crates/core/src/cors/answer.rs", "crates/core/src/cors/mod.rs", "crates/gateway/src/lib.rs"):
    path = pathlib.Path(name)
    path.write_text(path.read_text().replace("ACCESS_CONTROL_ALLOW_CREDENTIALS", "ALLOW_CREDS"))
PYEOF
}
expect_fail check_cors_credentials_exclusive.sh \
    'the credentials constant renamed, leaving the guard with nothing to check' mut_credentials_constant_renamed

# -----------------------------------------------------------------------------
# check_no_minio_source.sh
#
# The clean-room provenance guard. Rule 1 (AGPL licence text) is exemptable through
# scripts/allowances/clean-room-allowances.txt, so it gets two cases: one for a file
# that is not on the list, and one proving the list is read as a list of paths rather
# than as a licence to say anything anywhere. Rules 2, 3 and 4 have no exemption.
#
# The licence text and the provenance sentence are written with byte escapes, the same
# device the Chinese cases above use and for the same reason: spelling them literally
# would make the guard flag this file, and allowing this file would then let real AGPL
# text and a real port comment sit here unnoticed forever. `\x41` is `A` and `\x6f` is
# `o`, so the strings reach the sandbox intact and are absent from this source.
# -----------------------------------------------------------------------------

mut_agpl_licence_text() {
    printf '\n// Licensed under the GNU \x41FFERO GENERAL PUBLIC LICENSE Version 3\n' \
        >>crates/core/src/dialect/overlay.rs
}
expect_fail check_no_minio_source.sh \
    'AGPL licence text in a source file' mut_agpl_licence_text

mut_agpl_in_unlisted_prose() {
    printf 'This component is offered under \x41GPL-3.0.\n' >crates/core/PROVENANCE.md
}
expect_fail check_no_minio_source.sh \
    'a file naming the AGPL that the allowance list does not carry' mut_agpl_in_unlisted_prose

mut_port_provenance_comment() {
    printf '\n// The ordering above was p\x6frted from the minio server bucket handler.\n' \
        >>crates/core/src/dialect/mod.rs
}
expect_fail check_no_minio_source.sh \
    'a comment giving the contents a MinIO-server origin' mut_port_provenance_comment

mut_vendored_server_tree() {
    mkdir -p vendor/github.com/minio/minio/cmd
    printf 'package cmd\n' >vendor/github.com/minio/minio/cmd/api-router.go
}
expect_fail check_no_minio_source.sh \
    'a vendored MinIO server tree' mut_vendored_server_tree

mut_minio_submodule() {
    printf '[submodule "minio"]\n\tpath = third_party/minio\n\turl = https://github.com/minio/minio.git\n' \
        >.gitmodules
}
expect_fail check_no_minio_source.sh \
    'the MinIO server declared as a git submodule' mut_minio_submodule

mut_clean_room_allowance_widened() {
    # The allowance list turned into a blanket permission. The guard reads it as a list of
    # paths, so a glob is not a path and the offending file is still reported -- which is the
    # behaviour under test: widening the list must not silence rule 1 for everything.
    printf '*\n' >scripts/allowances/clean-room-allowances.txt
    printf 'Offered under the \x41ffero General Public License.\n' >crates/core/PROVENANCE.md
}
expect_fail check_no_minio_source.sh \
    'an allowance list widened to a glob, which is not a path' mut_clean_room_allowance_widened

mut_tracked_symlink_to_ignored_agpl() {
    mkdir -p ignored-provenance crates/core/src/dialect
    printf 'ignored-provenance/\n' >>.gitignore
    printf '// GNU \x41FFERO GENERAL PUBLIC LICENSE Version 3\n' \
        >ignored-provenance/hidden.rs
    ln -s ../../../../ignored-provenance/hidden.rs crates/core/src/dialect/tracked-link.rs
}
expect_fail check_no_minio_source.sh \
    'a tracked Rust symlink resolving to ignored AGPL source' mut_tracked_symlink_to_ignored_agpl

mut_broken_tracked_source_symlink() {
    ln -s missing-provenance.rs crates/core/src/dialect/broken-source-link.rs
}
expect_fail check_no_minio_source.sh \
    'a broken tracked source symlink whose content cannot be inspected' mut_broken_tracked_source_symlink

mut_binary_tracked_manifest() {
    mkdir -p crates/binary-manifest
    printf '[package]\nname = "binary-manifest"\n\0\nminio = "forbidden"\n' \
        >crates/binary-manifest/Cargo.toml
}
expect_fail check_no_minio_source.sh \
    'a tracked NUL-bearing Cargo.toml hiding a minio dependency' mut_binary_tracked_manifest

mut_binary_untracked_manifest() {
    mkdir -p untracked-binary-manifest
    printf '[package]\nname = "binary-manifest"\n\0\nminio = "forbidden"\n' \
        >untracked-binary-manifest/Cargo.toml
}
expect_fail_unstaged check_no_minio_source.sh \
    'an untracked NUL-bearing Cargo.toml hiding a minio dependency' mut_binary_untracked_manifest

SCANNER_TOOLS=(grep rg awk sed perl find git)

write_scanner_shim() {
    local shim_dir="$1" scanner="$2" real dispatch
    real="$(command -v "$scanner" 2>/dev/null)" || real=""
    [[ -z "$real" || -x "$real" ]] || return 1
    if [[ -n "$real" ]]; then
        dispatch="exec \"${real}\" \"\$@\""
    else
        dispatch='exit 127'
    fi
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        ': "${GATEWAY_SCANNER_COUNT_DIR:?}"' \
        "printf '.\\n' >>\"\${GATEWAY_SCANNER_COUNT_DIR}/${scanner}\"" \
        "$dispatch" >"${shim_dir}/${scanner}"
    chmod +x "${shim_dir}/${scanner}"
}

prepare_scanner_shims() {
    local shim_dir="$1" scanner
    for scanner in "${SCANNER_TOOLS[@]}"; do
        write_scanner_shim "$shim_dir" "$scanner" || return 1
    done
}

validate_scanner_shims() {
    local shim_dir="$1" count_dir="$2" scanner
    for scanner in "${SCANNER_TOOLS[@]}"; do
        rm -f "${count_dir}/${scanner}"
        PATH="${shim_dir}:${PATH}" GATEWAY_SCANNER_COUNT_DIR="$count_dir" \
            "${shim_dir}/${scanner}" </dev/null >/dev/null 2>&1 || true
        [[ -s "${count_dir}/${scanner}" ]] || return 1
        : >"${count_dir}/${scanner}"
    done
}

scanner_process_count() {
    local count_dir="$1" scanner line total=0
    for scanner in "${SCANNER_TOOLS[@]}"; do
        while IFS= read -r line; do
            total=$((total + 1))
        done <"${count_dir}/${scanner}"
    done
    printf '%s\n' "$total"
}

scanner_budget_case() {
    local guard="$1" ceiling="$2" expectation="$3" desc="$4" mutate="${5:-}"
    local sandbox shim_dir count_dir rc=0 observed
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    if [[ -n "$mutate" ]]; then
        (cd "$sandbox" && "$mutate" >/dev/null)
    fi
    shim_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-shims.XXXXXX")"
    count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-counts.XXXXXX")"
    if ! prepare_scanner_shims "$shim_dir" || ! validate_scanner_shims "$shim_dir" "$count_dir"; then
        fail_msg "scanner process harness could not validate every shim: ${desc}"
        rm -rf "$shim_dir" "$count_dir"
        return
    fi
    GATEWAY_CHECK_ROOT="$sandbox" PATH="${shim_dir}:${PATH}" GATEWAY_SCANNER_COUNT_DIR="$count_dir" \
        "$sandbox/scripts/$guard" >/dev/null 2>&1 || rc=$?
    observed="$(scanner_process_count "$count_dir")"
    rm -rf "$shim_dir" "$count_dir"

    if [[ "$rc" -ne 0 ]]; then
        fail_msg "${guard} failed for the wrong reason while measuring scanner processes: ${desc}"
    elif [[ "$expectation" == within && "$observed" -le "$ceiling" ]]; then
        pass_msg "${guard} uses ${observed}/${ceiling} scanner processes: ${desc}"
    elif [[ "$expectation" == over && "$observed" -gt "$ceiling" ]]; then
        pass_msg "${guard} exceeds ${ceiling} scanner processes after mutation (${observed}): ${desc}"
    else
        fail_msg "${guard} scanner process count ${observed} did not satisfy ${expectation} ceiling ${ceiling}: ${desc}"
    fi
}

insert_guard_probe() {
    local path="$1" probe="$2"
    python3 - "$path" "$probe" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
probe = sys.argv[2]
text = path.read_text()
marker = '\nexit "$status"\n'
if text.count(marker) != 1:
    raise SystemExit("guard exit marker is missing or ambiguous")
path.write_text(text.replace(marker, f"\n{probe}\nexit \"$status\"\n"))
PYEOF
}

mut_single_per_candidate_scan() {
    insert_guard_probe scripts/check_single_normalization.sh $'for candidate in "${sources[@]}"; do\n    grep -E "never-match" "$candidate" >/dev/null || true\ndone'
}

mut_no_minio_candidate_slice_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    git grep -E "never-match" -- "$candidate" >/dev/null || true\ndone'
}

mut_no_minio_wrapper_alias_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'GREP=grep\nscan_candidate() { "${GREP}" -E "never-match" "$1" >/dev/null || true; }\nfor candidate in "${content_files[@]:0:64}"; do\n    scan_candidate "$candidate"\ndone'
}

mut_no_minio_rg_scan() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    rg "never-match" "$candidate" >/dev/null || true\ndone'
}

absolute_scanner_path_case() {
    local expectation="$1" desc="$2" mutate="${3:-}" sandbox hits rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
    if [[ -n "$mutate" ]]; then
        (cd "$sandbox" && "$mutate" >/dev/null)
    fi
    hits="$(mktemp "${TMPDIR:-/tmp}/gateway-absolute-scanner-hits.XXXXXX")"
    if grep -nE '/[^[:space:]]*/(grep|rg|awk|sed|perl|find|git)([^[:alnum:]_.-]|$)' \
        "$sandbox/scripts/check_single_normalization.sh" \
        "$sandbox/scripts/check_no_minio_source.sh" >"$hits"; then
        rc=0
    else
        rc=$?
    fi
    if [[ "$rc" -gt 1 ]]; then
        fail_msg "absolute scanner path check could not inspect both target guards: ${desc}"
    elif [[ "$expectation" == clean && "$rc" -eq 1 ]]; then
        pass_msg "target guards contain no literal absolute scanner path: ${desc}"
    elif [[ "$expectation" == caught && "$rc" -eq 0 ]]; then
        pass_msg "target guards reject a literal absolute scanner path: ${desc}"
    else
        fail_msg "absolute scanner path check did not satisfy ${expectation}: ${desc}"
    fi
    rm -f "$hits"
}

mut_absolute_scanner_path() {
    insert_guard_probe scripts/check_no_minio_source.sh $'for candidate in "${content_files[@]:0:64}"; do\n    /usr/bin/grep -E "never-match" "$candidate" >/dev/null || true\ndone'
}

scanner_budget_case check_single_normalization.sh 21 within \
    'the repository-wide source corpus is scanned in constant process count'
scanner_budget_case check_no_minio_source.sh 12 within \
    'tracked, untracked, symlink and manifest scans stay batched'
scanner_budget_case check_single_normalization.sh 21 over \
    'a scanner process restored for every source candidate' mut_single_per_candidate_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate loop hidden behind an array slice' mut_no_minio_candidate_slice_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate scanner hidden behind a wrapper and command alias' mut_no_minio_wrapper_alias_scan
scanner_budget_case check_no_minio_source.sh 12 over \
    'a per-candidate scanner switched from grep to rg' mut_no_minio_rg_scan
absolute_scanner_path_case clean \
    'PATH shims remain the only scanner resolution path'
absolute_scanner_path_case caught \
    'an absolute grep path cannot bypass the process counter' mut_absolute_scanner_path

cases=$((cases + 1))
missing_shim_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing.XXXXXX")"
missing_count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-count.XXXXXX")"
if prepare_scanner_shims "$missing_shim_dir"; then
    rm -f "${missing_shim_dir}/grep"
fi
if validate_scanner_shims "$missing_shim_dir" "$missing_count_dir"; then
    fail_msg 'scanner process harness reported green with a missing grep shim'
else
    pass_msg 'scanner process harness fails closed when a shim is missing'
fi
rm -rf "$missing_shim_dir" "$missing_count_dir"

cases=$((cases + 1))
missing_tool_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-tool.XXXXXX")"
missing_tool_count_dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-scanner-missing-tool-count.XXXXXX")"
missing_tool_rc=0
if write_scanner_shim "$missing_tool_dir" gateway-scanner-tool-that-does-not-exist; then
    GATEWAY_SCANNER_COUNT_DIR="$missing_tool_count_dir" \
        "$missing_tool_dir/gateway-scanner-tool-that-does-not-exist" \
        >/dev/null 2>&1 || missing_tool_rc=$?
fi
if [[ "$missing_tool_rc" -ne 0 \
    && -s "$missing_tool_count_dir/gateway-scanner-tool-that-does-not-exist" ]]; then
    pass_msg 'scanner process harness counts a missing scanner tool and fails closed'
else
    fail_msg 'scanner process harness reported green or did not count a missing scanner tool'
fi
rm -rf "$missing_tool_dir" "$missing_tool_count_dir"
# check_stage_filter_sync.sh has four rules and each one gets its own negative
# control, for the reason check_resolver_pure.sh's do: two of the three seams
# run before the request has been authenticated, so "it cannot await", "it holds
# no store handle", "there are exactly these three seams" and "it cannot reach
# the method, the target or the routed bucket" are the four sentences standing
# between a deployment's own rewrite and a pre-authentication storage read or a
# forged signature input.
# -----------------------------------------------------------------------------

mut_async_seam() {
    perl -0pi -e 's/    fn on_wire\(&self, _head: &mut WireHead/    async fn on_wire(&self, _head: &mut WireHead/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a StageFilter seam declared async' mut_async_seam

mut_awaiting_filter() {
    perl -0pi -e 's/        \(\*\*self\)\.on_wire\(head\)/        lookup().await;\n        (**self).on_wire(head)/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a StageFilter implementation that awaits' mut_awaiting_filter

mut_filter_store_handle() {
    perl -0pi -e 's/pub struct WireHead<.a> \{/pub struct WireHead<\x27a> {\n    buckets: std::sync::Arc<dyn BucketStore>,/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a store handle in a guarded StageFilter file' mut_filter_store_handle

mut_fourth_seam() {
    perl -0pi -e 's/    fn on_routed\(&self, _routed: &RoutedView/    fn on_body(&self, _routed: &RoutedView<\x27_>) -> Result<\(\), S3Error> {\n        Ok\(\(\)\)\n    }\n\n    fn on_routed(&self, _routed: &RoutedView/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a fourth seam added to the trait without an argument for it' mut_fourth_seam

mut_writable_routed_view() {
    perl -0pi -e 's/    \/\/\/ The bucket, from the one place a bucket is produced\./    pub fn bucket_mut(&mut self) -> Option<&mut BucketName> {\n        None\n    }\n\n    \/\/\/ The bucket, from the one place a bucket is produced./' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a mutable accessor on RoutedView, which would be a second producer of the target' mut_writable_routed_view

mut_head_target_setter() {
    perl -0pi -e 's/    \/\/\/ The frozen check, in one place/    pub fn set_path(&mut self, _path: \&str) {}\n\n    \/\/\/ The frozen check, in one place/' \
        crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'a request-target setter on WireHead, which the frozen header snapshot does not cover' mut_head_target_setter

mut_no_filter_trait_file() {
    rm -f crates/gateway/src/ext/filter.rs
}
expect_fail check_stage_filter_sync.sh \
    'the StageFilter trait file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_filter_trait_file

# -----------------------------------------------------------------------------
# check_patch_layer_map.sh is checked in both directions plus the count, because
# the failure it exists to prevent is silent: a renamed test leaves the table
# saying what it said, and the table is what P10-06 deletes nine tower layers
# against.
# -----------------------------------------------------------------------------

mut_orphan_table_row() {
    perl -0pi -e 's/`bodyless_status_fix_is_the_response_invariant`/`bodyless_status_fix_renamed_away`/' \
        docs/middleware.md
}
expect_fail check_patch_layer_map.sh \
    'a table row naming a test that does not exist' mut_orphan_table_row

mut_orphan_test() {
    printf '\n/// A landing with no row.\n#[test]\nfn a_tenth_landing_nobody_wrote_down() {}\n' \
        >>crates/gateway/tests/patch_layer_landings.rs
}
expect_fail check_patch_layer_map.sh \
    'a landing test with no row in the table' mut_orphan_test

mut_deleted_table_row() {
    perl -0ni -e 's/^\| 3 \|.*\n//m; print' docs/middleware.md
}
expect_fail check_patch_layer_map.sh \
    'a landing row deleted, leaving eight layers accounted for out of nine' mut_deleted_table_row

mut_no_landing_test_file() {
    rm -f crates/gateway/tests/patch_layer_landings.rs
}
expect_fail check_patch_layer_map.sh \
    'the landings file missing entirely (a guard whose input is gone must fail, not skip)' mut_no_landing_test_file
# check_sse_key_never_leaks.sh has five rules over the SSE-C customer key, plus the missing-input
# rule every guard owes. Each is mutated separately: one case would leave four of them as prose.
# rustfs/backlog#1751 is the task all six are about, and GHSA-8cm2-h255-v749 is what a key in a log
# line looks like once it has happened.

mut_sse_key_bound_as_an_output() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("spec/operations/PutObject.toml")
# The generated encoder that would write the key onto the response, spelled the way the emitter
# spells one.
path.write_text(path.read_text() + """
[[output]]
name = "SSECustomerKey"
wire_name = "x-amz-server-side-encryption-customer-key"
binding = "Header"
type = "String"
required = false
hot = false
quirks = []
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'an operation output binding the customer key header' mut_sse_key_bound_as_an_output

mut_sse_copy_source_key_dropped_from_the_list() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/headers.rs")
# The half of the list nobody looks at: a CopyObject's source-side key.
path.write_text(path.read_text().replace(
    "pub const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY, COPY_SSEC_KEY];",
    "pub const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY];",
))
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'the copy-source key dropped from the never-echoed list' mut_sse_copy_source_key_dropped_from_the_list

mut_sse_response_strip_removed() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/gateway/src/invariants.rs")
# The strip deleted from the one place every response passes through.
path.write_text(path.read_text().replace(
    "    for name in rustfs_gateway_core::sse::NEVER_IN_A_RESPONSE {",
    "    for name in [] as [&str; 0] {",
))
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'the response invariant no longer stripping the customer-key headers' mut_sse_response_strip_removed

mut_sse_second_expose_call_site() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/mod.rs")
path.write_text(path.read_text() + """
fn a_second_reader(text: &headers::KeyText<'_>) -> usize {
    text.expose().len()
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a second reader of the customer key text' mut_sse_second_expose_call_site

mut_sse_second_choice_to_bool() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/core/src/sse/consistency.rs")
path.write_text(path.read_text() + """
fn a_second_escape_hatch(choice: subtle::Choice) -> bool {
    bool::from(choice)
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a second subtle::Choice-to-bool conversion in the SSE module' mut_sse_second_choice_to_bool

mut_sse_key_in_a_log_line() {
    python3 - <<'SSEPY'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
path.write_text(path.read_text() + """
fn an_operator_friendly_diagnostic(customer_key: &str) -> String {
    format!("rejected the customer_key {customer_key}")
}
""")
SSEPY
}
expect_fail check_sse_key_never_leaks.sh \
    'a formatting macro naming the customer key' mut_sse_key_in_a_log_line

mut_sse_headers_module_deleted() {
    rm -f crates/core/src/sse/headers.rs
}
expect_fail check_sse_key_never_leaks.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_sse_headers_module_deleted

mut_clock_second_wall_reading() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
# The shape this guard exists for: a second reading taken half way down the
# pipeline, so the skew check and the expiry check judge two different presents.
path.write_text(path.read_text() + """
fn a_second_present() -> std::time::SystemTime {
    std::time::SystemTime::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'a second wall-clock reading inside the pipeline' mut_clock_second_wall_reading

mut_clock_stray_monotonic_reading() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/core/src/lib.rs")
path.write_text(path.read_text() + """
fn a_stray_stopwatch() -> std::time::Instant {
    std::time::Instant::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'a monotonic reading taken outside the monotonic source' mut_clock_stray_monotonic_reading

mut_clock_wall_source_reads_the_monotonic_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/sig/src/clock.rs")
# Mixing the two: signature expiry judged against a source with no absolute time.
path.write_text(path.read_text() + """
fn expiry_on_a_stopwatch() -> std::time::Instant {
    std::time::Instant::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'the wall-clock source reading the monotonic clock' mut_clock_wall_source_reads_the_monotonic_clock

mut_clock_monotonic_source_reads_the_wall_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/gateway/src/clock.rs")
# The other direction: a rate limiter an NTP step can steer.
path.write_text(path.read_text() + """
fn refill_on_the_wall_clock() -> std::time::SystemTime {
    std::time::SystemTime::now()
}
""")
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    'the monotonic source reading the wall clock' mut_clock_monotonic_source_reads_the_wall_clock

mut_clock_wall_source_stops_reading_the_clock() {
    python3 - <<'CLOCKPY'
import pathlib
path = pathlib.Path("crates/sig/src/clock.rs")
# The subject refactored away. The guard must fail rather than pass vacuously.
path.write_text(path.read_text().replace("std::time::SystemTime::now()", "SOME_OTHER_SOURCE.read()"))
CLOCKPY
}
expect_fail check_clock_single_source.sh \
    "the guard's own subject refactored away, which must fail rather than skip" \
    mut_clock_wall_source_stops_reading_the_clock

mut_clock_monotonic_source_deleted() {
    rm -f crates/gateway/src/clock.rs
}
expect_fail check_clock_single_source.sh \
    "the monotonic source deleted, which must fail rather than skip" mut_clock_monotonic_source_deleted

mut_governor_sync_path_allocates() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
text = path.read_text()
needle = "    pub fn try_acquire_sync(&self, request: &GovernorRequest<'_>) -> Option<Lease> {"
path.write_text(text.replace(needle, needle + "\n        let _allocation = Box::new(0_u8);", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'an allocation added to the synchronous governor path' mut_governor_sync_path_allocates

mut_governor_single_client_lock() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
path.write_text(path.read_text().replace("const CLIENT_SHARDS: usize = 32;", "const CLIENT_SHARDS: usize = 1;", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'the address table collapsed to one lock' mut_governor_single_client_lock

mut_governor_user_replaces_framework() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/builder.rs")
path.write_text(path.read_text().replace(
    "Arc::new(LayeredGovernor::new(framework_governor, user))",
    "user",
    1,
))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'a user governor replacing the framework governor' mut_governor_user_replaces_framework

mut_governor_request_constructor_public() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor.rs")
path.write_text(path.read_text().replace("pub(crate) const fn new(", "pub const fn new(", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'GovernorRequest construction exposed to extensions' mut_governor_request_constructor_public

mut_governor_client_map_allocates_on_demand() {
    python3 - <<'GOVPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/governor/default.rs")
path.write_text(path.read_text().replace("HashMap::with_capacity(capacity)", "HashMap::new()", 1))
GOVPY
}
expect_fail check_governor_fast_path.sh \
    'client-map allocation moved into the decision path' mut_governor_client_map_allocates_on_demand
# check_secret_hygiene.sh has six rules over the credential containers in crates/gateway/src/ext/,
# which is outside the path scope of check_ct_eq.sh rules 3-6. Each is mutated separately, because
# one case would leave the other five as prose. rustfs/backlog#1736 is the task, and
# GHSA-333v-68xh-8mmq is what a secret in a diagnostic looks like once it has happened.

mut_credentials_debug_derived() {
    python3 - <<'CREDPY'
import pathlib, re
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
text = path.read_text()
# The redacting Debug deleted and the derive put back — the whole leak in two edits.
text = re.sub(r"impl core::fmt::Debug for Credentials \{.*?\n\}\n", "", text, flags=re.S)
text = text.replace("pub struct Credentials {", "#[derive(Debug)]\npub struct Credentials {")
path.write_text(text)
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'the redacting Debug on Credentials replaced by a derive' mut_credentials_debug_derived

# ── check_authz_fail_closed.sh (P6-02) ─────────────────────────────────────────

expect_authz_fail_minimal() {
    local desc="$1" mutate="$2" expected="$3"
    local sandbox file output tool rc=0
    local -a sources=(
        crates/core/src/authz/mod.rs
        crates/core/tests/registration.rs
        crates/gateway/src/ext/authorizer.rs
        crates/gateway/src/ext/authz_audit.rs
        crates/gateway/src/ext/mod.rs
        crates/gateway/src/service.rs
        crates/gateway/examples/custom_authorizer.rs
        crates/gateway/examples/minimal.rs
        crates/gateway/tests/assembly.rs
        crates/gateway/tests/authz_consumption.rs
        crates/gateway/tests/authz_contract.rs
        crates/gateway/tests/authz_contract/oracle.rs
        crates/gateway/tests/authz_implementations.rs
        crates/gateway/tests/compile_fail/azc_0014_missing_input.rs
        crates/gateway/tests/compile_fail/azc_0015_forge_authorized.rs
        crates/gateway/tests/compile_fail/azc_0016_denial_code.rs
        crates/gateway/tests/compile_fail/azc_0020_service_config_default.rs
        crates/gateway/tests/compile_fail/azc_0021_allow_all.rs
        crates/gateway/tests/compile_fail/azc_0025_request_extensions.rs
    )

    cases=$((cases + 1))
    for tool in awk bash cat cp dirname git grep mkdir mktemp python3 rm sort tr; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail_msg "check_authz_fail_closed.sh cannot test ${desc}; required command is missing: ${tool}"
            return
        fi
    done
    if [[ ! -f "${SCRIPT_DIR}/check_authz_fail_closed.sh" ]]; then
        fail_msg "check_authz_fail_closed.sh cannot test ${desc}; the real guard source is missing"
        return
    fi
    for file in "${sources[@]}"; do
        if [[ ! -f "${REPO_ROOT}/${file}" ]]; then
            fail_msg "check_authz_fail_closed.sh cannot test ${desc}; required source is missing: ${file}"
            return
        fi
    done

    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/gateway-authz-guard.XXXXXX")" || {
        fail_msg "check_authz_fail_closed.sh cannot create its fixture: ${desc}"
        return
    }
    if ! mkdir -p "$sandbox/scripts" ||
        ! cp "${SCRIPT_DIR}/check_authz_fail_closed.sh" "$sandbox/scripts/"; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh fixture initialization failed: ${desc}"
        return
    fi
    for file in "${sources[@]}"; do
        if ! mkdir -p "$(dirname "$sandbox/$file")" ||
            ! cp "${REPO_ROOT}/${file}" "$sandbox/$file"; then
            rm -rf "$sandbox"
            fail_msg "check_authz_fail_closed.sh fixture initialization failed while copying ${file}: ${desc}"
            return
        fi
    done
    if ! git -C "$sandbox" init -q ||
        ! git -C "$sandbox" add -A; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh fixture Git initialization failed: ${desc}"
        return
    fi

    output="$(GATEWAY_CHECK_ROOT="$sandbox" bash "$sandbox/scripts/check_authz_fail_closed.sh" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh rejects its unmutated source closure: ${desc}"
        printf '%s\n' "$output" >&2
        return
    fi
    if ! (cd "$sandbox" && "$mutate" >/dev/null); then
        rm -rf "$sandbox"
        fail_msg "check_authz_fail_closed.sh mutation setup failed: ${desc}"
        return
    fi

    rc=0
    output="$(GATEWAY_CHECK_ROOT="$sandbox" bash "$sandbox/scripts/check_authz_fail_closed.sh" 2>&1)" || rc=$?
    rm -rf "$sandbox"
    if [[ "$rc" -ne 0 && "$output" == *"$expected"* ]]; then
        pass_msg "check_authz_fail_closed.sh catches: ${desc}"
    else
        fail_msg "check_authz_fail_closed.sh did not report its expected violation: ${desc}"
        printf '%s\n' "$output" >&2
    fi
}

mut_a_fourth_verdict_state() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("    Indeterminate,\n}", "    Indeterminate,\n    Unknown,\n}", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a fourth Decision state, which no interpretation site was written for' \
    mut_a_fourth_verdict_state 'Decision declares [Allow Deny Indeterminate Unknown]'

mut_decision_from_a_bool() {
    cat >>crates/gateway/src/ext/mod.rs <<'AZEOF'

impl Default for Decision {
    fn default() -> Self {
        Self::Allow
    }
}
AZEOF
}
expect_authz_fail_minimal \
    'a Default impl for Decision, so a verdict nobody reached becomes Allow' \
    mut_decision_from_a_bool 'an impl of Default or From for Decision'

mut_a_second_interpretation_site() {
    cat >>crates/gateway/src/service.rs <<'AZEOF'

fn interpret(verdict: crate::ext::Decision) -> bool {
    match verdict {
        crate::ext::Decision::Allow => true,
        crate::ext::Decision::Deny => false,
        crate::ext::Decision::Indeterminate => true,
    }
}
AZEOF
}
expect_authz_fail_minimal \
    'a second place deciding what a verdict means, reading Indeterminate as allow' \
    mut_a_second_interpretation_site 'matches on a Decision variant'

mut_a_wildcard_in_settle() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("            Self::Deny | Self::Indeterminate => Err(Denied { decision: self }),",
              "            _ => Err(Denied { decision: self }),", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a wildcard arm in settle, so a later state inherits a branch nobody chose for it' \
    mut_a_wildcard_in_settle 'settle has a wildcard arm'

mut_a_denial_that_picks_its_code() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/core/src/authz/mod.rs")
s = p.read_text()
s = s.replace("impl Denied {\n", "impl Denied {\n    pub fn with_code(code: ErrorCode) -> Self {\n        let _ = code;\n        Self { decision: Decision::Deny }\n    }\n\n", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'a Denial constructor taking an ErrorCode, which is a private-bucket enumeration oracle' \
    mut_a_denial_that_picks_its_code 'a Denial constructor takes an ErrorCode'

mut_an_audit_sink_that_answers() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/ext/authz_audit.rs")
s = p.read_text()
s = s.replace("    fn on_decision(&self, event: &AuthzAuditEvent<'_>);",
              "    fn on_decision(&self, event: &AuthzAuditEvent<'_>) -> Decision;", 1)
p.write_text(s)
AZPY
}
expect_authz_fail_minimal \
    'an audit sink whose method returns a verdict, so the hook could overturn the decision' \
    mut_an_audit_sink_that_answers 'an AuthzAuditSink method returns a value or takes a mutable reference'

mut_an_allow_all_example() {
    cat >>crates/gateway/examples/minimal.rs <<'AZEOF'

fn convenient() -> impl rustfs_gateway::Authorizer {
    rustfs_gateway::allow_when(|_| true)
}
AZEOF
}
expect_authz_fail_minimal \
    'a copy-pasteable allow-all in an example, which is API' \
    mut_an_allow_all_example 'an example ships an unconditional allow'
expect_fail check_no_allow_all_in_examples.sh \
    'a copy-pasteable allow-all in an example' mut_an_allow_all_example

mut_authorizer_module_deleted() {
    rm -f crates/gateway/src/ext/authorizer.rs
}
expect_authz_fail_minimal \
    "the guard's own subject deleted, which must fail rather than skip" \
    mut_authorizer_module_deleted 'authorizer.rs does not exist; the guard cannot find the surface it is written about'

mut_an_authz_case_removed() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/tests/authz_contract.rs")
p.write_text(p.read_text().replace("c-azc-0030", "removed-case", 1))
AZPY
}
expect_authz_fail_minimal \
    'one of the thirty executable authorization cases removed' \
    mut_an_authz_case_removed 'the executable authorization matrix is not exactly c-azc-0001 through c-azc-0030'

# ── check_policy_snapshot_once.sh (P6-02) ──────────────────────────────────────

mut_a_second_reading_in_the_pipeline() {
    cat >>crates/gateway/src/service.rs <<'AZEOF'

async fn reread(inner: &Inner) {
    let _ = inner.policy_source.snapshot(None).await;
}
AZEOF
}
expect_fail check_policy_snapshot_once.sh \
    'a second reading of policy inside the pipeline crate' mut_a_second_reading_in_the_pipeline

mut_a_reading_outside_the_pipeline() {
    cat >>crates/gateway/src/dispatch.rs <<'AZEOF'

async fn own_view(source: &dyn crate::ext::PolicySource) {
    let _ = source.snapshot(None).await;
}
AZEOF
}
expect_fail check_policy_snapshot_once.sh \
    'a stage reading its own view of policy instead of the one it was handed' mut_a_reading_outside_the_pipeline

mut_the_reading_taken_after_the_reader() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/service.rs")
lines = p.read_text().splitlines(keepends=True)
# An authorize call above the snapshot: the reading is then not the one the
# reader used, whatever the response looks like.
lines.insert(14, "fn early(a: &dyn crate::ext::Authorizer) { let _ = |c, r| a.authorize_route(c, r); }\n")
p.write_text("".join(lines))
AZPY
}
expect_fail check_policy_snapshot_once.sh \
    'the policy reading taken after the authorizer has already run' mut_the_reading_taken_after_the_reader

mut_policy_module_deleted() {
    rm -f crates/gateway/src/ext/policy.rs
}
expect_fail check_policy_snapshot_once.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_policy_module_deleted

# ── check_authz_no_default_impl.sh (P6-02) ─────────────────────────────────────

mut_authorize_route_default_body() {
    python3 - <<'AZPY'
import pathlib
p = pathlib.Path("crates/gateway/src/ext/authorizer.rs")
s = p.read_text()
s = s.replace(
    ") -> BoxFuture<'a, Decision>;",
    ") -> BoxFuture<'a, Decision> { Box::pin(async { Decision::Deny }) }",
    1,
)
p.write_text(s)
AZPY
}
expect_fail check_authz_no_default_impl.sh \
    'a default body on authorize_route' mut_authorize_route_default_body

# -----------------------------------------------------------------------------
# P7-06. An operation scaffold is deliberately red while it is being implemented,
# but the exact marker must never survive into a merge. Both tracked and brand-new
# files are controls because a guard that only reads the index misses the latter.
# -----------------------------------------------------------------------------

mut_scaffold_marker_in_module() {
    printf '\n// SCAF%s\n' 'FOLD: implement before merge' >>crates/core/src/ops/mod.rs
}
expect_fail check_no_scaffold_on_main.sh \
    'a scaffold marker inserted into an existing operation module' mut_scaffold_marker_in_module

mut_untracked_scaffold_marker() {
    printf '// SCAF%s\n' 'FOLD: implement before merge' >crates/core/tests/scaffold_untracked.rs
}
expect_fail_unstaged check_no_scaffold_on_main.sh \
    'a scaffold marker in a new unstaged test file' mut_untracked_scaffold_marker

# The operation-to-test map is codegen-owned. A guard that checks only its header
# accepts a hand-edited body, while a guard that regenerates in memory catches it.
mut_verify_map_edited() {
    printf '\n# hand-edited mapping\n' >>xtask/verify-map.toml
}
expect_fail check_verify_map_generated.sh \
    'a manual edit to the generated operation verification map' mut_verify_map_edited

mut_verify_map_deleted() {
    rm -f xtask/verify-map.toml
}
expect_fail check_verify_map_generated.sh \
    'the generated operation verification map being absent' mut_verify_map_deleted

# Tool pins are one reviewable block. Test a moving version, a missing pin and the
# explicitly rejected installer independently so each assertion has gone red.
mut_tool_version_latest() {
    sed 's/cargo-hack@0\.6\.45/cargo-hack@latest/' .github/workflows/ci.yml >.github/workflows/ci.yml.mut
    mv .github/workflows/ci.yml.mut .github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'a CI tool pin changed to latest' mut_tool_version_latest

mut_tool_pin_deleted() {
    grep -v 'CARGO_DENY_TOOL:' .github/workflows/ci.yml >.github/workflows/ci.yml.mut
    mv .github/workflows/ci.yml.mut .github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'one of the six CI tool pins being removed' mut_tool_pin_deleted

mut_cargo_binstall_added() {
    printf '\n# cargo install cargo-%s\n' 'binstall' >>.github/workflows/ci.yml
}
expect_fail check_tool_versions_pinned.sh \
    'cargo-binstall introduced into the CI workflow' mut_cargo_binstall_added

mut_credentials_display() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
impl core::fmt::Display for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.identity().access_key_id())
    }
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'a Display implementation on Credentials' mut_credentials_display
# P7-05 documentation/context guards. Each acceptance rule has an explicit mutation so a green
# guard proves both directions rather than merely describing the current tree.
mut_map_deleted() {
    rm -f crates/xml/MAP.md
}
expect_fail check_map_files.sh \
    'a workspace crate losing its MAP.md' mut_map_deleted

mut_map_too_long() {
    for _ in $(seq 1 101); do printf 'extra\n' >>crates/xml/MAP.md; done
}
expect_fail check_map_files.sh \
    'a MAP.md growing beyond the 100-line entry-point budget' mut_map_too_long

mut_map_recommends_generated() {
    printf '| `generated/**` | generated details | Read it when debugging |\n' >>crates/xml/MAP.md
}
expect_fail check_map_files.sh \
    'a MAP.md directing an agent into generated output' mut_map_recommends_generated

mut_module_doc_loses_boundary() {
    sed '/NOT responsible for:/d' xtask/src/main.rs >xtask/src/main.rs.mut
    mv xtask/src/main.rs.mut xtask/src/main.rs
}
expect_fail check_module_doc.sh \
    'a Rust file documenting responsibility but not its boundary' mut_module_doc_loses_boundary

mut_unallowed_large_file() {
    for _ in $(seq 1 801); do printf '// padding\n' >>xtask/src/main.rs; done
}
expect_fail check_file_size.sh \
    'a Rust file exceeding 800 lines without an allowance' mut_unallowed_large_file

mut_invalid_file_size_allowance() {
    printf 'xtask/src/main.rs 900 missing-reason\n' >>allowances/file_size.txt
}
expect_fail check_file_size.sh \
    'a file-size allowance without an issue URL and reason' mut_invalid_file_size_allowance

mut_forbidden_list_loses_alternative() {
    sed 's|`cargo tree -p <crate> -e normal`|none|' AGENTS.md >AGENTS.md.mut
    mv AGENTS.md.mut AGENTS.md
}
expect_fail check_agents_forbidden_list.sh \
    'a forbidden-list entry losing its safe alternative' mut_forbidden_list_loses_alternative

mut_scoped_agents_file() {
    printf '# local rules\n' >crates/xml/AGENTS.md
}
expect_fail check_agents_layering.sh \
    'a scoped AGENTS.md introduced before the layering trigger' mut_scoped_agents_file

mut_secret_in_a_log_line() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + """
fn an_operator_friendly_diagnostic(secret: &str) -> String {
    format!("the secret did not match: {secret}")
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'a formatting macro naming a secret in the gateway extension tree' mut_secret_in_a_log_line

mut_refusal_in_a_log_line() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + """
fn why_it_was_refused(reason: crate::ext::CredentialRefusal) -> String {
    format!("refused: {reason:?}")
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'the refusal reason travelling out of the module that produced it' mut_refusal_in_a_log_line

mut_secret_in_a_growing_buffer() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
fn accumulate(parts: &[&[u8]]) -> Vec<u8> {
    let mut secret: Vec<u8> = Vec::new();
    for part in parts {
        secret.extend_from_slice(part);
    }
    secret
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'key material accumulated into a reallocating buffer' mut_secret_in_a_growing_buffer

mut_extra_expose_call_site() {
    python3 - <<'CREDPY'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
path.write_text(path.read_text() + """
fn a_second_reader(credentials: &Credentials) -> usize {
    credentials.secret().expose().len()
}
""")
CREDPY
}
expect_fail check_secret_hygiene.sh \
    'one more place key material leaves its container' mut_extra_expose_call_site

mut_credentials_module_deleted() {
    rm -f crates/gateway/src/ext/credentials.rs
}
expect_fail check_secret_hygiene.sh \
    "the guard's own subject deleted, which must fail rather than skip" mut_credentials_module_deleted

mut_provider_error_interpolates_request() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/credentials.rs")
text = path.read_text().replace("pub enum ProviderError {", "pub enum ProviderError {\n    Request(String),", 1)
path.write_text(text)
PYEOF
}
expect_fail check_preauth_no_interp.sh \
    'a provider error carrying request-derived text' mut_provider_error_interpolates_request

mut_signing_key_cache() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/authenticator.rs")
path.write_text(path.read_text() + "\nstruct BadCache { signing_key_cache: std::collections::HashMap<String, rustfs_gateway_sig::SigningKey> }\n")
PYEOF
}
expect_fail check_no_signing_key_cache.sh \
    'a cache retaining derived signing keys' mut_signing_key_cache

replace_ci_text() {
    python3 - "$1" "$2" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
old, new = sys.argv[1:]
if old not in text:
    raise SystemExit(f"missing mutation subject: {old}")
path.write_text(text.replace(old, new, 1))
PYEOF
}

mut_ci_time_static_command_weakened() {
    replace_ci_text 'cargo fmt --all --check' 'cargo fmt --check'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job weakening the exact fmt command' mut_ci_time_static_command_weakened

mut_ci_time_clippy_command_weakened() {
    replace_ci_text 'cargo clippy --workspace --all-targets -- -D warnings' \
        'cargo clippy --workspace -- -D warnings'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy job dropping all-target coverage' mut_ci_time_clippy_command_weakened

mut_ci_time_static_failure_swallowed() {
    replace_ci_text '      - run: cargo fmt --all --check' \
        '      - run: cargo fmt --all --check || true'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job swallowing fmt failure' mut_ci_time_static_failure_swallowed

mut_ci_time_clippy_continues_on_error() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        continue-on-error: true'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy step being allowed to fail' mut_ci_time_clippy_continues_on_error

mut_ci_time_static_name_changed() {
    replace_ci_text '    name: Static checks' '    name: Static check'
}
expect_fail check_ci_time_gate.sh \
    'the branch-protected Static checks context being renamed' mut_ci_time_static_name_changed

mut_ci_time_duplicate_required_name() {
    replace_ci_text '  clippy:
    name: Clippy' '  static-decoy:
    name: Static checks
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
      - run: true

  clippy:
    name: Clippy'
}
expect_fail check_ci_time_gate.sh \
    'a second job impersonating a branch-protected check name' mut_ci_time_duplicate_required_name

mut_ci_time_static_timeout_removed() {
    replace_ci_text '  static:
    name: Static checks
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  static:
    name: Static checks
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'the required Static checks job becoming unbounded' mut_ci_time_static_timeout_removed

mut_ci_time_feedback_timeout_removed() {
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  feedback-loop:
    name: Operation feedback loop
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'a non-required pull-request job becoming unbounded' mut_ci_time_feedback_timeout_removed

mut_ci_time_msrv_timeout_removed() {
    replace_ci_text '  msrv:
    name: MSRV
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  msrv:
    name: MSRV
    runs-on: ubuntu-latest'
}
expect_fail check_ci_time_gate.sh \
    'the MSRV job becoming unbounded' mut_ci_time_msrv_timeout_removed

mut_ci_time_dependency_path_exceeds_budget() {
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop' '  feedback-loop:
    name: Operation feedback loop
    needs: bootstrap'
}
expect_fail check_ci_time_gate.sh \
    'serial jobs permitting a fifteen-minute dependency path' mut_ci_time_dependency_path_exceeds_budget

mut_ci_time_docs_job_removed() {
    replace_ci_text '  docs:' '  docs-removed:'
}
expect_fail check_ci_time_gate.sh \
    'an accepted pull-request job being renamed away' mut_ci_time_docs_job_removed

mut_ci_time_permissions_widened() {
    replace_ci_text 'permissions:
  contents: read' 'permissions:
  contents: write'
}
expect_fail check_ci_time_gate.sh \
    'workflow permissions being widened' mut_ci_time_permissions_widened

mut_ci_time_action_pin_replaced_by_tag() {
    replace_ci_text 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10' \
        'actions/checkout@v6'
}
expect_fail check_ci_time_gate.sh \
    'an action pin being replaced by a movable tag' mut_ci_time_action_pin_replaced_by_tag

mut_ci_time_job_permissions_override() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    permissions:
      contents: write'
}
expect_fail check_ci_time_gate.sh \
    'a job overriding the workflow minimum permissions' mut_ci_time_job_permissions_override

mut_ci_time_required_step_skips() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        if: ${{ false }}'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command being conditionally skipped' mut_ci_time_required_step_skips

mut_ci_time_job_concurrency_serializes() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    concurrency: pull-request-gate'
}
expect_fail check_ci_time_gate.sh \
    'a job-level concurrency lane invalidating the dependency budget' mut_ci_time_job_concurrency_serializes

mut_ci_time_workflow_defaults_hide_failure() {
    replace_ci_text 'permissions:
  contents: read' 'defaults:
  run:
    shell: bash {0}

permissions:
  contents: read'
}
expect_fail check_ci_time_gate.sh \
    'workflow defaults disabling fail-fast shell behavior' mut_ci_time_workflow_defaults_hide_failure

mut_ci_time_workflow_env_overrides_cargo() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  PATH: scripts/fake-bin
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_time_gate.sh \
    'the workflow environment overriding the required command path' mut_ci_time_workflow_env_overrides_cargo

mut_ci_time_concurrency_cancel_disabled() {
    replace_ci_text '  cancel-in-progress: true' '  cancel-in-progress: false'
}
expect_fail check_ci_time_gate.sh \
    'superseded branch runs no longer being cancelled' mut_ci_time_concurrency_cancel_disabled

mut_ci_time_static_parent_fetch_dropped() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  static:")
position = text.index("          fetch-depth: 2", start)
path.write_text(text[:position] + text[position:].replace("          fetch-depth: 2", "          fetch-depth: 1", 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'the Static checks job losing access to the baseline parent commit' mut_ci_time_static_parent_fetch_dropped

mut_ci_time_clippy_setup_action_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  clippy:")
old = "      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'a fully pinned action replacing the expected Clippy setup' mut_ci_time_clippy_setup_action_replaced

mut_ci_time_duplicate_fmt_execution() {
    replace_ci_text '  clippy:
    name: Clippy' '  fmt-decoy:
    name: Format duplicate
    runs-on: ubuntu-latest
    timeout-minutes: 1
    steps:
      - run: cargo fmt --all --check

  clippy:
    name: Clippy'
}
expect_fail check_ci_time_gate.sh \
    'a second CI job duplicating the authoritative fmt execution' mut_ci_time_duplicate_fmt_execution

mut_ci_time_matrix_serializes_job() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    strategy:
      max-parallel: 1
      matrix:
        shard: [one, two]'
}
expect_fail check_ci_time_gate.sh \
    'a serial matrix invalidating the one-job timeout budget' mut_ci_time_matrix_serializes_job

mut_ci_time_nonrequired_job_skips() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    if: ${{ false }}'
}
expect_fail check_ci_time_gate.sh \
    'a pull-request job being conditionally skipped' mut_ci_time_nonrequired_job_skips

mut_ci_time_dependency_cycle() {
    replace_ci_text '  docs:
    name: Documentation' '  docs:
    name: Documentation
    needs: feedback-loop'
    replace_ci_text '  feedback-loop:
    name: Operation feedback loop' '  feedback-loop:
    name: Operation feedback loop
    needs: docs'
}
expect_fail check_ci_time_gate.sh \
    'a cycle making the CI dependency budget undefined' mut_ci_time_dependency_cycle

mut_ci_time_required_shell_override() {
    replace_ci_text '      - run: cargo clippy --workspace --all-targets -- -D warnings' \
        '      - run: cargo clippy --workspace --all-targets -- -D warnings
        shell: bash {0}'
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command overriding fail-fast shell behavior' mut_ci_time_required_shell_override

mut_ci_time_required_runner_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  clippy:")
position = text.index("    runs-on: ubuntu-latest", start)
path.write_text(text[:position] + text[position:].replace("    runs-on: ubuntu-latest", "    runs-on: self-hosted", 1))
PYEOF
}
expect_fail check_ci_time_gate.sh \
    'the required Clippy command moving to an unexpected runner' mut_ci_time_required_runner_replaced

mut_ci_time_workflow_deleted() {
    rm -f .github/workflows/ci.yml
}
expect_fail check_ci_time_gate.sh \
    "the guard's own workflow input deleted, which must fail rather than skip" mut_ci_time_workflow_deleted

mut_ci_workspace_job_missing() {
    replace_ci_text '  workspace-tests:' '  workspace-testz:'
}
expect_fail check_ci_test_split.sh \
    'the workspace-tests job being renamed away' mut_ci_workspace_job_missing

mut_ci_workspace_command_weakened() {
    replace_ci_text 'timeout 480s cargo test --workspace' 'timeout 480s cargo test -p xtask'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job running only one package' mut_ci_workspace_command_weakened

mut_ci_workspace_failure_swallowed() {
    replace_ci_text '          timeout 480s cargo test --workspace' \
        '          timeout 480s cargo test --workspace || true'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job swallowing a failure or timeout' mut_ci_workspace_failure_swallowed

mut_ci_workspace_budget_widened() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  workspace-tests:
    name: Workspace tests
    runs-on: ubuntu-latest
    timeout-minutes: 10'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job consuming the aggregation minute' mut_ci_workspace_budget_widened

mut_ci_workspace_serialized() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests' '  workspace-tests:
    needs: guard-self-test
    name: Workspace tests'
}
expect_fail check_ci_test_split.sh \
    'the workspace test job waiting for guard mutations' mut_ci_workspace_serialized

mut_ci_workspace_setup_action_replaced() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  workspace-tests:")
old = "      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'a workspace setup action being replaced by an environment injector' mut_ci_workspace_setup_action_replaced

mut_ci_guard_job_missing() {
    replace_ci_text '  guard-self-test:' '  guard-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the guard-self-test job being renamed away' mut_ci_guard_job_missing

mut_ci_guard_parent_fetch_dropped() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  guard-self-test:")
old = "          fetch-depth: 2"
position = text.index(old, start)
path.write_text(text[:position] + text[position:].replace(old, "          fetch-depth: 1", 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job losing access to the baseline parent commit' mut_ci_guard_parent_fetch_dropped

mut_ci_guard_command_dropped() {
    replace_ci_text 'timeout 480s bash scripts/test_guard_scripts.sh' 'timeout 480s true'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation suite being replaced with a no-op' mut_ci_guard_command_dropped

mut_ci_guard_failure_swallowed() {
    replace_ci_text '          timeout 480s bash scripts/test_guard_scripts.sh' \
        '          timeout 480s bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job swallowing a failure or timeout' mut_ci_guard_failure_swallowed

mut_ci_guard_budget_widened() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test
    runs-on: ubuntu-latest
    timeout-minutes: 9' '  guard-self-test:
    name: Guard self-test
    runs-on: ubuntu-latest
    timeout-minutes: 10'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job consuming the aggregation minute' mut_ci_guard_budget_widened

mut_ci_guard_serialized() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    needs: workspace-tests
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation job waiting for workspace tests' mut_ci_guard_serialized

mut_ci_target_job_missing() {
    replace_ci_text '  target-consolidation-self-test:' '  target-consolidation-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation-self-test job being renamed away' mut_ci_target_job_missing

mut_ci_target_command_dropped() {
    replace_ci_text 'timeout 120s bash scripts/test_test_target_consolidation.sh' \
        'timeout 120s true'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation mutation suite being replaced with a no-op' mut_ci_target_command_dropped

mut_ci_target_failure_swallowed() {
    replace_ci_text '          timeout 120s bash scripts/test_test_target_consolidation.sh' \
        '          timeout 120s bash scripts/test_test_target_consolidation.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job swallowing a failure or timeout' mut_ci_target_failure_swallowed

mut_ci_target_budget_widened() {
    replace_ci_text '  target-consolidation-self-test:
    name: Target consolidation self-test
    runs-on: ubuntu-latest
    timeout-minutes: 3' '  target-consolidation-self-test:
    name: Target consolidation self-test
    runs-on: ubuntu-latest
    timeout-minutes: 4'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job widening its three-minute budget' mut_ci_target_budget_widened

mut_ci_target_setup_action_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  target-consolidation-self-test:")
old = "      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation checkout being replaced by an environment injector' \
    mut_ci_target_setup_action_replaced

mut_ci_target_serialized() {
    replace_ci_text '  target-consolidation-self-test:
    name: Target consolidation self-test' '  target-consolidation-self-test:
    needs: guard-self-test
    name: Target consolidation self-test'
}
expect_fail check_ci_test_split.sh \
    'the target-consolidation job waiting for guard mutations' mut_ci_target_serialized

mut_ci_quirk_ledger_job_missing() {
    replace_ci_text '  quirk-ledger-self-test:' '  quirk-ledger-self-tesx:'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger-self-test job being renamed away' mut_ci_quirk_ledger_job_missing

mut_ci_quirk_ledger_command_dropped() {
    replace_ci_text 'timeout 60s env GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 bash scripts/test_guard_scripts.sh' \
        'timeout 60s true'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger mutation suite being replaced with a no-op' mut_ci_quirk_ledger_command_dropped

mut_ci_quirk_ledger_failure_swallowed() {
    replace_ci_text '          timeout 60s env GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 bash scripts/test_guard_scripts.sh' \
        '          timeout 60s env GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 bash scripts/test_guard_scripts.sh || true'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job swallowing a failure or timeout' mut_ci_quirk_ledger_failure_swallowed

mut_ci_quirk_ledger_budget_widened() {
    replace_ci_text '  quirk-ledger-self-test:
    name: Quirk ledger self-test
    runs-on: ubuntu-latest
    timeout-minutes: 2' '  quirk-ledger-self-test:
    name: Quirk ledger self-test
    runs-on: ubuntu-latest
    timeout-minutes: 3'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job widening its two-minute budget' mut_ci_quirk_ledger_budget_widened

mut_ci_quirk_ledger_setup_action_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path

path = Path(".github/workflows/ci.yml")
text = path.read_text()
start = text.index("  quirk-ledger-self-test:")
old = "      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6"
position = text.index(old, start)
new = "      - uses: example/environment-injector@0000000000000000000000000000000000000000"
path.write_text(text[:position] + text[position:].replace(old, new, 1))
PYEOF
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger checkout being replaced by an environment injector' \
    mut_ci_quirk_ledger_setup_action_replaced

mut_ci_quirk_ledger_serialized() {
    replace_ci_text '  quirk-ledger-self-test:
    name: Quirk ledger self-test' '  quirk-ledger-self-test:
    needs: guard-self-test
    name: Quirk ledger self-test'
}
expect_fail check_ci_test_split.sh \
    'the quirk-ledger job waiting for guard mutations' mut_ci_quirk_ledger_serialized

mut_ci_target_serialized_in_guard() {
    printf '%s\n' 'if "${SCRIPT_DIR}/test_test_target_consolidation.sh"; then' \
        >>scripts/test_guard_scripts.sh
}
expect_fail check_ci_test_split.sh \
    'the guard job serializing target-consolidation mutations again' mut_ci_target_serialized_in_guard

mut_ci_required_name_changed() {
    replace_ci_text '    name: Test' '    name: Tests'
}
expect_fail check_ci_test_split.sh \
    'the branch-protected Test check being renamed' mut_ci_required_name_changed

mut_ci_aggregate_drops_guard() {
    replace_ci_text 'needs: [workspace-tests, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]' \
        'needs: [workspace-tests, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for guard mutations' mut_ci_aggregate_drops_guard

mut_ci_aggregate_drops_target() {
    replace_ci_text 'needs: [workspace-tests, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]' \
        'needs: [workspace-tests, guard-self-test, quirk-ledger-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for target-consolidation mutations' \
    mut_ci_aggregate_drops_target

mut_ci_aggregate_drops_quirk_ledger() {
    replace_ci_text 'needs: [workspace-tests, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]' \
        'needs: [workspace-tests, guard-self-test, target-consolidation-self-test, gateway-tsan]'
}
expect_fail check_ci_test_split.sh \
    'the required Test check no longer waiting for quirk-ledger mutations' \
    mut_ci_aggregate_drops_quirk_ledger

mut_ci_aggregate_skips_on_failure() {
    replace_ci_text 'if: always()' 'if: success()'
}
expect_fail check_ci_test_split.sh \
    'the required Test check being skipped after a dependency failure' mut_ci_aggregate_skips_on_failure

mut_ci_aggregate_hides_always_in_comment() {
    replace_ci_text '    if: always()' '    if: success() # if: always()'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check hiding a skipped condition behind a comment' mut_ci_aggregate_hides_always_in_comment

mut_ci_aggregate_step_skips_failure() {
    replace_ci_text '      - name: Require test jobs' \
        '      - name: Require test jobs
        if: ${{ needs.workspace-tests.result == '\''success'\'' && needs.guard-self-test.result == '\''success'\'' }}'
}
expect_fail check_ci_test_split.sh \
    'the aggregate comparison step being skipped after a worker failure' mut_ci_aggregate_step_skips_failure

mut_ci_aggregate_budget_widened() {
    replace_ci_text '  test:
    name: Test
    needs: [workspace-tests, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]
    if: always()
    runs-on: ubuntu-latest
    timeout-minutes: 1' '  test:
    name: Test
    needs: [workspace-tests, guard-self-test, target-consolidation-self-test, quirk-ledger-self-test, gateway-tsan]
    if: always()
    runs-on: ubuntu-latest
    timeout-minutes: 2'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check widening the total job budget past ten minutes' mut_ci_aggregate_budget_widened

mut_ci_workspace_result_ignored() {
    replace_ci_text 'WORKSPACE_RESULT: ${{ needs.workspace-tests.result }}' 'WORKSPACE_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the workspace test result' mut_ci_workspace_result_ignored

mut_ci_guard_result_ignored() {
    replace_ci_text 'GUARD_RESULT: ${{ needs.guard-self-test.result }}' 'GUARD_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the guard mutation result' mut_ci_guard_result_ignored

mut_ci_target_result_ignored() {
    replace_ci_text 'TARGET_CONSOLIDATION_RESULT: ${{ needs.target-consolidation-self-test.result }}' \
        'TARGET_CONSOLIDATION_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the target-consolidation result' mut_ci_target_result_ignored

mut_ci_quirk_ledger_result_ignored() {
    replace_ci_text 'QUIRK_LEDGER_RESULT: ${{ needs.quirk-ledger-self-test.result }}' \
        'QUIRK_LEDGER_RESULT: success'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check ignoring the quirk-ledger result' mut_ci_quirk_ledger_result_ignored

mut_ci_workspace_comparison_dropped() {
    replace_ci_text '          test "$WORKSPACE_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the workspace result comparison' mut_ci_workspace_comparison_dropped

mut_ci_guard_comparison_dropped() {
    replace_ci_text '          test "$GUARD_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the guard result comparison' mut_ci_guard_comparison_dropped

mut_ci_target_comparison_dropped() {
    replace_ci_text '          test "$TARGET_CONSOLIDATION_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the target-consolidation result comparison' \
    mut_ci_target_comparison_dropped

mut_ci_quirk_ledger_comparison_dropped() {
    replace_ci_text '          test "$QUIRK_LEDGER_RESULT" = success' '          true'
}
expect_fail check_ci_test_split.sh \
    'the aggregate check not executing the quirk-ledger result comparison' \
    mut_ci_quirk_ledger_comparison_dropped

mut_ci_workers_share_concurrency_lane() {
    replace_ci_text '  workspace-tests:
    name: Workspace tests' '  workspace-tests:
    concurrency: split-test-lane
    name: Workspace tests'
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    concurrency: split-test-lane
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'the parallel workers sharing a serial concurrency lane' mut_ci_workers_share_concurrency_lane

mut_ci_guard_quoted_dependency() {
    replace_ci_text '  guard-self-test:
    name: Guard self-test' '  guard-self-test:
    "needs": workspace-tests
    name: Guard self-test'
}
expect_fail check_ci_test_split.sh \
    'a quoted worker dependency serializing the split jobs' mut_ci_guard_quoted_dependency

mut_ci_worker_continues_on_error() {
    replace_ci_text '      - name: Workspace tests (maximum 8 minutes after setup)' \
        '      - name: Workspace tests (maximum 8 minutes after setup)
        continue-on-error: true'
}
expect_fail check_ci_test_split.sh \
    'the workspace test step being allowed to fail' mut_ci_worker_continues_on_error

mut_ci_worker_shell_disables_errexit() {
    replace_ci_text '      - name: Guard mutations (maximum 8 minutes after setup)' \
        '      - name: Guard mutations (maximum 8 minutes after setup)
        shell: bash {0}'
}
expect_fail check_ci_test_split.sh \
    'the guard mutation step overriding the fail-fast shell' mut_ci_worker_shell_disables_errexit

mut_ci_workflow_shell_disables_errexit() {
    replace_ci_text 'permissions:
  contents: read' 'defaults:
  run:
    shell: bash {0}

permissions:
  contents: read'
}
expect_fail check_ci_test_split.sh \
    'workflow defaults overriding the fail-fast shell' mut_ci_workflow_shell_disables_errexit

mut_ci_workflow_bash_env() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  BASH_ENV: scripts/disable-errexit.sh
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding bash startup' mut_ci_workflow_bash_env

mut_ci_workflow_overrides_test() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  "BASH_FUNC_test%%": '\''() { return 0; }'\''
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding the aggregate test command' mut_ci_workflow_overrides_test

mut_ci_workflow_overrides_timeout() {
    replace_ci_text 'env:
  CARGO_TERM_COLOR: always' 'env:
  "BASH_FUNC_timeout%%": '\''() { shift; "$@" || true; }'\''
  CARGO_TERM_COLOR: always'
}
expect_fail check_ci_test_split.sh \
    'the workflow environment overriding worker timeouts' mut_ci_workflow_overrides_timeout

mut_ci_serial_verify_returns() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path(".github/workflows/ci.yml")
path.write_text(path.read_text() + """
  serialized-regression:
    name: Serialized regression
    runs-on: ubuntu-latest
    steps:
      - run: cargo xtask verify --all
""")
PYEOF
}
expect_fail check_ci_test_split.sh \
    'workspace tests and guard mutations being serialized again' mut_ci_serial_verify_returns

mut_ci_workflow_deleted() {
    rm -f .github/workflows/ci.yml
}
expect_fail check_ci_test_split.sh \
    "the guard's own workflow input deleted, which must fail rather than skip" mut_ci_workflow_deleted
mut_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let _torn = self.inner.config.load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read in the request pipeline' mut_second_config_load

mut_aliased_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let config_store = &self.inner.config;\n        let _torn = config_store.load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through an aliased store' mut_aliased_second_config_load

mut_as_ref_second_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let _torn = self.inner.config.as_ref().load_full();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through Arc::as_ref' mut_as_ref_second_config_load

mut_guarded_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let _torn = self.inner.config.load();",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through ArcSwap::load' mut_guarded_config_load

mut_ufcs_config_load_full() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let _torn = arc_swap::ArcSwapAny::load_full(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through UFCS load_full' mut_ufcs_config_load_full

mut_ufcs_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        let _torn = arc_swap::ArcSwapAny::load(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through UFCS load' mut_ufcs_config_load

mut_import_aliased_config_load_full() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        use arc_swap::ArcSwapAny as Swap;\n        let _torn = Swap::load_full(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through an imported type alias' mut_import_aliased_config_load_full

mut_type_aliased_config_load() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        type ConfigStoreAlias = arc_swap::ArcSwapAny<Arc<ServiceConfig>>;\n        let _torn = ConfigStoreAlias::load(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through a type alias' mut_type_aliased_config_load

mut_config_load_function_item() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace(
    "let config = self.inner.config.load_full();",
    "let config = self.inner.config.load_full();\n        use arc_swap::ArcSwapAny as Swap;\n        let read = Swap::load_full;\n        let _torn = read(self.inner.config.as_ref());",
    1,
)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a second hot-configuration read through a function item' mut_config_load_function_item

mut_config_load_allowlist_deleted() {
    rm -f scripts/config_load_allowlist.txt
}
expect_fail check_config_load_once.sh \
    'the config-load allowlist being absent' mut_config_load_allowlist_deleted

mut_config_snapshot_stage_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/service.rs")
text = path.read_text().replace("let config = state.config.decoded();", "let config = state.config;", 1)
path.write_text(text)
PYEOF
}
expect_fail check_config_load_once.sh \
    'a real request path dropping the decoded snapshot stage' mut_config_snapshot_stage_deleted

mut_tsan_instrumentation_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/run_gateway_tsan.sh")
path.write_text(path.read_text().replace("RUSTFLAGS='-Zsanitizer=thread'", "RUSTFLAGS=''", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the TSAN runner losing sanitizer instrumentation' mut_tsan_instrumentation_deleted

mut_tsan_build_std_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("scripts/run_gateway_tsan.sh")
path.write_text(path.read_text().replace(" test -Zbuild-std ", " test ", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the TSAN runner using an uninstrumented standard library' mut_tsan_build_std_deleted

mut_tsan_thread_count_reduced() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/tests/service_concurrency.rs")
path.write_text(path.read_text().replace("const THREADS: usize = 100;", "const THREADS: usize = 99;", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'the concurrency case being reduced to 99 OS threads' mut_tsan_thread_count_reduced

mut_tsan_ci_call_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path(".github/workflows/ci.yml")
path.write_text(path.read_text().replace("scripts/run_gateway_tsan.sh", "cargo test -p rustfs-gateway", 1))
PYEOF
}
expect_fail check_gateway_tsan_wiring.sh \
    'CI no longer invoking the TSAN runner' mut_tsan_ci_call_deleted

mut_default_security_doc_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/policy.rs")
text = path.read_text().replace("/// # Security\n", "", 1)
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a Default implementation losing its security consequences' mut_default_security_doc_deleted

mut_derived_default_security_doc_deleted() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/host.rs")
text = path.read_text().replace("/// # Security\n", "", 1)
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a derived extension default losing its security consequences' mut_derived_default_security_doc_deleted

mut_undocumented_derived_default_added() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/observer.rs")
text = path.read_text()
text += "\n#[derive(Default)]\npub struct UndocumentedObserverDefault;\n"
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'a newly derived extension default without security documentation' mut_undocumented_derived_default_added

mut_inline_undocumented_derived_default_added() {
    python3 - <<'PYEOF'
import pathlib
path = pathlib.Path("crates/gateway/src/ext/observer.rs")
text = path.read_text()
text += "\n#[derive(Default)] pub struct InlineUndocumentedDefault;\n"
path.write_text(text)
PYEOF
}
expect_fail check_default_doc.sh \
    'an inline derived extension default without security documentation' mut_inline_undocumented_derived_default_added

mut_default_doc_subject_deleted() {
    rm -f crates/gateway/src/ext/policy.rs
}
expect_fail check_default_doc.sh \
    "a documented Default implementation's source being absent" mut_default_doc_subject_deleted

# Fault-inject the real make_sandbox function. Each mode must fail without publishing a sandbox or
# leaving its derived list, archive, or partially initialized directory behind.
expect_sandbox_setup_failure() {
    local mode="$1" probe_root rc=0
    cases=$((cases + 1))
    probe_root="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-fault.XXXXXX")"
    mkdir -p "$probe_root/repo" "$probe_root/tmp"
    (
        cd "$probe_root/repo"
        git init -q .
        printf 'sandbox fault probe\n' >tracked.txt
        git add tracked.txt
        git -c user.name=t -c user.email=t@t commit -qm base
    )
    (
        local real_git real_tar sandbox_rc=0
        real_git="$(command -v git)"
        real_tar="$(command -v tar)"
        REPO_ROOT="$probe_root/repo"
        TMPDIR="$probe_root/tmp"
        SANDBOX=""

        git() {
            local argument
            if [[ "$mode" == list-failure && "$1" == ls-files ]]; then
                return 71
            fi
            if [[ "$mode" == commit-failure ]]; then
                for argument in "$@"; do
                    if [[ "$argument" == commit ]]; then
                        return 72
                    fi
                done
            fi
            command "$real_git" "$@"
        }
        tar() {
            if [[ "$mode" == create-failure && "$1" == -cf ]]; then
                return 73
            fi
            if [[ "$mode" == extract-failure && "$1" == -xf ]]; then
                return 74
            fi
            command "$real_tar" "$@"
        }

        make_sandbox || sandbox_rc=$?
        [[ "$sandbox_rc" -ne 0 && -z "$SANDBOX" ]] || exit 1
        shopt -s nullglob dotglob
        leftovers=("$TMPDIR"/*)
        [[ "${#leftovers[@]}" -eq 0 ]]
    ) || rc=$?
    rm -rf "$probe_root"
    if [[ "$rc" -eq 0 ]]; then
        pass_msg "make_sandbox fails closed and cleans up: ${mode}"
    else
        fail_msg "make_sandbox leaked state or reported success: ${mode}"
    fi
}

expect_sandbox_setup_failure list-failure
expect_sandbox_setup_failure create-failure
expect_sandbox_setup_failure extract-failure
expect_sandbox_setup_failure commit-failure

mut_guard_sandbox_archive_restored_to_stream() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
start = text.index('    list="${dir}.files"')
end = text.index('    if ! (cd "$dir" && git init -q .); then', start)
stream = '''    (cd "$REPO_ROOT" && tar -cf - -T "$list") | (cd "$dir" && tar -xf -)
    rm -f "$list"
'''
path.write_text(text[:start] + stream + text[end:])
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'make_sandbox restoring the streaming tar pipeline' mut_guard_sandbox_archive_restored_to_stream

mut_guard_sandbox_archive_not_derived_from_unique_dir() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '    archive="${dir}.tar"\n'
path.write_text(text.replace(old, '    archive="${TMPDIR:-/tmp}/gateway-guard-archive.tar"\n', 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'make_sandbox using a fixed archive path' mut_guard_sandbox_archive_not_derived_from_unique_dir

mut_guard_sandbox_archive_list_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '''    (
        cd "$REPO_ROOT" &&
            git ls-files >"$list" &&
            git ls-files --others --exclude-standard >>"$list" &&
            sort -u -o "$list" "$list"
    ) || true
'''
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'file-list creation ignoring a producer failure' mut_guard_sandbox_archive_list_not_fail_closed

mut_guard_sandbox_archive_create_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
path.write_text(text.replace(old, '    (cd "$REPO_ROOT" && tar -cf "$archive" -T "$list") || true\n', 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'archive creation ignoring a producer failure' mut_guard_sandbox_archive_create_not_fail_closed

mut_guard_sandbox_archive_extract_leaks_partial_state() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$dir" && tar -xf "$archive"); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '''    if ! (cd "$dir" && tar -xf "$archive"); then
        return 1
    fi
'''
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'archive extraction leaking partial state' mut_guard_sandbox_archive_extract_leaks_partial_state

mut_guard_sandbox_archive_cleanup_commented_out() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '        rm -f "$list" "$archive" || true\n'
new = '        # rm -f "$list" "$archive" || true\n'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'a cleanup command being replaced by a comment' mut_guard_sandbox_archive_cleanup_commented_out

mut_guard_sandbox_archive_commit_not_fail_closed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("scripts/test_guard_scripts.sh")
text = path.read_text()
old = '''    if ! (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1); then
        rm -f "$list" "$archive" || true
        rm -rf "$dir" || true
        return 1
    fi
'''
new = '    (cd "$dir" && git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1) || true\n'
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_guard_sandbox_archive.sh \
    'sandbox base commit ignoring failure' mut_guard_sandbox_archive_commit_not_fail_closed

mut_xtask_autotests_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("autotests = false\n", "autotests = true\n", 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'restoring xtask implicit test discovery' mut_xtask_autotests_restored

mut_xtask_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/integration.rs")
text = path.read_text()
path.write_text(text.replace('#[path = "cli_contract.rs"]\nmod cli_contract;\n', '', 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an omitted xtask integration registration' mut_xtask_registration_omitted

mut_xtask_registration_duplicated() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/integration.rs")
text = path.read_text()
entry = '#[path = "cli_contract.rs"]\nmod cli_contract;\n'
path.write_text(text.replace(entry, entry + entry, 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a duplicated xtask integration registration' mut_xtask_registration_duplicated

mut_xtask_source_unregistered() {
    cp xtask/tests/cli_contract.rs xtask/tests/unregistered_contract.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a new unregistered xtask integration source' mut_xtask_source_unregistered

mut_xtask_source_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/tests/cli_contract.rs")
path.write_text("#![cfg(any())]\n" + path.read_text())
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a registered xtask source disabled by file cfg' mut_xtask_source_disabled

mut_xtask_source_symlinked() {
    rm xtask/tests/cli_contract.rs
    ln -s why_contract.rs xtask/tests/cli_contract.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a registered xtask source replaced by a symlink' mut_xtask_source_symlinked

mut_xtask_extra_test_target() {
    cat >>xtask/Cargo.toml <<'TOMLEOF'

[[test]]
name = "duplicate"
path = "tests/integration.rs"
TOMLEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a second explicit xtask test target' mut_xtask_extra_test_target

mut_xtask_example_reuses_source() {
    cat >>xtask/Cargo.toml <<'TOMLEOF'

[[example]]
name = "duplicate-contract"
path = "tests/cli_contract.rs"
test = true
TOMLEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an example target reusing an xtask test source' mut_xtask_example_reuses_source

mut_xtask_path_reuses_source() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

#[cfg(test)]
#[path = "../tests/cli_contract.rs"]
mod duplicate_contract;
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'a path attribute reusing an xtask test source' mut_xtask_path_reuses_source

mut_xtask_include_reuses_source() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

#[cfg(test)]
mod duplicate_contract {
    include!("../tests/cli_contract.rs");
}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an include reusing an xtask test source' mut_xtask_include_reuses_source

mut_xtask_lifetimes_surround_path_reuse() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

fn before_path<'a>() {} #[cfg(test)] #[path = "../tests/cli_contract.rs"] mod duplicate_contract; fn after_path<'b>() {}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'lifetimes surrounding an active path reuse' mut_xtask_lifetimes_surround_path_reuse

mut_xtask_lifetimes_surround_include_reuse() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

fn before_include<'a>() {} #[cfg(test)] mod duplicate_contract { include!("../tests/cli_contract.rs"); } fn after_include<'b>() {}
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'lifetimes surrounding an active include reuse' mut_xtask_lifetimes_surround_include_reuse

mut_xtask_path_include_token_decoys() {
    cat >>xtask/src/main.rs <<'RUSTEOF'

// #[path = "../tests/cli_contract.rs"]
const PATH_DECOY: &str = "#[path = \"../tests/cli_contract.rs\"]";
const INCLUDE_DECOY: &str = "include!(\"../tests/cli_contract.rs\")";
const CHAR_DECOY: char = '#';
const BYTE_CHAR_DECOY: u8 = b'!';
fn lifetime_control<'a>(value: &'a str) -> &'a str { value }
RUSTEOF
}
expect_guard_pass check_xtask_test_target_consolidation.sh \
    'comment, string, char, byte-char, and lifetime token decoys' mut_xtask_path_include_token_decoys

mut_xtask_explicit_build_reuses_source() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("xtask/Cargo.toml")
text = path.read_text()
path.write_text(text.replace("publish = false\n", 'publish = false\nbuild = "tests/cli_contract.rs"\n', 1))
PYEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'an explicit build target reusing an xtask test source' mut_xtask_explicit_build_reuses_source

mut_xtask_default_build_symlink_reuses_source() {
    ln -s tests/cli_contract.rs xtask/build.rs
}
expect_fail check_xtask_test_target_consolidation.sh \
    'the default build target symlinking an xtask test source' mut_xtask_default_build_symlink_reuses_source

mut_xtask_default_build_includes_source() {
    cat >xtask/build.rs <<'RUSTEOF'
include!("tests/cli_contract.rs");
RUSTEOF
}
expect_fail check_xtask_test_target_consolidation.sh \
    'the default build target including an xtask test source' mut_xtask_default_build_includes_source

fi

if [[ "$QUIRK_LEDGER_ONLY" == 1 ]]; then

# The protected quirk ledger has independent negative controls for its counts, source union,
# dimensions, capability exclusions, production consumers, bilateral backlinks and generated ID
# sets. None of these controls runs codegen or Cargo.
QUIRK_LEDGER_DIAGNOSTICS=$(cat <<'DIAGEOF'
mut_quirk_ledger_classification_count	q-timestamp-0012: unknown classification
mut_quirk_ledger_duplicate_source	q-restore-header-absence-0127: multiple typed sources
mut_quirk_ledger_typed_contract_proof_removed	ledger typed_contracts: expected 157, found 156
mut_quirk_ledger_dimension_count	ledger dimensions: expected 171, found 170
mut_quirk_ledger_misbound_emitter_dimension	q-restore-header-absence-0127: expected one declared emitter binding, found 0
mut_quirk_ledger_capability_exclusion	capability exclusions must remain typed contract sources
mut_quirk_ledger_mutable_consumer	q-empty-0002: mutable source has no parsed operation consumer
mut_quirk_ledger_runtime_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_cfg_disabled_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_cfg_attr_disabled_consumer	q-restore-header-absence-0127: emitted constants lack one production consumer identity
mut_quirk_ledger_codegen_consumer_decoy	q-restore-root-namespace-0137: emitted constants lack one production consumer identity
mut_quirk_ledger_direct_case_comment_decoy	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_string_decoy	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_disabled	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_attr_disabled	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_ignored	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_cfg_attr_ignored	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_should_panic	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_inert_body_string	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_ordinary_function	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_direct_case_shadowed_macro	q-restore-header-parser-0128 -> c-rst-0014: expected one executable direct-case backlink, found 0
mut_quirk_ledger_forward_backlink	q-restore-header-absence-0127 -> c-select-restore-0019: missing unique backlink
mut_quirk_ledger_reverse_backlink	c-select-restore-0040 -> q-restore-header-absence-0127: missing unique source backlink
mut_quirk_ledger_spec_id_set	spec/quirks id set drifted:
DIAGEOF
)
if ! python3 - "${GATEWAY_GUARD_SCRIPT_SOURCE:-$0}" <<'PYEOF'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
entries = re.findall(r"expect_fail check_quirk_ledger\.sh \\\n\s+'([^']+)' ([a-z0-9_]+)", text)
diagnostics = re.findall(r"^(mut_quirk_ledger_[a-z0-9_]+)\t([^\n]+)$", text, re.MULTILINE)
helpers = [helper for _, helper in entries]
if len(entries) != 24 or len(set(entries)) != 24 or len(diagnostics) != 24 or len(set(diagnostics)) != 24:
    raise SystemExit("quirk-ledger mutation manifest must contain 24 unique description/helper pairs")
if set(helpers) != {helper for helper, _ in diagnostics}:
    raise SystemExit("quirk-ledger diagnostic manifest does not match the 24 mutation helpers")
PYEOF
then
    fail_msg 'check_quirk_ledger.sh mutation manifest is missing or duplicated'
fi
QUIRK_LEDGER_PARSE_CACHE="$(mktemp "${TMPDIR:-/tmp}/gateway-quirk-ledger-cache.XXXXXX")"
rm -f "$QUIRK_LEDGER_PARSE_CACHE"
export GATEWAY_QUIRK_LEDGER_PARSE_CACHE="$QUIRK_LEDGER_PARSE_CACHE"
make_sandbox
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh parse-cache baseline failed'
fi
python3 - "$QUIRK_LEDGER_PARSE_CACHE" "$SANDBOX/model/overlays/quirks/object.toml" <<'PYEOF'
import hashlib
import pathlib
import sqlite3
import sys

cache, subject = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256(subject.read_bytes()).hexdigest()
with sqlite3.connect(cache) as connection:
    connection.execute(
        "UPDATE parse_cache SET value = 'not-json' WHERE kind = 'toml' AND hash = ?", (digest,)
    )
PYEOF
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh did not repair a malformed cached row'
fi
if [[ ! -s "$QUIRK_LEDGER_PARSE_CACHE" ]]; then
    fail_msg 'check_quirk_ledger.sh parse cache was not populated'
fi
printf 'not-json\n' >"$QUIRK_LEDGER_PARSE_CACHE"
if ! GATEWAY_CHECK_ROOT="$SANDBOX" "${SCRIPT_DIR}/check_quirk_ledger.sh" >/dev/null 2>&1; then
    fail_msg 'check_quirk_ledger.sh did not rebuild a corrupt parse cache'
fi
quirk_ledger_cases_before="$cases"
mut_quirk_ledger_classification_count() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/object.toml")
text = path.read_text()
old = 'id      = "q-timestamp-0012"\nkind    = "structured_header"\nclassification = "contract"'
new = 'id      = "q-timestamp-0012"\nkind    = "structured_header"\nclassification = "unknown"'
if old not in text:
    raise SystemExit("classification mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one protected record leaving the 96/157/88 classification ledger' mut_quirk_ledger_classification_count
if ! python3 - "$QUIRK_LEDGER_PARSE_CACHE" "$SANDBOX/model/overlays/quirks/object.toml" <<'PYEOF'
import hashlib
import pathlib
import sqlite3
import sys

cache, subject = map(pathlib.Path, sys.argv[1:])
digest = hashlib.sha256(subject.read_bytes()).hexdigest()
with sqlite3.connect(cache) as connection:
    row = connection.execute(
        "SELECT 1 FROM parse_cache WHERE kind = 'toml' AND hash = ?", (digest,)
    ).fetchone()
if row is None:
    raise SystemExit("changed content did not create a content-hash cache miss")
PYEOF
then
    fail_msg 'check_quirk_ledger.sh reused the baseline parse for changed content'
fi

mut_quirk_ledger_duplicate_source() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
new = 'mutation_dimension = "restore_header_absence"\ncodec_value = "entity_tag"\ncontract_value = "omit"'
if old not in text:
    raise SystemExit("typed-source mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one atom claiming two typed sources' mut_quirk_ledger_duplicate_source

mut_quirk_ledger_typed_contract_proof_removed() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
if text.count(old) != 1:
    raise SystemExit("typed-contract proof mutation subject is not unique")
path.write_text(text.replace(old, "", 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a typed contract losing its current value and mutation dimension' mut_quirk_ledger_typed_contract_proof_removed

mut_quirk_ledger_dimension_count() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/select-restore.toml")
text = path.read_text()
old = 'mutation_dimension = "restore_header_absence"\ncontract_value = "omit"'
new = 'mutation_dimension = "restore_header_parse_grammar"\ncontract_value = "omit"'
if old not in text:
    raise SystemExit("dimension mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the 171-dimension ledger collapsing one independent atom' mut_quirk_ledger_dimension_count

mut_quirk_ledger_misbound_emitter_dimension() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/codegen/src/emit/runtime_contracts/select_restore.rs")
text = path.read_text()
old = '''        RestoreHeaderAbsence,
        RestoreHeaderAbsence,
        RestoreHeaderAbsenceValue,'''
new = '''        RestoreHeaderParseGrammar,
        RestoreHeaderAbsence,
        RestoreHeaderAbsenceValue,'''
if text.count(old) != 1:
    raise SystemExit("emitter-dimension mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'one typed source being bound to another atom dimension by its emitter' mut_quirk_ledger_misbound_emitter_dimension

mut_quirk_ledger_capability_exclusion() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("model/overlays/quirks/cors.toml")
text = path.read_text()
old = 'id      = "q-cors-0006"'
new = 'id      = "q-cors-9006"'
if text.count(old) != 1:
    raise SystemExit("capability exclusion mutation subject is not unique")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'the explicit two-entry CORS capability exclusion drifting' mut_quirk_ledger_capability_exclusion

mut_quirk_ledger_mutable_consumer() {
    python3 - <<'PYEOF'
import pathlib

decoy_path = None
for path in pathlib.Path("model/overlays/ops").glob("*.toml"):
    text = path.read_text()
    if '"q-empty-0002"' in text:
        path.write_text(text.replace('"q-empty-0002"', '"q-region-0003"'))
        decoy_path = path
if decoy_path is None:
    raise SystemExit("mutable-consumer mutation subject is missing")
with decoy_path.open("a") as output:
    output.write('\n# A raw TOML comment is not a consumer: "q-empty-0002"\n')
    output.write('ledger_string_decoy = "q-empty-0002"\n')
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a TOML comment replacing every parsed mutable consumer' mut_quirk_ledger_mutable_consumer

mut_quirk_ledger_runtime_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("runtime-consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '\n// A comment is not a production consumer: RESTORE_HEADER_ABSENCE\n'
text += 'const _LEDGER_STRING_DECOY: &str = "RESTORE_HEADER_ABSENCE";\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'comments and strings replacing an emitted constant production use' mut_quirk_ledger_runtime_consumer

mut_quirk_ledger_cfg_disabled_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("cfg-disabled consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '''
#[cfg(any())]
fn disabled_ledger_decoy() {
    let _ = crate::contracts::RESTORE_HEADER_ABSENCE;
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg-disabled item replacing an emitted constant production use' mut_quirk_ledger_cfg_disabled_consumer

mut_quirk_ledger_cfg_attr_disabled_consumer() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/core/src/ops/shared/restore.rs")
text = path.read_text()
old = "RESTORE_HEADER_ABSENCE"
if old not in text:
    raise SystemExit("cfg_attr-disabled consumer mutation subject is missing")
text = text.replace(old, "RESTORE_HEADER_ABSENCE_BROKEN")
text += '''
#[cfg_attr(all(), cfg(any()))]
fn disabled_ledger_decoy() {
    let _ = crate::contracts::RESTORE_HEADER_ABSENCE;
}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-disabled item replacing an emitted constant production use' mut_quirk_ledger_cfg_attr_disabled_consumer

mut_quirk_ledger_codegen_consumer_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/codegen/src/emit/codec/decode.rs")
text = path.read_text()
old = '"crate::contracts::RESTORE_ROOT_NAMESPACE_POLICY, crate::contracts::RestoreRootNamespacePolicy::QualifiedName"'
new = '"crate::contracts::RestoreRootNamespacePolicy::QualifiedName"'
if text.count(old) != 1:
    raise SystemExit("codegen-consumer mutation subject is not unique")
text = text.replace(old, new, 1)
text += '\n// An unrelated emitted-code string is not a live match-arm consumer.\n'
text += 'const _LEDGER_CODEGEN_DECOY: &str = "crate::contracts::RESTORE_ROOT_NAMESPACE_POLICY";\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an emitted-code policy leaving its active match arm for a string decoy' mut_quirk_ledger_codegen_consumer_decoy

mut_quirk_ledger_direct_case_comment_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("direct-case comment mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'\n// #[test]\n// fn {name}() {{ let quirk = "q-restore-header-parser-0128"; assert!(true, "{{}}", quirk); }}\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a commented direct case replacing its active test function' mut_quirk_ledger_direct_case_comment_decoy

mut_quirk_ledger_direct_case_string_decoy() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("direct-case string mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'\nconst _DIRECT_CASE_DECOY: &str = r#"#[test] fn {name}() {{ let quirk = \\"q-restore-header-parser-0128\\"; assert!(true, \\"{{}}\\", quirk); }}"#;\n'
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a string direct-case decoy replacing its active test function' mut_quirk_ledger_direct_case_string_decoy

mut_quirk_ledger_direct_case_cfg_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg-disabled direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[cfg(any())]
#[test]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg-disabled direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_disabled

mut_quirk_ledger_direct_case_cfg_attr_disabled() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg_attr-disabled direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[cfg_attr(all(), cfg(any()))]
#[test]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-disabled direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_attr_disabled

mut_quirk_ledger_direct_case_ignored() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("ignored direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[ignore]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an ignored direct case replacing its active test function' mut_quirk_ledger_direct_case_ignored

mut_quirk_ledger_direct_case_cfg_attr_ignored() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("cfg_attr-ignored direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[cfg_attr(all(), ignore)]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    assert!(true, "{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a cfg_attr-ignored direct case replacing its active test function' mut_quirk_ledger_direct_case_cfg_attr_ignored

mut_quirk_ledger_direct_case_should_panic() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
name = "c_rst_0014_malformed_restore_header_is_rejected_through_public_api"
if text.count(f"fn {name}()") != 1:
    raise SystemExit("should-panic direct-case mutation subject is not unique")
text = text.replace(f"fn {name}()", f"fn disabled_{name}()", 1)
text += f'''\n#[test]
#[should_panic]
fn {name}() {{
    let quirk = "q-restore-header-parser-0128";
    panic!("{{}}", quirk);
}}
'''
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a should-panic direct case replacing its active test function' mut_quirk_ledger_direct_case_should_panic

mut_quirk_ledger_direct_case_inert_body_string() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{value:?} must be refused");'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("inert direct-case string mutation subject is not unique")
text = text.replace(old_binding, '    let _ = "q-restore-header-parser-0128";', 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an inert in-body string replacing an assertion-bound backlink' mut_quirk_ledger_direct_case_inert_body_string

mut_quirk_ledger_direct_case_ordinary_function() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
new_binding = '''    let quirk = "q-restore-header-parser-0128";
    fn assert_eq(_marker: &str) {}
    assert_eq(quirk);'''
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{value:?} must be refused");'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("ordinary-function direct-case mutation subject is not unique")
text = text.replace(old_binding, new_binding, 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'an ordinary function call replacing an assertion-macro backlink' mut_quirk_ledger_direct_case_ordinary_function

mut_quirk_ledger_direct_case_shadowed_macro() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("crates/gateway/tests/select_restore_intent.rs")
text = path.read_text()
old_binding = '    let quirk = "q-restore-header-parser-0128";'
new_binding = '''    let quirk = "q-restore-header-parser-0128";
    macro_rules! assert_eq {
        ($($token:tt)*) => {};
    }'''
old_assertion = '        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
new_assertion = '        assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);'
if text.count(old_binding) != 1 or text.count(old_assertion) != 1:
    raise SystemExit("shadowed-macro direct-case mutation subject is not unique")
text = text.replace(old_binding, new_binding, 1)
text = text.replace(old_assertion, new_assertion, 1)
path.write_text(text)
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a local no-op macro replacing an absolute assertion backlink' mut_quirk_ledger_direct_case_shadowed_macro

mut_quirk_ledger_forward_backlink() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("conformance/cases/select-restore/c-select-restore-0019.toml")
text = path.read_text()
old = 'quirks = ["q-restore-header-absence-0127"]'
if old not in text:
    raise SystemExit("forward-backlink mutation subject is missing")
path.write_text(text.replace(old, 'quirks = []', 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a source-to-case backlink being removed' mut_quirk_ledger_forward_backlink

mut_quirk_ledger_reverse_backlink() {
    python3 - <<'PYEOF'
import pathlib

path = pathlib.Path("conformance/cases/select-restore/c-select-restore-0040.toml")
text = path.read_text()
old = 'quirks = ["q-restore-select-members-0131"]'
new = 'quirks = ["q-restore-header-absence-0127", "q-restore-select-members-0131"]'
if old not in text:
    raise SystemExit("reverse-backlink mutation subject is missing")
path.write_text(text.replace(old, new, 1))
PYEOF
}
expect_fail check_quirk_ledger.sh \
    'a case naming a typed source without the reverse source backlink' mut_quirk_ledger_reverse_backlink

mut_quirk_ledger_spec_id_set() {
    mv spec/quirks/q-empty-0002.toml spec/quirks/q-empty-0002.missing
}
expect_fail check_quirk_ledger.sh \
    'one generated protected ID disappearing from the 96/157 typed set' mut_quirk_ledger_spec_id_set

if [[ $((cases - quirk_ledger_cases_before)) -ne 24 ]]; then
    fail_msg 'check_quirk_ledger.sh mutation census is not exactly 24 cases'
fi

unset GATEWAY_QUIRK_LEDGER_PARSE_CACHE
rm -f "$QUIRK_LEDGER_PARSE_CACHE"
QUIRK_LEDGER_PARSE_CACHE=""

fi

printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
