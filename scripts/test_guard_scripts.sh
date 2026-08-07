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

pass_msg() { printf '  ok   %s\n' "$*"; }
fail_msg() {
    printf '  FAIL %s\n' "$*" >&2
    failures=$((failures + 1))
}

# One sandbox, reused. Each negative case mutates it, the guard runs, and the tree is
# reset with `git checkout` plus a clean of untracked files — a few milliseconds instead
# of a fresh copy. Twenty-nine full copies plus twenty-nine `git add -A` runs pushed this
# suite past the ten-minute budget of the CI job it lives in, which is a gate that fails
# for a reason having nothing to do with what it checks.
SANDBOX=""

make_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        (
            cd "$SANDBOX"
            git checkout -- . >/dev/null 2>&1 || true
            git clean -fdq >/dev/null 2>&1 || true
        )
        printf '%s' "$SANDBOX"
        return
    fi

    local dir list
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
    list="$(mktemp "${TMPDIR:-/tmp}/gateway-guard-files.XXXXXX")"
    (cd "$REPO_ROOT" && git ls-files) >"$list"
    (cd "$REPO_ROOT" && tar -cf - -T "$list") | (cd "$dir" && tar -xf -)
    rm -f "$list"
    (
        cd "$dir"
        git init -q .
        git add -A >/dev/null 2>&1
        git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1
    )
    SANDBOX="$dir"
    printf '%s' "$dir"
}

cleanup_sandbox() {
    # Must return 0: an EXIT trap's status becomes the script's status, so a bare
    # `[[ -n "$SANDBOX" ]] && rm -rf` reports failure whenever no sandbox was made,
    # and the suite would exit 1 while printing "0 failures".
    if [[ -n "$SANDBOX" ]]; then
        rm -rf "$SANDBOX"
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
    sandbox="$(make_sandbox)"
    (cd "$sandbox" && "$mutate" >/dev/null)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches (unstaged): ${desc}"
    else
        fail_msg "${guard} did NOT catch (unstaged): ${desc}"
    fi
}

# expect_fail <guard> <description> <mutation-fn>
# Runs the mutation inside a sandbox, then asserts the guard exits non-zero.
expect_fail() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    sandbox="$(make_sandbox)"
    (cd "$sandbox" && "$mutate" >/dev/null)
    (cd "$sandbox" && git add -A >/dev/null 2>&1)
    GATEWAY_CHECK_ROOT="$sandbox" "${SCRIPT_DIR}/${guard}" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        pass_msg "${guard} catches: ${desc}"
    else
        fail_msg "${guard} did NOT catch: ${desc}"
    fi
}

# -----------------------------------------------------------------------------
# Positive control: the repository as it stands must be clean.
# -----------------------------------------------------------------------------
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

mut_rustfs_dep() {
    printf 'rustfs-ecstore = "0.1"\n' >>crates/core/Cargo.toml
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
    printf 'inventory = "0.3"\n' >>crates/core/Cargo.toml
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
expect_fail check_english_only.sh \
    'a Chinese comment in a source file' mut_chinese_comment

mut_chinese_markdown() {
    printf '\n\xe4\xb8\xad\xe6\x96\x87\n' >>docs/msrv.md
}
expect_fail check_english_only.sh \
    'a Chinese paragraph in a Markdown document' mut_chinese_markdown


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
expect_fail_unstaged check_english_only.sh \
    'CJK in a file that has never been added to the index' mut_untracked_chinese_source

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
# document over the object; shrinking it silently is how a closed exposure keeps
# being counted, and a count that only ever says 46 is a count nobody reads.
#
# Both controls therefore mutate the register rather than the tree, because the
# register is the artefact the guard exists to keep honest.
# -----------------------------------------------------------------------------

mut_forgotten_exposure() {
    grep -v 'PutObjectAcl' scripts/allowances/route-coverage-allowances.txt >/tmp/rc-allow.$$
    mv /tmp/rc-allow.$$ scripts/allowances/route-coverage-allowances.txt
}
expect_fail check_route_coverage.sh \
    'a swallowed operation missing from the register' mut_forgotten_exposure

mut_stale_exposure() {
    printf 'NoSuchOperation -> NoSuchNeighbour\n' >>scripts/allowances/route-coverage-allowances.txt
}
expect_fail check_route_coverage.sh \
    'a register entry for an exposure that no longer exists' mut_stale_exposure

printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
