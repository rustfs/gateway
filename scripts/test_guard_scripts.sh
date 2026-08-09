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

# One build directory, shared with whoever ran this. A guard that declares
# REQUIRES-BUILD compiles the workspace, and a sandbox with its own target/ compiles it
# from nothing — three times over, once as the positive control and once per negative
# case. That took this suite from under a minute to past ten, which is the same
# budget failure the sandbox reuse above was written to avoid, arriving by a different
# road.
#
# Sharing is sound because a sandbox differs from the tree only in the one file a case
# mutates: every dependency is already built, and cargo rebuilds the workspace crates
# alone. It is not a correctness shortcut — the guards still read the sandbox, and
# CARGO_TARGET_DIR changes where objects land, not what is compiled.
GUARD_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/guard-self-test"
export CARGO_TARGET_DIR="$GUARD_TARGET_DIR"

make_sandbox() {
    if [[ -n "$SANDBOX" ]]; then
        (
            cd "$SANDBOX"
            git clean -fdq >/dev/null 2>&1 || true
            git checkout -f HEAD -- . >/dev/null 2>&1
        )
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
    # Include new, unignored files: a guard introduced in the same change must be able to test its
    # own inputs before the author stages them.
    (cd "$REPO_ROOT" && { git ls-files; git ls-files --others --exclude-standard; } | sort -u) >"$list"
    (cd "$REPO_ROOT" && tar -cf - -T "$list") | (cd "$dir" && tar -xf -)
    rm -f "$list"
    (
        cd "$dir"
        git init -q .
        git add -A >/dev/null 2>&1
        git -c user.name=t -c user.email=t@t commit -qm base >/dev/null 2>&1
    )
    SANDBOX="$dir"
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

# expect_fail <guard> <description> <mutation-fn>
# Runs the mutation inside a sandbox, then asserts the guard exits non-zero.
expect_fail() {
    local guard="$1" desc="$2" mutate="$3"
    local sandbox rc=0
    cases=$((cases + 1))
    make_sandbox
    sandbox="$SANDBOX"
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
    "        AllowOrigin::Reflected(_) | AllowOrigin::Wildcard => None,",
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


printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
