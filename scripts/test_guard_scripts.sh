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

# Materialise a git-tracked copy of the repository in a fresh temp directory.
make_sandbox() {
    local dir
    dir="$(mktemp -d "${TMPDIR:-/tmp}/gateway-guard-test.XXXXXX")"
    (
        cd "$REPO_ROOT"
        git ls-files -z | tar -cf - --null -T - 2>/dev/null || {
            git ls-files | tar -cf - -T -
        }
    ) | (cd "$dir" && tar -xf -)
    (
        cd "$dir"
        git init -q .
        git add -A >/dev/null 2>&1
    )
    printf '%s' "$dir"
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
    rm -rf "$sandbox"
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
    printf 's3gate-types = { workspace = true }\n' >>crates/s3gate-xml/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'reverse edge s3gate-xml -> s3gate-types' mut_reverse_edge

mut_conformance_internal() {
    printf 's3gate-core = { workspace = true }\n' >>crates/s3gate-conformance/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'conformance reaching past the facade into s3gate-core' mut_conformance_internal

mut_unregistered_crate() {
    mkdir -p crates/s3gate-newthing
    printf '[package]\nname = "s3gate-newthing"\n\n[dependencies]\n' >crates/s3gate-newthing/Cargo.toml
}
expect_fail check_layer_dependencies.sh \
    'a new crate that is not registered in the allow matrix' mut_unregistered_crate

mut_rustfs_dep() {
    printf 'rustfs-ecstore = "0.1"\n' >>crates/s3gate-core/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a rustfs crate' mut_rustfs_dep

mut_ring2_dep() {
    printf 'rustfs-gateway-admin = "0.1"\n' >>crates/s3gate-http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    'ring-0 crate depending on a ring-2 crate' mut_ring2_dep

mut_stray_s3s() {
    printf 's3s = "0.11"\n' >>crates/s3gate-http/Cargo.toml
}
expect_fail check_ring_boundaries.sh \
    's3s dependency outside s3gate-types' mut_stray_s3s

mut_drop_delete_by() {
    grep -v '# DELETE BY' crates/s3gate-types/Cargo.toml >/tmp/.ct.$$ && mv /tmp/.ct.$$ crates/s3gate-types/Cargo.toml
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
    printf 'inventory = "0.3"\n' >>crates/s3gate-core/Cargo.toml
}
expect_fail check_no_global_registry_deps.sh \
    'an `inventory` dependency' mut_inventory

# NOTE: appended to a manifest whose last table is `[dependencies]`. Appending
# to s3gate-types would land the line in its `[features]` table, where it is
# correctly NOT a dependency.
mut_ctor() {
    printf 'ctor = "0.2"\n' >>crates/s3gate-xml/Cargo.toml
}
expect_fail check_no_global_registry_deps.sh \
    'a `ctor` dependency' mut_ctor

mut_derived_signature() {
    cat >crates/s3gate-sig/src/proof.rs <<'RS'
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
    grep -v 'Licensed under the Apache License' crates/s3gate-core/src/lib.rs >/tmp/.lh.$$ &&
        mv /tmp/.lh.$$ crates/s3gate-core/src/lib.rs
}
expect_fail check_license_headers.sh \
    'a Rust file with the licence header removed' mut_strip_header

printf '\n%s case(s), %s failure(s)\n' "$cases" "$failures"
[[ "$failures" -eq 0 ]]
