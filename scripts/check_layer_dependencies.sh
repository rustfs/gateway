#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_layer_dependencies.sh
#
# WHAT THIS CHECKS
#   Every internal (`rustfs-gateway` / `rustfs-gateway-*`) dependency edge declared in
#   `crates/*/Cargo.toml` and `xtask/Cargo.toml`, against the allow matrix
#   below. Three rules in one pass:
#
#     1. Direction  — a crate may only depend on the crates its own row lists.
#                     A reverse edge (e.g. `rustfs-gateway-xml` depending on
#                     `rustfs-gateway-types`) fails.
#     2. Acyclicity — the matrix is declared in topological order and every
#                     allowed edge must point strictly backwards in that order.
#                     This is checked against the matrix itself before any
#                     manifest is read, so a future edit cannot introduce a
#                     cycle by adding a row in the wrong place.
#     3. Facade-only — `rustfs-gateway-conformance` may depend on the `rustfs-gateway` facade
#                     and nothing else internal. It is a product other S3
#                     implementations run against themselves, so it must
#                     exercise the public API, not internal crates.
#
#   Registration is mandatory: a crate directory that is not in the matrix
#   fails the check. Adding a crate is a deliberate architectural act.
#
#   NOT checked here (by design, to keep one guard per question):
#     - `rustfs-*` / ring-2 dependencies and the `s3s` compat exception
#       -> `check_ring_boundaries.sh`
#     - global-registry crates (`inventory`, `linkme`)
#       -> `check_no_inventory.sh`
#
# WHY
#   The layering is not an aesthetic preference; three concrete constraints
#   ride on it (see rustfs/backlog#1723 and AGENTS.md "Dependency Boundaries"):
#     - `rustfs-gateway-stream` must stay standalone, otherwise
#       `GetObjectOutput.body: StreamingBlob` creates a `rustfs-gateway-types` <->
#       `rustfs-gateway-http` dependency cycle;
#     - `rustfs-gateway-types`' `compat-s3s` feature is the only place a core crate may
#       ever reach for s3s, because the orphan rule (E0117) forbids writing
#       `impl From<s3s::X> for rustfs-gateway::X` from a third crate;
#     - `rustfs-gateway-sig` must freeze `PayloadMode` before `rustfs-gateway-http` decodes
#       chunked framing, because the framing mode is derived from the signature.
#   The first codegen PR touches these boundaries, so they must be hard before
#   P1 starts.
#
# HOW TO EXEMPT
#   Add a line to `scripts/allowances/layer-dependency-allowances.txt`
#   (create the file if it does not exist yet):
#
#       <crate> -> <dependency>    # <reason, issue link, and removal trigger>
#
#   The file is intentionally reviewed by humans, not generated. An allowance
#   without a stated removal trigger should not survive review.
#
# USAGE
#   scripts/check_layer_dependencies.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_layer_dependencies.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DEPS_AWK="${SCRIPT_DIR}/lib/cargo_deps.awk"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/layer-dependency-allowances.txt"

cd "$ROOT_DIR"

# -----------------------------------------------------------------------------
# The allow matrix. Format: "<crate>|<space separated allowed internal deps>".
#
# DECLARATION ORDER IS THE TOPOLOGICAL ORDER. Every allowed dependency must
# appear ABOVE its dependent; rule 2 enforces this, which is what makes the
# matrix provably acyclic. Keep it byte-for-byte in sync with the dependency
# graph in AGENTS.md — AGENTS.md is the source of truth, this list follows it.
# -----------------------------------------------------------------------------
LAYERS=(
    "rustfs-gateway-macros|"
    "rustfs-gateway-model|"
    "rustfs-gateway-stream|"
    "rustfs-gateway-xml|"
    "rustfs-gateway-codegen|rustfs-gateway-model"
    "rustfs-gateway-types|rustfs-gateway-xml rustfs-gateway-stream"
    "rustfs-gateway-http|rustfs-gateway-types rustfs-gateway-stream"
    "rustfs-gateway-sig|rustfs-gateway-http rustfs-gateway-types rustfs-gateway-stream"
    "rustfs-gateway-core|rustfs-gateway-sig rustfs-gateway-http rustfs-gateway-types rustfs-gateway-xml rustfs-gateway-stream"
    "rustfs-gateway|rustfs-gateway-core rustfs-gateway-sig rustfs-gateway-http rustfs-gateway-types rustfs-gateway-xml rustfs-gateway-stream"
    "rustfs-gateway-conformance|rustfs-gateway"
    "xtask|rustfs-gateway-codegen rustfs-gateway-model"
)

status=0

fail() {
    printf '%s\n' "$*" >&2
    status=1
}

rank_of() {
    local want="$1" idx=0 entry
    for entry in "${LAYERS[@]}"; do
        idx=$((idx + 1))
        if [[ "${entry%%|*}" == "$want" ]]; then
            printf '%s' "$idx"
            return 0
        fi
    done
    return 1
}

allowed_of() {
    local want="$1" entry
    for entry in "${LAYERS[@]}"; do
        if [[ "${entry%%|*}" == "$want" ]]; then
            printf '%s' "${entry#*|}"
            return 0
        fi
    done
    return 1
}

is_internal() {
    [[ "$1" == "rustfs-gateway" || "$1" == rustfs-gateway-* ]]
}

# -----------------------------------------------------------------------------
# Allowances
# -----------------------------------------------------------------------------
ALLOWANCES=""
if [[ -f "$ALLOWANCE_FILE" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -s ' \t' ' ')"
        line="${line# }"
        line="${line% }"
        [[ -z "$line" ]] && continue
        ALLOWANCES="${ALLOWANCES}${line}
"
    done <"$ALLOWANCE_FILE"
fi

is_allowed_exception() {
    local crate="$1" dep="$2"
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "${crate} -> ${dep}"
}

# -----------------------------------------------------------------------------
# Rule 2: the matrix itself must be a DAG (checked before any manifest is read)
# -----------------------------------------------------------------------------
for entry in "${LAYERS[@]}"; do
    crate="${entry%%|*}"
    crate_rank="$(rank_of "$crate")"
    for dep in ${entry#*|}; do
        if ! dep_rank="$(rank_of "$dep")"; then
            fail "allow matrix: '${crate}' is allowed to depend on unknown crate '${dep}'"
            continue
        fi
        if [[ "$dep_rank" -ge "$crate_rank" ]]; then
            fail "allow matrix is not a DAG: '${crate}' (position ${crate_rank}) may not be allowed to depend on '${dep}' (position ${dep_rank}); a dependency must be declared above its dependent"
        fi
    done
done

if [[ "$status" -ne 0 ]]; then
    printf '\nThe allow matrix in %s is internally inconsistent. Fix it before touching manifests.\n' \
        "${BASH_SOURCE[0]}" >&2
    exit "$status"
fi

# -----------------------------------------------------------------------------
# Rules 1 and 3: scan the manifests
# -----------------------------------------------------------------------------
manifests=()
while IFS= read -r manifest; do
    [[ -n "$manifest" ]] && manifests+=("$manifest")
done < <(ls -1 crates/*/Cargo.toml xtask/Cargo.toml 2>/dev/null || true)

if [[ "${#manifests[@]}" -eq 0 ]]; then
    printf 'check_layer_dependencies: no crate manifests found under %s\n' "$ROOT_DIR" >&2
    exit 1
fi

for manifest in "${manifests[@]}"; do
    # The matrix is keyed by PACKAGE name, which no longer equals the directory name:
    # directories dropped the prefix (crates/types) while packages kept it
    # (rustfs-gateway-types), matching the convention in the rustfs main repository.
    crate="$(awk -F'"' '/^name[[:space:]]*=/ {print $2; exit}' "$manifest")"
    if [[ -z "$crate" ]]; then
        fail "${manifest}: no package name found"
        continue
    fi

    if ! allowed="$(allowed_of "$crate")"; then
        fail "${manifest}: crate '${crate}' is not registered in the layer allow matrix; add a row to LAYERS in $(basename "${BASH_SOURCE[0]}") and to the dependency graph in AGENTS.md"
        continue
    fi

    while IFS=$'\t' read -r kind dep; do
        [[ -z "${dep:-}" ]] && continue
        is_internal "$dep" || continue

        # A dev-dependency on a higher layer is not a cycle. Cargo builds dev-deps only for
        # tests and explicitly permits them to point back at a dependent crate, which is how a
        # proc-macro crate tests that its expansion produces the same registry as hand-written
        # code: it needs the real types to compare against. Treating dev-deps like build deps
        # would either forbid that test or push it into the crate it is meant to check.
        # Every other kind is still held to the matrix.
        if [[ "$kind" == "dev-dependencies" ]]; then
            continue
        fi

        allowed_here=0
        for candidate in $allowed; do
            if [[ "$candidate" == "$dep" ]]; then
                allowed_here=1
                break
            fi
        done
        [[ "$allowed_here" -eq 1 ]] && continue

        if is_allowed_exception "$crate" "$dep"; then
            continue
        fi

        if [[ "$crate" == "rustfs-gateway-conformance" ]]; then
            fail "${manifest}: '${crate}' depends on internal crate '${dep}' (${kind}); the conformance suite is a product run against other S3 implementations and may only use the public API of the 'rustfs-gateway' facade"
        elif rank_of "$dep" >/dev/null 2>&1 && [[ "$(rank_of "$dep")" -gt "$(rank_of "$crate")" ]]; then
            fail "${manifest}: '${crate}' depends on '${dep}' (${kind}), which sits ABOVE it in the layering; this is a reverse dependency and would eventually close a cycle"
        else
            fail "${manifest}: '${crate}' depends on '${dep}' (${kind}), which its row in the allow matrix does not permit (allowed: ${allowed:-none})"
        fi
    done < <(awk -f "$DEPS_AWK" "$manifest")
done

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Layer violation. See AGENTS.md "Dependency Boundaries" and rustfs/backlog#1723.
Either move the code to the correct crate, or — if the edge is genuinely
required — record it in scripts/allowances/layer-dependency-allowances.txt with
a reason and a removal trigger, and say so in the PR body.
EOF
fi

exit "$status"
