#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_ring_boundaries.sh
#
# WHAT THIS CHECKS
#   That no ring-0/ring-1 crate (everything named `s3gate*` in this repository,
#   plus `xtask` and the workspace root) declares a dependency on:
#
#     a) any `rustfs-*` crate published by the rustfs/rustfs main repository, or
#     b) any ring-2 `rustfs-gateway-*` crate (RustFS-specific edge crates), or
#     c) `s3s` / `s3s-*`.
#
#   Exactly one exception exists for (c): `s3gate-types` may carry an OPTIONAL
#   `s3s` dependency behind its `compat-s3s` feature. That feature must keep a
#   `# DELETE BY` marker in the manifest — the guard fails if the marker is
#   removed, whether or not the dependency itself is present yet.
#
#   Dev-dependencies count. A dev-dependency is still an edge in the crate
#   graph and still breaks the cross-repository DAG for downstream consumers
#   that build with `--all-targets`.
#
# WHY
#   The cross-repository dependency graph is only acyclic because ring 0/1 never
#   points at rustfs. `rustfs-gateway-types` (ring 0) is consumed by
#   rustfs/ecstore, lifecycle, replication and the scanner; ring-2 crates
#   (`rustfs-gateway-admin`, `-console`, `-sts`, `-metadata-ext`, `-rpc`) depend
#   on ecstore/iam/policy in turn. A single ring-0 -> rustfs edge closes that
#   loop and makes the whole thing unbuildable. See rustfs/backlog#1677 §2
#   ("cross-repo dependency graph is a DAG") and ADR-0005.
#
#   The second reason is reuse: ring 0 + ring 1 are published as general-purpose
#   crates. Any project depending on them must not transitively pull in RustFS
#   business logic.
#
#   The s3s clause exists because the orphan rule (E0117, measured) forbids a
#   third crate from writing `impl From<s3s::X> for s3gate::X`. That forces the
#   migration conversions into `s3gate-types`, and an un-dated exception spreads.
#
# HOW TO EXEMPT
#   Add a line to `scripts/allowances/ring-boundary-allowances.txt`
#   (create the file if it does not exist yet):
#
#       <crate> -> <dependency>    # <reason, ADR link, and removal milestone>
#
#   An allowance here is an architectural decision, not a convenience: it must
#   cite an ADR. There is deliberately no `--update-baseline` flag — a ring
#   violation should cost a human review, not one command.
#
# USAGE
#   scripts/check_ring_boundaries.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_ring_boundaries.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DEPS_AWK="${SCRIPT_DIR}/lib/cargo_deps.awk"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/ring-boundary-allowances.txt"

# The one crate allowed to carry an s3s compat edge, and the feature gating it.
COMPAT_CRATE="s3gate-types"
COMPAT_FEATURE="compat-s3s"

cd "$ROOT_DIR"

status=0

fail() {
    printf '%s\n' "$*" >&2
    status=1
}

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

manifests=()
while IFS= read -r manifest; do
    [[ -n "$manifest" ]] && manifests+=("$manifest")
done < <(ls -1 Cargo.toml crates/*/Cargo.toml xtask/Cargo.toml 2>/dev/null || true)

if [[ "${#manifests[@]}" -eq 0 ]]; then
    printf 'check_ring_boundaries: no manifests found under %s\n' "$ROOT_DIR" >&2
    exit 1
fi

for manifest in "${manifests[@]}"; do
    if [[ "$manifest" == "Cargo.toml" ]]; then
        crate="<workspace>"
    else
        crate="$(basename "$(dirname "$manifest")")"
    fi

    while IFS=$'\t' read -r kind dep; do
        [[ -z "${dep:-}" ]] && continue

        case "$dep" in
        rustfs-gateway | rustfs-gateway-*)
            if is_allowed_exception "$crate" "$dep"; then continue; fi
            fail "${manifest}: ring-0/1 crate '${crate}' depends on ring-2 crate '${dep}' (${kind}); ring 2 is RustFS-specific and must never be reachable from the reusable rings"
            ;;
        rustfs | rustfs-* | rustfs_*)
            if is_allowed_exception "$crate" "$dep"; then continue; fi
            fail "${manifest}: ring-0/1 crate '${crate}' depends on rustfs crate '${dep}' (${kind}); this closes the cross-repository dependency cycle (rustfs consumes ring 0, so ring 0 must never consume rustfs)"
            ;;
        s3s | s3s-*)
            if is_allowed_exception "$crate" "$dep"; then continue; fi
            if [[ "$crate" != "$COMPAT_CRATE" ]]; then
                fail "${manifest}: '${crate}' depends on '${dep}' (${kind}); s3s may only be reached from '${COMPAT_CRATE}' behind its '${COMPAT_FEATURE}' feature (orphan rule E0117), and nowhere else"
                continue
            fi
            if ! grep -Eq "^[[:space:]]*${dep}[[:space:]]*=.*optional[[:space:]]*=[[:space:]]*true" "$manifest"; then
                fail "${manifest}: the '${dep}' dependency must be declared 'optional = true' so it is only pulled in by the '${COMPAT_FEATURE}' feature"
            fi
            if ! grep -Eq "^[[:space:]]*${COMPAT_FEATURE}[[:space:]]*=" "$manifest"; then
                fail "${manifest}: '${dep}' is declared but the '${COMPAT_FEATURE}' feature that is supposed to gate it does not exist"
            fi
            ;;
        esac
    done < <(awk -f "$DEPS_AWK" "$manifest")
done

# -----------------------------------------------------------------------------
# The compat-s3s escape hatch must keep its expiry marker, dependency or not.
# This runs even while the feature is an empty placeholder: the marker is what
# stops the exception from quietly becoming permanent.
# -----------------------------------------------------------------------------
compat_manifest="crates/${COMPAT_CRATE}/Cargo.toml"
if [[ -f "$compat_manifest" ]] && grep -Eq "^[[:space:]]*${COMPAT_FEATURE}[[:space:]]*=" "$compat_manifest"; then
    if ! grep -q '# DELETE BY' "$compat_manifest"; then
        fail "${compat_manifest}: the '${COMPAT_FEATURE}' feature is the only sanctioned s3s escape hatch and must carry a '# DELETE BY <milestone>' marker; without an expiry the exception spreads"
    fi
fi

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Ring boundary violation. See rustfs/backlog#1677 and ADR-0005.
Ring 0 (protocol core) and ring 1 (server runtime) are published as
general-purpose crates and are consumed by rustfs itself; an edge back into
rustfs or into a ring-2 crate makes the cross-repository graph cyclic.
Move the RustFS-specific code into a ring-2 crate instead.
EOF
fi

exit "$status"
