#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_no_global_registry_deps.sh
#
# WHAT THIS CHECKS
#   That no manifest in the workspace declares a dependency on a link-time
#   global-registry / life-before-main crate: `inventory`, `linkme` or `ctor`
#   (any dependency kind, including dev- and build-dependencies).
#
# WHY
#   ADR-0003: operation registration is explicit and compile-time, not
#   collected from a link-section at startup. Global registries look convenient
#   and cost three properties this project cannot give up:
#
#     - Determinism. Registration order depends on link order, so the routing
#       table can differ between a debug build, a release build, and an LTO
#       build. Protocol behaviour must not depend on the linker.
#     - Discoverability. `rustfs-gateway` is meant to be readable by both humans and
#       agents: "where is this operation registered?" must be answerable by
#       grep, not by knowing that a macro emitted a static into a link section.
#     - Dead-code elimination. Registry entries are unconditionally live, so
#       a consumer that only needs ten operations still links all of them.
#
#   The failure mode is also silent: `inventory`/`linkme` entries in a staticlib
#   or behind `--gc-sections` simply disappear, and the operation 404s in
#   production while every test passes. `ctor` is banned for the same reason
#   one level down: it runs arbitrary code before `main`, in unspecified order,
#   outside any panic or tracing context.
#
# HOW TO EXEMPT
#   Add a line to `scripts/allowances/global-registry-allowances.txt`
#   (create the file if it does not exist yet):
#
#       <crate> -> <dependency>    # <reason and the ADR amendment that allows it>
#
#   ADR-0003 is a merged ADR. An allowance here means the ADR is being
#   contradicted, so it needs an ADR amendment, not just a comment.
#
# USAGE
#   scripts/check_no_global_registry_deps.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_no_global_registry_deps.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DEPS_AWK="${SCRIPT_DIR}/lib/cargo_deps.awk"
ALLOWANCE_FILE="${SCRIPT_DIR}/allowances/global-registry-allowances.txt"

cd "$ROOT_DIR"

BANNED_CRATES="inventory linkme ctor"

status=0

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

is_allowed() {
    [[ -z "$ALLOWANCES" ]] && return 1
    printf '%s' "$ALLOWANCES" | grep -qxF "$1 -> $2"
}

manifests=()
while IFS= read -r manifest; do
    [[ -n "$manifest" ]] && manifests+=("$manifest")
done < <(git ls-files -- 'Cargo.toml' '*/Cargo.toml' 2>/dev/null || true)

if [[ "${#manifests[@]}" -eq 0 ]]; then
    printf 'check_no_global_registry_deps: no tracked Cargo.toml found under %s\n' "$ROOT_DIR" >&2
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
        for banned in $BANNED_CRATES; do
            [[ "$dep" == "$banned" ]] || continue
            if is_allowed "$crate" "$dep"; then
                continue
            fi
            printf "%s: '%s' declares the global-registry crate '%s' (%s); ADR-0003 requires explicit compile-time registration\n" \
                "$manifest" "$crate" "$dep" "$kind" >&2
            status=1
        done
    done < <(awk -f "$DEPS_AWK" "$manifest")
done

if [[ "$status" -ne 0 ]]; then
    cat >&2 <<'EOF'

Global registry crates are banned by ADR-0003. Register the operation
explicitly instead — a plain `const` table or a generated `match` keeps the
routing table deterministic, greppable, and dead-code-eliminable.
EOF
fi

exit "$status"
