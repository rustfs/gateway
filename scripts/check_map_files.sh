#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Every workspace package has a three-column MAP.md of at most 100 lines, and no map directs an
#   agent to read a path forbidden by AGENTS.md.
# WHY
#   rustfs/backlog#1742 makes MAP.md the bounded entry point for choosing a task's <=8 input files.
# HOW TO EXEMPT
#   There is no exemption. Split an overgrown map; forbidden paths must name their safe substitute.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
failures=0
count=0

fail() {
    printf 'check_map_files: %s\n' "$*" >&2
    failures=$((failures + 1))
}

while IFS= read -r manifest; do
    package_dir="${manifest%/Cargo.toml}"
    map="${package_dir}/MAP.md"
    count=$((count + 1))
    if [[ ! -f "$map" ]]; then
        fail "${package_dir#"$ROOT"/} has no MAP.md"
        continue
    fi
    if [[ ! -f "$package_dir/README.md" ]]; then
        fail "${package_dir#"$ROOT"/} has no crate README.md"
    fi
    if ! grep -q '^\[package.metadata.docs.rs\]$' "$manifest" ||
        ! grep -q '^all-features = true$' "$manifest" ||
        ! grep -Fq 'rustdoc-args = ["--cfg", "docsrs"]' "$manifest"; then
        fail "${manifest#"$ROOT"/} is missing the docs.rs metadata contract"
    fi
    if [[ -f "$package_dir/src/lib.rs" ]] &&
        { ! grep -Fq '#![deny(missing_docs)]' "$package_dir/src/lib.rs" ||
          ! grep -Fq '#![doc = include_str!("../README.md")]' "$package_dir/src/lib.rs"; }; then
        fail "${package_dir#"$ROOT"/}/src/lib.rs does not enforce docs and include its README"
    fi
    lines=$(wc -l <"$map" | tr -d ' ')
    if (( lines > 100 )); then
        fail "${map#"$ROOT"/} has ${lines} lines; maximum is 100"
    fi
    if ! grep -Eq '^\|[[:space:]]*File[[:space:]]*\|[[:space:]]*Responsibility[[:space:]]*\|[[:space:]]*Read it when[[:space:]]*\|' "$map"; then
        fail "${map#"$ROOT"/} is missing the File / Responsibility / Read it when table"
    fi
    while IFS='|' read -r _ file _ when _; do
        if [[ "$file" =~ generated/|model/s3\.json|Cargo\.lock ]] &&
            [[ ! "$when" =~ [Nn]ever|[Dd]o[[:space:]]not|[Ff]orbidden ]]; then
            fail "${map#"$ROOT"/} recommends forbidden path:${file}"
        fi
    done <"$map"
done < <(find "$ROOT/crates" "$ROOT/xtask" -mindepth 1 -maxdepth 2 -type f -name Cargo.toml | sort)

format="$ROOT/docs/MAP-format.md"
if [[ ! -f "$format" ]]; then
    fail "docs/MAP-format.md is missing"
elif (( $(wc -l <"$format") > 50 )); then
    fail "docs/MAP-format.md exceeds its 50-line limit"
fi

if (( failures > 0 )); then
    exit 1
fi
printf 'OK: %s/%s workspace packages have bounded MAP.md files\n' "$count" "$count"
