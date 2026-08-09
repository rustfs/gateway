#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Every hand-written Rust file answers responsibility, non-responsibility and upstream/downstream
#   within its first 45 lines.
# WHY
#   rustfs/backlog#1742 prevents agents from placing logic in a plausible but wrong module.
# HOW TO EXEMPT
#   There is no exemption. Add the missing module-level `//!` sentence.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
files=()
while IFS= read -r -d '' file; do
    files+=("$file")
done < <(find "$ROOT/crates" "$ROOT/xtask" \
    -path "$ROOT/crates/types/generated" -prune -o \
    -type f -name '*.rs' -print0)

awk -v root="$ROOT" '
    function add(value) { missing = missing (missing == "" ? "" : ",") value }
    function finish_file() {
        if (!started || (generated_candidate && generated)) return
        count++
        missing = ""
        if (!responsible) add("responsibility")
        if (!not_responsible) add("non-responsibility")
        if (!upstream) add("upstream")
        if (!downstream) add("downstream")
        if (missing != "") {
            printf "check_module_doc: %s is missing %s\n", relative, missing > "/dev/stderr"
            failures++
        }
    }
    FNR == 1 {
        finish_file()
        started = 1
        responsible = not_responsible = upstream = downstream = generated = 0
        relative = FILENAME
        if (index(relative, root "/") == 1) relative = substr(relative, length(root) + 2)
        generated_candidate = relative ~ /^crates\/macros\/tests\/expand\/.*\.expanded\.rs$/
    }
    FNR <= 45 {
        line = tolower($0)
        if (generated_candidate && line ~ /@generated/) generated = 1
        if (line ~ /^\/\/!/) {
            line = tolower($0)
            responsibility_line = line
            gsub(/not responsible for:/, "", responsibility_line)
            if (responsibility_line ~ /responsible for:/) responsible = 1
            if (line ~ /not responsible for:/) not_responsible = 1
            if (line ~ /upstream:/) upstream = 1
            if (line ~ /downstream:/) downstream = 1
        }
    }
    END {
        finish_file()
        if (failures > 0) exit 1
        printf "OK: %s/%s Rust files answer the three module questions\n", count, count
    }
' "${files[@]}"
