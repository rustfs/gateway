#!/usr/bin/env bash
# a-asm-0023: every extension default documents its security consequence.
# Every public extension default states its security consequence at the implementation site.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
EXT_DIR="${ROOT_DIR}/crates/gateway/src/ext"

fail() {
    printf 'check_default_doc: %s\n' "$1" >&2
    exit 1
}

[[ -d "$EXT_DIR" ]] || fail 'gateway extension tree is missing'

subjects=(
    'cors.rs:CorsCacheConfig'
    'credential_guard.rs:CredentialGuardConfig'
    'governor/default.rs:DefaultGovernor'
    'governor/rates.rs:GovernorRates'
    'policy.rs:PolicyTimeout'
)

checked=0
for subject in "${subjects[@]}"; do
    relative="${subject%%:*}"
    type="${subject#*:}"
    file="${EXT_DIR}/${relative}"
    [[ -f "$file" ]] || fail "${relative} is missing"
    line="$(grep -nE "^impl Default for ${type}[[:space:]]*\\{" "$file" | cut -d: -f1)"
    [[ -n "$line" ]] || fail "${relative}: Default for ${type} is missing"
    start=$((line > 8 ? line - 8 : 1))
    sed -n "${start},$((line - 1))p" "$file" | grep -qF '/// # Security' \
        || fail "${relative}:${line}: Default for ${type} has no # Security section"
    checked=$((checked + 1))
done

actual="$(grep -RhsE '^impl Default for [A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{' "$EXT_DIR" --include='*.rs' | wc -l | tr -d '[:space:]')"
[[ "$actual" == "$checked" ]] || fail "found ${actual} Default implementations but documented ${checked}"

derived=0
while IFS='|' read -r relative type line documented; do
    [[ -n "$relative" ]] || continue
    [[ "$documented" == yes ]] \
        || fail "${relative}:${line}: derived Default for ${type} has no # Security section"
    checked=$((checked + 1))
    derived=$((derived + 1))
done < <(python3 - "$EXT_DIR" <<'PYEOF'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(
    r"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]\s*"
    r"pub\s+(?:struct|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.DOTALL,
)
for path in sorted(root.rglob("*.rs")):
    source = path.read_text()
    for match in pattern.finditer(source):
        if not re.search(r"(?:^|,)\s*Default\s*(?:,|$)", match.group("traits")):
            continue
        prefix = source[:match.start()].splitlines()
        docs = []
        while prefix and prefix[-1].lstrip().startswith("///"):
            docs.append(prefix.pop())
        documented = "yes" if any("/// # Security" in line for line in docs) else "no"
        line = source.count("\n", 0, match.start("name")) + 1
        print(f"{path.relative_to(root)}|{match.group('name')}|{line}|{documented}")
PYEOF
)

[[ "$derived" -gt 0 ]] || fail 'no public derived Default subject was found'
total=$((actual + derived))
printf 'OK: %s/%s extension defaults document security consequences\n' "$checked" "$total"
