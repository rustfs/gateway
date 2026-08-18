#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_route_shadowing_authority.sh
#
# WHAT THIS CHECKS
#   That `model/overlays/route.toml` is the *only* place a cross-precedence
#   route shadowing pair is declared. Three properties, one per way the single
#   source can be lost:
#
#     1. Complete    — every `[[shadowing]]` entry carries `winner`,
#                      `shadowed`, exactly one of `reason` / `reason_ref`, and a
#                      non-empty `evidence` list.
#     2. No residual — no `ShadowingDecl` struct literal is written by hand
#                      anywhere under `crates/core/src/`. The runtime record
#                      arrives through the generated include and nowhere else.
#     3. No dual-write — the (winner, shadowed) pairs in
#                      `generated/route_shadowing.rs` are exactly the pairs the
#                      overlay declares, and the runtime constant is built from
#                      that one generated group.
#
# WHY
#   Cross-precedence overlap is legal, so the only thing standing between the
#   route table and an accidental ordering is that every such pair was reviewed
#   and written down with a reason. That record used to be hand-written Rust in
#   six files (rustfs/gateway#4). Two hand-written sources for one fact is the
#   defect this repository keeps re-finding: the reasons drift, and the copy
#   nobody updated reads exactly like the copy somebody did.
#
#   A missing `reason` or `evidence` is the same failure one field down. The
#   loader refuses both, and this guard refuses them again on the file itself —
#   because the loader only runs when somebody runs codegen, and a pair whose
#   reason was deleted still routes.
#
# HOW TO EXEMPT
#   Not applicable. Declare the pair in `model/overlays/route.toml` and run
#   `cargo xtask codegen`. A dialect's own declarations are not covered: they
#   arrive from outside this crate through `ShadowingDecls::and`, are checked
#   against the same table by `RouteTable::build`, and are the reason the
#   collection takes more than one group.
#
# USAGE
#   scripts/check_route_shadowing_authority.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_route_shadowing_authority.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

OVERLAY="model/overlays/route.toml"
GENERATED="generated/route_shadowing.rs"
RUNTIME="crates/core/src/route/shadowing.rs"
RUNTIME_SRC="crates/core/src"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_route_shadowing_authority.sh: required command is missing: python3\n' >&2
    exit 1
}

# Deliberately not `|| exit 0`. All three inputs exist in every checkout, so an
# absent one means this guard is running somewhere it cannot see what it is
# checking — and a check that reports success without checking anything is
# indistinguishable from one that passed.
for input in "$OVERLAY" "$GENERATED" "$RUNTIME"; do
    if [[ ! -f "$input" ]]; then
        printf 'check_route_shadowing_authority.sh: cannot read %s — refusing to report success without checking\n' \
            "$input" >&2
        exit 1
    fi
done
if [[ ! -d "$RUNTIME_SRC" ]]; then
    printf 'check_route_shadowing_authority.sh: cannot read %s — refusing to report success without checking\n' \
        "$RUNTIME_SRC" >&2
    exit 1
fi

python3 - "$OVERLAY" "$GENERATED" "$RUNTIME" "$RUNTIME_SRC" <<'PYEOF'
import pathlib
import re
import sys

overlay_path, generated_path, runtime_path, runtime_src = (pathlib.Path(a) for a in sys.argv[1:5])

status = 0


def bad(message):
    global status
    status = 1
    print(f"check_route_shadowing_authority: {message}", file=sys.stderr)


# ------------------------------------------------------------------ the overlay
# A deliberately small reader, matching the overlay grammar the model crate
# accepts: one `[[shadowing]]` header, then `key = value` lines until the next
# header. Anything it cannot read is reported rather than skipped.
overlay_text = overlay_path.read_text(encoding="utf-8")
blocks = []
current = None
for number, line in enumerate(overlay_text.splitlines(), start=1):
    stripped = line.strip()
    if stripped.startswith("#"):
        continue
    if stripped.startswith("["):
        if current is not None:
            blocks.append(current)
            current = None
        if stripped == "[[shadowing]]":
            current = {"line": number, "fields": {}}
        continue
    if current is None:
        continue
    match = re.match(r"([A-Za-z0-9_-]+)\s*=\s*(.+)$", stripped)
    if match:
        current["fields"][match.group(1)] = match.group(2).strip()
if current is not None:
    blocks.append(current)

if not blocks:
    bad(f"{overlay_path} declares no `[[shadowing]]` entry; it is the authority for the whole record")

overlay_pairs = []
for block in blocks:
    fields = block["fields"]
    where = f"{overlay_path}:{block['line']}"
    winner = fields.get("winner", "").strip('"')
    shadowed = fields.get("shadowed", "").strip('"')
    if not winner or not shadowed:
        bad(f"{where}: a shadowing entry needs both `winner` and `shadowed`")
        continue
    pair = (winner, shadowed)
    overlay_pairs.append(pair)
    label = f"{winner} over {shadowed}"
    has_reason = fields.get("reason", "").strip('"').strip() != ""
    has_reason_ref = fields.get("reason_ref", "").strip('"').strip() != ""
    if not has_reason and not has_reason_ref:
        bad(f"{where}: `{label}` carries no `reason` and no `reason_ref`; an undeclared ordering is a guess")
    if has_reason and has_reason_ref:
        bad(f"{where}: `{label}` carries both `reason` and `reason_ref`; exactly one says where the reasoning lives")
    evidence = fields.get("evidence", "")
    cited = re.findall(r'"([^"]+)"', evidence)
    if not evidence or not cited:
        bad(f"{where}: `{label}` cites no `evidence`; an unsourced ordering is a guess")

duplicates = {pair for pair in overlay_pairs if overlay_pairs.count(pair) > 1}
for winner, shadowed in sorted(duplicates):
    bad(f"{overlay_path}: `{winner} over {shadowed}` is declared twice")

# ---------------------------------------------------- no hand-written residual
# `crates/core/src` is the runtime. Its shadowing record arrives through the
# generated include; a struct literal here is a second source by construction.
# A dialect's declarations are deliberately out of scope — they live outside
# this crate and reach the table through `ShadowingDecls::and`.
for source in sorted(runtime_src.rglob("*.rs")):
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if "//" in line and line.index("//") < line.find("ShadowingDecl"):
            continue
        if re.search(r"(?<!struct )\bShadowingDecl\s*\{", line):
            bad(
                f"{source}:{number}: a hand-written `ShadowingDecl` literal. "
                f"The record is written in {overlay_path} and lowered by `cargo xtask codegen`; "
                "a second source is a second set of reasons, and two sets drift"
            )

# ------------------------------------------------------------- no dual-writing
runtime_text = runtime_path.read_text(encoding="utf-8")
groups = re.findall(r"ShadowingDecls::over\(&\[([^\]]*)\]\)", runtime_text)
if len(groups) != 1:
    bad(f"{runtime_path}: expected exactly one `ShadowingDecls::over(&[…])`, found {len(groups)}")
else:
    members = [member.strip().rstrip(",") for member in groups[0].split(",") if member.strip()]
    if members != ["data::SHADOWING"]:
        bad(
            f"{runtime_path}: the runtime record is built from {members!r}; it must be the one "
            "generated group `data::SHADOWING` and nothing else"
        )

generated_text = generated_path.read_text(encoding="utf-8")
generated_pairs = [
    (match.group(1), match.group(2))
    for match in re.finditer(r'winner:\s*"([^"]+)",\s*\n\s*shadowed:\s*"([^"]+)",', generated_text)
]
if not generated_pairs:
    bad(f"{generated_path}: carries no declaration; run `cargo xtask codegen`")

for pair in sorted(set(generated_pairs) - set(overlay_pairs)):
    bad(
        f"{generated_path}: `{pair[0]} over {pair[1]}` is not declared in {overlay_path}. "
        "The generated file is output, never a place to add a pair"
    )
for pair in sorted(set(overlay_pairs) - set(generated_pairs)):
    bad(
        f"{overlay_path}: `{pair[0]} over {pair[1]}` never reached {generated_path}; "
        "run `cargo xtask codegen`"
    )

sys.exit(status)
PYEOF
