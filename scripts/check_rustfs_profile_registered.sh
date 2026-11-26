#!/usr/bin/env bash
set -euo pipefail

# WHAT: Every legacy compatibility switch applied by `ServiceBuilder::rustfs_profile` and
#       `SigV4Authenticator::rustfs_profile` is registered in `docs/rustfs-profile.md` and in the
#       `crates/gateway/src/builder/rustfs_profile.rs` rustdoc tables with a concrete tracking
#       reference and retirement/exit condition, with zero `unregistered` entries.
# WHY:  rustfs/gateway#1634 closed ~28 unregistered compatibility switches that had accumulated
#       without tracking entries or retirement criteria. Failing closed here prevents new
#       unregistered or undocumented legacy switches from re-entering the RustFS profile.
# HOW TO EXEMPT: There is no exemption. Register every switch with a real issue, ADR, or ledger
#       entry and a concrete exit condition, or retire the switch from the preset.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_rustfs_profile_registered)" || exit 1

"$PYTHON" - "$REPO_ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
doc_path = root / "docs/rustfs-profile.md"
src_path = root / "crates/gateway/src/builder/rustfs_profile.rs"

for rel, path in (
    ("docs/rustfs-profile.md", doc_path),
    ("crates/gateway/src/builder/rustfs_profile.rs", src_path),
):
    if not path.is_file():
        raise SystemExit(f"check_rustfs_profile_registered: required input is missing: {rel}")

doc_text = doc_path.read_text(encoding="utf-8")
src_text = src_path.read_text(encoding="utf-8")

TRACKING_RE = re.compile(
    r'(#\d+|ADR-\d+|GW-[A-Z]+|R-?\d+|"[^"]+")'
)
UNREGISTERED_RE = re.compile(r"\bunregistered\b", re.IGNORECASE)
REGISTER_PLACEHOLDER_RE = re.compile(r"^\s*register\s*;", re.IGNORECASE)


def normalize_switch(cell: str) -> str:
    m = re.search(r"`([a-z0-9_]+)(?:\([^)]*\))?`", cell)
    if m is None:
        raise SystemExit(f"check_rustfs_profile_registered: unreadable switch cell: {cell!r}")
    return m.group(1)


def parse_md_table(section_text: str, expected_cols: int, origin: str) -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    in_table = False
    for raw in section_text.splitlines():
        line = raw.strip()
        if line.startswith("| Switch |"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        parts = [c.strip() for c in line.strip("|").split("|")]
        if all(set(p) <= {"-", ":", " "} for p in parts):
            continue
        if len(parts) != expected_cols:
            raise SystemExit(
                f"check_rustfs_profile_registered: {origin} row has {len(parts)} columns, "
                f"expected {expected_cols}: {line}"
            )
        switch = normalize_switch(parts[0])
        if switch in rows:
            raise SystemExit(f"check_rustfs_profile_registered: duplicate switch {switch!r} in {origin}")
        rows[switch] = tuple(parts[1:])
    if not rows:
        raise SystemExit(f"check_rustfs_profile_registered: no switch rows found in {origin}")
    return rows


# 1. Parse docs/rustfs-profile.md tables.
builder_heading = "### Builder half: `ServiceBuilder::rustfs_profile`"
auth_heading = "### Authenticator half: `SigV4Authenticator::rustfs_profile`"
if builder_heading not in doc_text or auth_heading not in doc_text:
    raise SystemExit("check_rustfs_profile_registered: docs/rustfs-profile.md is missing builder or authenticator section")

b_idx = doc_text.index(builder_heading)
a_idx = doc_text.index(auth_heading)
doc_builder = parse_md_table(doc_text[b_idx:a_idx], 4, "docs/rustfs-profile.md (builder)")
doc_auth = parse_md_table(doc_text[a_idx:], 4, "docs/rustfs-profile.md (authenticator)")

errors: list[str] = []

for origin, table in (
    ("docs/rustfs-profile.md (builder)", doc_builder),
    ("docs/rustfs-profile.md (authenticator)", doc_auth),
):
    for switch, (_behavior, tracking, exit_cond) in table.items():
        if UNREGISTERED_RE.search(tracking):
            errors.append(f"{origin}: switch `{switch}` is still marked unregistered: {tracking!r}")
        if not TRACKING_RE.search(tracking):
            errors.append(f"{origin}: switch `{switch}` lacks a tracking reference: {tracking!r}")
        if not exit_cond or UNREGISTERED_RE.search(exit_cond) or REGISTER_PLACEHOLDER_RE.search(exit_cond):
            errors.append(f"{origin}: switch `{switch}` lacks a concrete retirement/exit condition: {exit_cond!r}")

# 2. Parse module rustdoc tables in crates/gateway/src/builder/rustfs_profile.rs.
doc_lines = "\n".join(
    line[4:] if line.startswith("//! ") else ("" if line == "//!" else line)
    for line in src_text.splitlines()
    if line.startswith("//!")
)
rb_heading = "Builder half, `ServiceBuilder::rustfs_profile`:"
ra_heading = "Authenticator half, `SigV4Authenticator::rustfs_profile`:"
if rb_heading not in doc_lines or ra_heading not in doc_lines:
    raise SystemExit("check_rustfs_profile_registered: rustfs_profile.rs rustdoc is missing builder or authenticator table")

rb_idx = doc_lines.index(rb_heading)
ra_idx = doc_lines.index(ra_heading)
src_doc_builder = parse_md_table(doc_lines[rb_idx:ra_idx], 3, "rustfs_profile.rs rustdoc (builder)")
src_doc_auth = parse_md_table(doc_lines[ra_idx:], 3, "rustfs_profile.rs rustdoc (authenticator)")

for origin, table in (
    ("rustfs_profile.rs rustdoc (builder)", src_doc_builder),
    ("rustfs_profile.rs rustdoc (authenticator)", src_doc_auth),
):
    for switch, (_behavior, tracking) in table.items():
        if UNREGISTERED_RE.search(tracking):
            errors.append(f"{origin}: switch `{switch}` is still marked unregistered: {tracking!r}")
        if not TRACKING_RE.search(tracking):
            errors.append(f"{origin}: switch `{switch}` lacks a tracking reference: {tracking!r}")


# 3. Extract switches actually invoked by ServiceBuilder::rustfs_profile and SigV4Authenticator::rustfs_profile.
def extract_fn_body(source: str, impl_marker: str) -> str:
    start_impl = source.find(impl_marker)
    if start_impl < 0:
        raise SystemExit(f"check_rustfs_profile_registered: cannot find {impl_marker!r}")
    fn_idx = source.find("pub fn rustfs_profile(", start_impl)
    if fn_idx < 0:
        raise SystemExit(f"check_rustfs_profile_registered: cannot find rustfs_profile in {impl_marker!r}")
    brace = source.index("{", fn_idx)
    depth = 0
    for pos in range(brace, len(source)):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : pos]
    raise SystemExit(f"check_rustfs_profile_registered: unbalanced braces in {impl_marker!r}")


def extract_chained_switches(body: str) -> set[str]:
    switches: set[str] = set()
    for raw in body.splitlines():
        code = raw.split("//", 1)[0].strip()
        if not code:
            continue
        m = re.match(r"^(?:self)?\.([a-z][a-z0-9_]*)\s*\(", code)
        if m is not None:
            switches.add(m.group(1))
    return switches


code_builder = extract_chained_switches(extract_fn_body(src_text, "impl ServiceBuilder"))
code_auth = extract_chained_switches(extract_fn_body(src_text, "impl SigV4Authenticator"))

for label, code_set, doc_set, rustdoc_set in (
    ("builder", code_builder, set(doc_builder.keys()), set(src_doc_builder.keys())),
    ("authenticator", code_auth, set(doc_auth.keys()), set(src_doc_auth.keys())),
):
    missing_doc = sorted(code_set - doc_set)
    extra_doc = sorted(doc_set - code_set)
    missing_rustdoc = sorted(code_set - rustdoc_set)
    extra_rustdoc = sorted(rustdoc_set - code_set)
    if missing_doc:
        errors.append(f"{label} switches in code missing from docs/rustfs-profile.md: {missing_doc}")
    if extra_doc:
        errors.append(f"{label} switches in docs/rustfs-profile.md not applied by rustfs_profile(): {extra_doc}")
    if missing_rustdoc:
        errors.append(f"{label} switches in code missing from rustfs_profile.rs rustdoc: {missing_rustdoc}")
    if extra_rustdoc:
        errors.append(f"{label} switches in rustfs_profile.rs rustdoc not applied by rustfs_profile(): {extra_rustdoc}")

if errors:
    for err in errors:
        print(f"check_rustfs_profile_registered: {err}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"OK: {len(code_builder)} builder and {len(code_auth)} authenticator RustFS-profile switches "
    "are registered with concrete exit conditions and match docs/rustfs-profile.md"
)
PY
