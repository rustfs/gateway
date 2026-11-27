#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps ADR-0056's bearer and header-token verdict, receipt, floor-claim, and context
#       construction sealed behind the #[doc(hidden)] __facade_internal bridge, never re-exported
#       by rustfs-gateway, allowlisted to the exact facade/dialect/test sites, and paired with the
#       run-time from_own_admission wall and trybuild compile-fail fixtures.
# WHY:  Rust has no cross-crate friend visibility; keeping one greppable sealed path plus a
#       deterministic guard prevents accidental public resurfacing or unauthorized workspace use.
# HOW TO EXEMPT: No exemption. Amend ADR-0056 before changing this contract.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
    printf 'check_token_sealing_surface: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail "required command is missing: python3"

REQUIRED_FILES=(
    "crates/sig/src/lib.rs"
    "crates/sig/src/facade_internal.rs"
    "crates/sig/src/bearer.rs"
    "crates/sig/src/floor_bearer.rs"
    "crates/sig/src/header_token.rs"
    "crates/sig/src/operation.rs"
    "crates/core/src/lib.rs"
    "crates/core/src/facade_internal.rs"
    "crates/core/src/request_context.rs"
    "crates/dialect-rustfs-admin/src/admin.rs"
    "crates/gateway/src/lib.rs"
    "crates/gateway/src/sig.rs"
    "crates/gateway/src/service.rs"
    "crates/gateway/src/service/authenticate.rs"
    "crates/gateway/src/service/host_tokens.rs"
    "crates/gateway/src/builder/host_tokens.rs"
)
for rel in "${REQUIRED_FILES[@]}"; do
    [[ -f "${ROOT}/${rel}" ]] || fail "required source is missing: ${rel}"
done

python3 - "$ROOT" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])

RAW_STRING_RE = re.compile(r'(?:br|r)(#{0,255})"')
CHAR_LITERAL_RE = re.compile(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'")


def fail(message: str) -> None:
    raise SystemExit(f"check_token_sealing_surface: {message}")


def rust_code(source: str, label: str) -> str:
    out = []
    pos = 0
    depth = 0
    n = len(source)
    while pos < n:
        if depth:
            if source.startswith("/*", pos):
                depth += 1
                out.extend("  ")
                pos += 2
            elif source.startswith("*/", pos):
                depth -= 1
                out.extend("  ")
                pos += 2
            else:
                out.append("\n" if source[pos] == "\n" else " ")
                pos += 1
        elif source.startswith("//", pos):
            while pos < n and source[pos] != "\n":
                out.append(" ")
                pos += 1
        elif source.startswith("/*", pos):
            depth = 1
            out.extend("  ")
            pos += 2
        elif raw := RAW_STRING_RE.match(source, pos):
            closing = '"' + raw.group(1)
            end = source.find(closing, raw.end())
            if end == -1:
                fail(f"{label} has an unterminated raw string")
            end += len(closing)
            out.extend("\n" if c == "\n" else " " for c in source[pos:end])
            pos = end
        elif source[pos] == '"' or source.startswith(('b"', 'c"'), pos):
            quote = pos if source[pos] == '"' else pos + 1
            end = quote + 1
            while end < n:
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            else:
                fail(f"{label} has an unterminated string")
            out.extend("\n" if c == "\n" else " " for c in source[pos:end])
            pos = end
        elif ch := CHAR_LITERAL_RE.match(source, pos):
            out.extend(" " for _ in range(ch.end() - pos))
            pos = ch.end()
        else:
            out.append(source[pos])
            pos += 1
    if depth:
        fail(f"{label} has an unterminated block comment")
    return "".join(out)


def read_code(rel: str) -> str:
    path = root / rel
    return rust_code(path.read_text(encoding="utf-8"), rel)


# 1. Sealed inherent methods must not resurface as `pub` (outside `pub(crate)` / `pub(super)`).
FORBIDDEN_PUBLIC_METHODS = {
    "crates/sig/src/bearer.rs": ("verify", "verify_alongside"),
    "crates/sig/src/floor_bearer.rs": ("bearer_alongside_signature",),
    "crates/sig/src/header_token.rs": ("verify",),
    "crates/sig/src/operation.rs": ("with_query_bearer_claim",),
    "crates/core/src/request_context.rs": ("with_bearer_receipt", "without_bearer_token"),
    "crates/dialect-rustfs-admin/src/admin.rs": ("zip_token_floor",),
}
for rel, names in FORBIDDEN_PUBLIC_METHODS.items():
    code = read_code(rel)
    for name in names:
        # Match bare `pub` (not `pub(...)`) followed by optional `const`/`async`/`unsafe` and `fn <name>`
        # (including generic `<...>` or `(`).
        pattern = re.compile(rf"\bpub(?!\s*\()\s+(?:const\s+)?(?:async\s+)?fn\s+{re.escape(name)}\b")
        for match in pattern.finditer(code):
            # Allow `BearerTokenVerifier::verify` trait method declaration (`fn verify` has no `pub`).
            fail(f"{rel} must not declare public `{name}` (ADR-0056)")

# Verify `admin::zip_token_floor` stays explicitly `pub(crate)`.
admin_code = read_code("crates/dialect-rustfs-admin/src/admin.rs")
if not re.search(r"\bpub\s*\(\s*crate\s*\)\s+const\s+fn\s+zip_token_floor\b", admin_code):
    fail("crates/dialect-rustfs-admin/src/admin.rs must declare `pub(crate) const fn zip_token_floor`")

# 2. Internal bridge modules stay `#[doc(hidden)]`, and `verify_bearer_alongside_signature`
#    keeps its `Verdict::Authenticated` proof check.
for lib_rel in ("crates/sig/src/lib.rs", "crates/core/src/lib.rs"):
    dense = re.sub(r"\s+", "", read_code(lib_rel))
    if '#[doc(hidden)]#[path=]pubmod__facade_internal;' not in dense:
        fail(f"{lib_rel} must mount `#[doc(hidden)] pub mod __facade_internal`")

sig_bridge = read_code("crates/sig/src/facade_internal.rs")
if "Verdict::Authenticated" not in sig_bridge:
    fail("crates/sig/src/facade_internal.rs must gate alongside-signature verification on Verdict::Authenticated")
if not re.search(r"#\s*\[\s*doc\s*\(\s*hidden\s*\)\s*\][\s\S]{0,80}\bpub\s+struct\s+FacadeSeal\s*\(\s*\(\s*\)\s*\)\s*;", sig_bridge):
    fail("crates/sig/src/facade_internal.rs must keep `#[doc(hidden)] pub struct FacadeSeal(())`")

core_bridge = read_code("crates/core/src/facade_internal.rs")
if not re.search(r"#\s*\[\s*doc\s*\(\s*hidden\s*\)\s*\][\s\S]{0,80}\bpub\s+struct\s+FacadeSeal\s*\(\s*\(\s*\)\s*\)\s*;", core_bridge):
    fail("crates/core/src/facade_internal.rs must keep `#[doc(hidden)] pub struct FacadeSeal(())`")

# 3. `rustfs-gateway` must never re-export internal bridge or sealed admission/receipt symbols.
FORBIDDEN_FACADE_EXPORTS = (
    "__facade_internal",
    "FacadeSeal",
    "Admission",
    "BearerAdmission",
    "HeaderTokenAdmission",
    "BearerReceipt",
    "HeaderTokenReceipt",
    "QueryBearerClaim",
    "WireView",
)
for facade_rel in ("crates/gateway/src/lib.rs", "crates/gateway/src/sig.rs"):
    code = read_code(facade_rel)
    for match in re.finditer(r"\bpub\s+use\s+([^;]+);", code):
        stmt = match.group(1)
        for symbol in FORBIDDEN_FACADE_EXPORTS:
            if re.search(rf"\b{re.escape(symbol)}\b", stmt):
                fail(f"{facade_rel} must not publicly re-export `{symbol}` (ADR-0056)")

# 4. Run-time defense-in-depth admission-arm wall must stay intact.
host_tokens_code = read_code("crates/gateway/src/service/host_tokens.rs")
auth_code = read_code("crates/gateway/src/service/authenticate.rs")
if "fn from_own_admission(" not in host_tokens_code:
    fail("crates/gateway/src/service/host_tokens.rs must retain `from_own_admission`")
if "host_tokens::from_own_admission(" not in auth_code or "bearer_admitted" not in auth_code or "header_token_admitted" not in auth_code:
    fail("crates/gateway/src/service/authenticate.rs must retain `bearer_admitted` / `header_token_admitted` checks")

# 5. Every reference to `__facade_internal` across the workspace must sit in the exact allowlist.
ALLOWED_BRIDGE_FILES = {
    # Defining module mounts
    "crates/sig/src/lib.rs",
    "crates/core/src/lib.rs",
    # Allowlisted production callers
    "crates/dialect-rustfs-admin/src/admin.rs",
    "crates/gateway/src/builder/host_tokens.rs",
    "crates/gateway/src/service.rs",
    "crates/gateway/src/service/authenticate.rs",
    "crates/gateway/src/service/host_tokens.rs",
    # Explicit workspace unit, integration, and compile-fail test fixtures
    "crates/sig/tests/header_token.rs",
    "crates/sig/tests/sigv2_refused_floor.rs",
    "crates/sig/tests/security_floor_schemes.rs",
    "crates/core/src/registry/reject_floor_tests.rs",
    "crates/core/src/request_context/tests.rs",
    "crates/gateway/src/bearer_posture.rs",
    "crates/gateway/src/header_token_posture.rs",
    "crates/gateway/tests/custom_signature_verifier.rs",
    "crates/gateway/tests/hardening_auth_and_owner.rs",
    "crates/gateway/tests/header_token.rs",
    "crates/gateway/tests/compile_fail/token_sealing_facade_exports_hidden.rs",
}
for base in (root / "crates", root / "xtask"):
    if not base.is_dir():
        continue
    for path in sorted(base.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith("crates/types/generated/"):
            continue
        code = rust_code(path.read_text(encoding="utf-8"), rel)
        if re.search(r"\b__facade_internal\b", code) and rel not in ALLOWED_BRIDGE_FILES:
            fail(f"unauthorized reference to `__facade_internal` in {rel} (ADR-0056)")

# 6. Trybuild compile-fail fixtures across sig, core, and gateway must exist and stay paired.
EXPECTED_FIXTURES = {
    "crates/sig/tests/compile_fail": {
        "token_sealing_bearer_verify",
        "token_sealing_bearer_verify_alongside",
        "token_sealing_bearer_alongside_signature",
        "token_sealing_header_token_verify",
        "token_sealing_query_bearer_claim",
    },
    "crates/core/tests/compile_fail": {
        "token_sealing_context_with_bearer_receipt",
        "token_sealing_context_without_bearer_token",
    },
    "crates/gateway/tests/compile_fail": {
        "token_sealing_facade_exports_hidden",
        "token_sealing_security_floor_alongside",
        "token_sealing_operation_floor_claim",
        "token_sealing_request_context_mutators",
        "token_sealing_dialect_zip_floor_private",
    },
}
for directory, expected in EXPECTED_FIXTURES.items():
    dir_path = root / directory
    if not dir_path.is_dir():
        fail(f"trybuild fixture directory is missing: {directory}")
    sources = {p.stem for p in dir_path.glob("token_sealing_*.rs")}
    goldens = {p.stem for p in dir_path.glob("token_sealing_*.stderr")}
    if sources != expected:
        fail(f"{directory} token_sealing_*.rs fixtures drifted: expected {sorted(expected)}, found {sorted(sources)}")
    if goldens != expected:
        fail(f"{directory} token_sealing_*.stderr goldens drifted: expected {sorted(expected)}, found {sorted(goldens)}")
PYEOF

printf 'OK: ADR-0056 bearer and header-token construction remains sealed behind __facade_internal\n'
