#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps ADR-0009's scope-rejection authority typed, deterministic and facade-private.
# WHY: Request text or a custom authenticator must not mint a trusted remediation Region detail.
# HOW TO EXEMPT: There is no exemption. Amend ADR-0009 before changing this contract.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SIG_SCOPE="${ROOT}/crates/sig/src/scope.rs"
AUTHENTICATOR="${ROOT}/crates/gateway/src/ext/authenticator.rs"
SERVICE="${ROOT}/crates/gateway/src/service.rs"
CORE_RESOLUTION="${ROOT}/crates/core/src/error_resolution.rs"

fail() {
    printf 'check_scope_rejection_surface: %s\n' "$1" >&2
    exit 1
}

for required in python3; do
    command -v "$required" >/dev/null 2>&1 || fail "required command is missing: ${required}"
done
for required in "$SIG_SCOPE" "$AUTHENTICATOR" "$SERVICE" "$CORE_RESOLUTION"; do
    [[ -f "$required" ]] || fail "required source is missing: ${required#"${ROOT}/"}"
done

python3 - "$ROOT" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
scope_path = root / "crates/sig/src/scope.rs"
auth_path = root / "crates/gateway/src/ext/authenticator.rs"
service_path = root / "crates/gateway/src/service.rs"
resolution_path = root / "crates/core/src/error_resolution.rs"


def fail(message):
    raise SystemExit(f"check_scope_rejection_surface: {message}")


def rust_code(source):
    out = []
    position = 0
    comment_depth = 0
    while position < len(source):
        if comment_depth:
            if source.startswith("/*", position):
                comment_depth += 1
                out.extend("  ")
                position += 2
            elif source.startswith("*/", position):
                comment_depth -= 1
                out.extend("  ")
                position += 2
            else:
                out.append("\n" if source[position] == "\n" else " ")
                position += 1
        elif source.startswith("//", position):
            while position < len(source) and source[position] != "\n":
                out.append(" ")
                position += 1
        elif source.startswith("/*", position):
            comment_depth = 1
            out.extend("  ")
            position += 2
        elif raw := re.match(r'(?:br|r)(#{0,255})"', source[position:]):
            closing = '"' + raw.group(1)
            end = source.find(closing, position + raw.end())
            if end == -1:
                fail("authenticator.rs has an unterminated raw string")
            end += len(closing)
            out.extend("\n" if char == "\n" else " " for char in source[position:end])
            position = end
        elif source[position] == '"' or source.startswith(('b"', 'c"'), position):
            quote = position if source[position] == '"' else position + 1
            end = quote + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            else:
                fail("authenticator.rs has an unterminated string")
            out.extend("\n" if char == "\n" else " " for char in source[position:end])
            position = end
        elif character := re.match(r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'", source[position:]):
            end = position + character.end()
            out.extend(" " for _ in source[position:end])
            position = end
        else:
            out.append(source[position])
            position += 1
    if comment_depth:
        fail("authenticator.rs has an unterminated block comment")
    return "".join(out)


def delimiter_depth(code, end):
    depth = {"{": 0, "(": 0, "[": 0}
    closing = {"}": "{", ")": "(", "]": "["}
    for char in code[:end]:
        if char in depth:
            depth[char] += 1
        elif char in closing:
            depth[closing[char]] -= 1
    return depth


def impl_header(code, item):
    stack = []
    angle_depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    position = item.end()
    while position < len(code):
        char = code[position]
        if char == "{" and not stack and angle_depth == 0:
            return re.sub(r"\s+", "", code[item.start() : position]), position
        if char in "([":
            stack.append(char)
        elif char in ")]":
            if not stack or pairs[stack[-1]] != char:
                fail("authenticator.rs has mismatched delimiters in impl header")
            stack.pop()
        elif char == "{" and (stack or angle_depth):
            stack.append(char)
        elif char == "}":
            if not stack or stack[-1] != "{":
                fail("authenticator.rs has mismatched delimiters in impl header")
            stack.pop()
        elif char == "<" and not stack:
            angle_depth += 1
        elif char == ">" and not stack and angle_depth:
            angle_depth -= 1
        position += 1
    fail("authenticator.rs has an unterminated impl header")


scope_source = scope_path.read_text()
scope_code = rust_code(scope_source)
auth_code = rust_code(auth_path.read_text())
service_code = rust_code(service_path.read_text())
resolution_code = rust_code(resolution_path.read_text())
dense_scope = re.sub(r"\s+", "", scope_code)
dense_auth = re.sub(r"\s+", "", auth_code)
dense_service = re.sub(r"\s+", "", service_code)
dense_resolution = re.sub(r"\s+", "", resolution_code)

if scope_code.count("pub struct ScopeRegion(Box<str>);") != 1:
    fail("ScopeRegion must remain a privately constructed bounded string")
if scope_code.count("pub struct ScopeRejection(Option<ScopeRegion>);") != 1:
    fail("ScopeRejection must remain a private optional configured region")
if not re.search(
    r"pub\s+fn\s+enforce_scope\s*\([\s\S]*?\)\s*->\s*Result<VerifiedScope,\s*ScopeRejection>",
    scope_code,
):
    fail("enforce_scope must return the typed rejection")
if scope_code.count("return Err(ScopeRejection(None));") != 2:
    fail("date and service mismatches must carry no remediation region")
if dense_scope.count("ScopeRejection(expected.regions().regions.first().cloned())") != 1:
    fail("only a region mismatch may carry the canonical configured region")
if "regions.sort_by(|left,right|left.as_str().as_bytes().cmp(right.as_str().as_bytes()));" not in dense_scope:
    fail("configured regions must be sorted byte-lexicographically")
if "regions.dedup();" not in dense_scope:
    fail("configured regions must be deduplicated")
alphabet = list(
    re.finditer(
        r"byte\.is_ascii_lowercase\(\)\s*\|\|\s*byte\.is_ascii_digit\(\)\s*\|\|\s*byte\s*==",
        scope_code,
    )
)
if len(alphabet) != 1 or re.match(r"\s*b'-'", scope_source[alphabet[0].end() :]) is None:
    fail("configured regions must use the bounded RegionLabel-compatible alphabet")

if dense_auth.count("pubstructAuthenticationOutcome{verdict:Verdict,scope_rejection:Option<ScopeRejection>,}") != 1:
    fail("AuthenticationOutcome fields must remain private and closed")
if "pubconstfnordinary(verdict:Verdict)->Self{Self{verdict,scope_rejection:None,}}" not in dense_auth:
    fail("ordinary outcomes must carry no scope proof")
if "pubconstfnverdict(&self)->&Verdict{&self.verdict}" not in dense_auth:
    fail("the public verdict accessor must borrow the exact stored verdict")
if (
    "fnscope_rejected(scope_rejection:ScopeRejection)->Self{Self{"
    "verdict:Verdict::reject(AuthError::AuthorizationHeaderMalformed),"
    "scope_rejection:Some(scope_rejection),}}"
    not in dense_auth
):
    fail("the private scope carrier must fix AuthorizationHeaderMalformed")

trait = re.search(r"\bpub\s+trait\s+Authenticator\b[^\{]*\{", auth_code)
if trait is None:
    fail("Authenticator trait is missing")
depth = 1
position = trait.end()
while position < len(auth_code) and depth:
    if auth_code[position] == "{":
        depth += 1
    elif auth_code[position] == "}":
        depth -= 1
    position += 1
if depth:
    fail("Authenticator trait has an unterminated body")
trait_body = re.sub(r"\s+", "", auth_code[trait.end() : position - 1])
expected_authenticate = (
    "fnauthenticate<'a>(&'aself,request:&'aAuthentication<'a>)"
    "->BoxFuture<'a,Result<AuthenticationOutcome,Unavailable>>;"
)
if trait_body.count(expected_authenticate) != 1 or "Result<Verdict,Unavailable>" in trait_body:
    fail("Authenticator must return the closed outcome carrier")

if "scope_rejection.and_then(|rejection|rejection.expected_region().cloned())" not in dense_service:
    fail("the service must consume the typed scope proof")
if "ErrorContext::authorization_region_mismatch(region)" not in dense_service:
    fail("a trusted region mismatch must use the named region context")
if "ErrorContext::authorization_scope_malformed()" not in dense_service:
    fail("a no-region rejection must use the closed no-detail context")
if "pubconstfnauthorization_scope_malformed()->Self" not in dense_resolution:
    fail("core must expose the closed no-detail context")

source = auth_path.read_text()
code = rust_code(source)
outcome_impls = []
inherent_opening = None
for item in re.finditer(r"\bimpl\b", code):
    if any(delimiter_depth(code, item.start()).values()):
        continue
    header, opening = impl_header(code, item)
    if "AuthenticationOutcome" in header:
        outcome_impls.append(header)
        if header == "implAuthenticationOutcome":
            inherent_opening = opening

if outcome_impls != ["implAuthenticationOutcome"] or inherent_opening is None:
    fail("AuthenticationOutcome must have only its exact inherent impl and no trait bridge")

depth = 1
position = inherent_opening + 1
while position < len(code) and depth:
    if code[position] == "{":
        depth += 1
    elif code[position] == "}":
        depth -= 1
    position += 1
if depth:
    fail("AuthenticationOutcome has an unterminated inherent impl")
body = code[inherent_opening + 1 : position - 1]
public_items = []
for item in re.finditer(r"\bpub\b", body):
    if any(delimiter_depth(body, item.start()).values()):
        continue
    brace = body.find("{", item.start())
    semicolon = body.find(";", item.start())
    ends = [end for end in (brace, semicolon) if end != -1]
    if not ends:
        fail("AuthenticationOutcome has an unterminated visible associated item")
    public_items.append(re.sub(r"\s+", "", body[item.start() : min(ends)]))

allowed_items = {
    "pubconstfnordinary(verdict:Verdict)->Self",
    "pubconstfnverdict(&self)->&Verdict",
    "pub(crate)fninto_parts(self)->(Verdict,Option<ScopeRejection>)",
}
if len(public_items) != len(allowed_items) or set(public_items) != allowed_items:
    fail("AuthenticationOutcome must expose only ordinary, verdict and the crate-private consuming split")
PYEOF

printf 'OK: ADR-0009 keeps scope remediation typed, stable and facade-private\n'
