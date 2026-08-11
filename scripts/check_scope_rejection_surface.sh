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

for required in rg awk python3; do
    command -v "$required" >/dev/null 2>&1 || fail "required command is missing: ${required}"
done
for required in "$SIG_SCOPE" "$AUTHENTICATOR" "$SERVICE" "$CORE_RESOLUTION"; do
    [[ -f "$required" ]] || fail "required source is missing: ${required#"${ROOT}/"}"
done

[[ "$(rg -c '^pub struct ScopeRegion\(Box<str>\);$' "$SIG_SCOPE" || true)" -eq 1 ]] \
    || fail 'ScopeRegion must remain a privately constructed bounded string'
[[ "$(rg -c '^pub struct ScopeRejection\(Option<ScopeRegion>\);$' "$SIG_SCOPE" || true)" -eq 1 ]] \
    || fail 'ScopeRejection must remain a private optional configured region'
rg -U 'pub fn enforce_scope\([\s\S]*?\) -> Result<VerifiedScope, ScopeRejection>' "$SIG_SCOPE" >/dev/null \
    || fail 'enforce_scope must return the typed rejection'
[[ "$(rg -c 'return Err\(ScopeRejection\(None\)\);' "$SIG_SCOPE" || true)" -eq 2 ]] \
    || fail 'date and service mismatches must carry no remediation region'
[[ "$(rg -c 'ScopeRejection\(expected\.regions\(\)\.regions\.first\(\)\.cloned\(\)\)' "$SIG_SCOPE" || true)" -eq 1 ]] \
    || fail 'only a region mismatch may carry the canonical configured region'
rg -F 'regions.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));' "$SIG_SCOPE" >/dev/null \
    || fail 'configured regions must be sorted byte-lexicographically'
rg -F 'regions.dedup();' "$SIG_SCOPE" >/dev/null \
    || fail 'configured regions must be deduplicated'
rg -F "byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'" "$SIG_SCOPE" >/dev/null \
    || fail 'configured regions must use the bounded RegionLabel-compatible alphabet'

rg -U 'pub struct AuthenticationOutcome \{\n    verdict: Verdict,\n    scope_rejection: Option<ScopeRejection>,\n\}' \
    "$AUTHENTICATOR" >/dev/null || fail 'AuthenticationOutcome fields must remain private and closed'
rg -U 'pub const fn ordinary\(verdict: Verdict\) -> Self \{[\s\S]*?scope_rejection: None,' \
    "$AUTHENTICATOR" >/dev/null || fail 'ordinary outcomes must carry no scope proof'
rg -U 'pub const fn verdict\(&self\) -> &Verdict \{\n        &self\.verdict\n    \}' "$AUTHENTICATOR" >/dev/null \
    || fail 'the public verdict accessor must borrow the exact stored verdict'
rg -U '    fn scope_rejected\(scope_rejection: ScopeRejection\) -> Self \{\n        Self \{\n            verdict: Verdict::reject\(AuthError::AuthorizationHeaderMalformed\),\n            scope_rejection: Some\(scope_rejection\),\n        \}\n    \}' \
    "$AUTHENTICATOR" >/dev/null || fail 'the private scope carrier must fix AuthorizationHeaderMalformed'
if rg -n 'pub fn scope_rejected|pub fn into_parts|Result<Verdict, Unavailable>' "$AUTHENTICATOR" >/dev/null; then
    fail 'the contextual constructor, consuming split or old bare-verdict trait surface became public'
fi
trait_outcomes="$(awk '
    /^pub trait Authenticator[[:space:]]*:/ { inside = 1 }
    /^impl<T: Authenticator/ { inside = 0 }
    inside && /Result<AuthenticationOutcome, Unavailable>/ { count++ }
    END { print count + 0 }
' "$AUTHENTICATOR")"
[[ "$trait_outcomes" -eq 1 ]] || fail 'Authenticator must return the closed outcome carrier'

rg -F 'scope_rejection.and_then(|rejection| rejection.expected_region().cloned())' "$SERVICE" >/dev/null \
    || fail 'the service must consume the typed scope proof'
rg -F 'ErrorContext::authorization_region_mismatch(region)' "$SERVICE" >/dev/null \
    || fail 'a trusted region mismatch must use the named region context'
rg -F 'ErrorContext::authorization_scope_malformed()' "$SERVICE" >/dev/null \
    || fail 'a no-region rejection must use the closed no-detail context'
rg -F 'pub const fn authorization_scope_malformed() -> Self' "$CORE_RESOLUTION" >/dev/null \
    || fail 'core must expose the closed no-detail context'

python3 - "$ROOT" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
path = root / "crates/gateway/src/ext/authenticator.rs"


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


source = path.read_text()
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
