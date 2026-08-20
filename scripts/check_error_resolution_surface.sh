#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps ADR-0008's error construction surface closed across core and the facade.
# WHY: A second public S3Error writer, status authority or filter-side resolved error can bypass
# visibility masking and pair contextual S3 codes with contradictory response facts.
# HOW TO EXEMPT: There is no exemption. Extend ADR-0008 before changing this public contract.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CORE_HANDLER="${ROOT}/crates/core/src/handler.rs"
CORE_RESOLUTION="${ROOT}/crates/core/src/error_resolution.rs"
FACADE_RENDER="${ROOT}/crates/gateway/src/render.rs"
FILTER="${ROOT}/crates/gateway/src/ext/filter.rs"
CORE_HARNESS="${ROOT}/crates/core/tests/compile_fail.rs"
GATEWAY_HARNESS="${ROOT}/crates/gateway/tests/compile_fail.rs"

fail() {
    printf 'check_error_resolution_surface: %s\n' "$1" >&2
    exit 1
}

for required in grep awk python3; do
    command -v "$required" >/dev/null 2>&1 \
        || fail "required command is missing: ${required}"
done
for required in "$CORE_HANDLER" "$CORE_RESOLUTION" "$FACADE_RENDER" "$FILTER" "$CORE_HARNESS" "$GATEWAY_HARNESS"; do
    [[ -f "$required" ]] || fail "required source is missing: ${required#"${ROOT}/"}"
done

if grep -En '^[[:space:]]*pub fn (new|with_status|closing|about_resource)\(' "$FACADE_RENDER" >/dev/null; then
    fail 'S3Error regained a public semantic writer'
fi
if grep -REn --include='*.rs' --exclude-dir=generated \
    'Result<[[:space:]]*\(\)[[:space:]]*,[[:space:]]*S3Error[[:space:]]*>' "${ROOT}/crates/gateway/src" >/dev/null; then
    fail 'a gateway extension point returns already-resolved S3Error'
fi
if grep -En '^[[:space:]]*pub fn status\(&self\)[[:space:]]*->[[:space:]]*StatusCode' "$CORE_HANDLER" >/dev/null; then
    fail 'HandlerError regained a status authority before resolution'
fi
if grep -En '^[[:space:]]*pub fn from_(wire|chunk|pre_auth|auth|denial|sse|codec|handler|transport)' \
    "$FACADE_RENDER" >/dev/null; then
    fail 'a typed facade conversion became a public S3Error writer'
fi

trait_shape="$(awk '
    /^pub trait StageFilter[[:space:]]*:/ { inside = 1 }
    /^impl<T: StageFilter/ { inside = 0 }
    inside && /fn on_(wire|routed|response)/ { methods++ }
    inside && /Result<\(\), HandlerError>/ { handler_results++ }
    END { printf "%d/%d", methods + 0, handler_results + 0 }
' "$FILTER")"
[[ "$trait_shape" == '3/3' ]] \
    || fail "StageFilter must expose exactly three HandlerError seams, found ${trait_shape}"

[[ "$(grep -Ec '^pub struct HandlerErrorContext\(ErrorContext\);' "$CORE_RESOLUTION" || true)" -eq 1 ]] \
    || fail 'the handler carrier must be an opaque HandlerErrorContext wrapper'
[[ "$(grep -Ec '^impl From<HandlerErrorContext> for HandlerError[[:space:]]*\{' "$CORE_HANDLER" || true)" -eq 1 ]] \
    || fail 'HandlerError must have exactly one legal HandlerErrorContext carrier bridge'
if grep -En '^impl (From<ErrorContext> for (HandlerError|HandlerErrorContext)|From<HandlerErrorContext> for ErrorContext|(Deref|DerefMut) for HandlerErrorContext|(AsRef|Borrow)<ErrorContext> for HandlerErrorContext)' \
    "$CORE_HANDLER" "$CORE_RESOLUTION" >/dev/null; then
    fail 'HandlerErrorContext exposes its arbitrary ErrorContext payload'
fi
[[ "$(grep -Ec '^pub fn resolve\(context: ErrorContext, response: ResponseKind\)' "$CORE_RESOLUTION" || true)" -eq 1 ]] \
    || fail 'core must expose exactly one resolution entry'
[[ "$(grep -Ec '^    pub const fn owned_bucket_recreation\(\) -> Self \{' "$CORE_RESOLUTION" || true)" -eq 2 ]] \
    || fail 'owned-bucket recreation must be parameter-free in both legal context types'
if grep -En 'success\(StatusCode::OK\)' "$CORE_RESOLUTION" >/dev/null; then
    fail 'CreateBucket success must not enter the error resolver'
fi

python3 - "$ROOT" <<'PYEOF'
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError as error:
    raise SystemExit("check_error_resolution_surface: Python tomllib is required") from error

root = Path(sys.argv[1])
RAW_STRING = re.compile(r'(?:br|r)(#{0,255})"')
CHARACTER_LITERAL = re.compile(
    r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])'"
)


def fail(message):
    raise SystemExit(f"check_error_resolution_surface: {message}")


def rust_code(path, source=None):
    if source is None:
        source = path.read_text()
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
        elif raw := RAW_STRING.match(source, position):
            closing = '"' + raw.group(1)
            end = source.find(closing, raw.end())
            if end == -1:
                fail(f"{path.relative_to(root)} has an unterminated raw string")
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
                fail(f"{path.relative_to(root)} has an unterminated string")
            out.extend("\n" if char == "\n" else " " for char in source[position:end])
            position = end
        elif character := CHARACTER_LITERAL.match(source, position):
            end = character.end()
            out.extend(" " for _ in source[position:end])
            position = end
        else:
            out.append(source[position])
            position += 1
    if comment_depth:
        fail(f"{path.relative_to(root)} has an unterminated block comment")
    return source, "".join(out)


def delimiter_depth(code, end):
    depth = {"{": 0, "(": 0, "[": 0}
    closing = {"}": "{", ")": "(", "]": "["}
    for char in code[:end]:
        if char in depth:
            depth[char] += 1
        elif char in closing:
            depth[closing[char]] -= 1
    return depth


def top_level_matches(code, pattern, path):
    depth = {"{": 0, "(": 0, "[": 0}
    closing = {"}": "{", ")": "(", "]": "["}
    position = 0
    matches = []
    for item in pattern.finditer(code):
        for char in code[position : item.start()]:
            if char in depth:
                depth[char] += 1
            elif char in closing:
                depth[closing[char]] -= 1
                if depth[closing[char]] < 0:
                    fail(f"{path.relative_to(root)} has mismatched top-level delimiters")
        if all(value == 0 for value in depth.values()):
            matches.append(item)
        position = item.end()
    return matches


def handwritten_rust_files(start):
    files = []
    for directory, names, filenames in os.walk(start, followlinks=False):
        directory_path = Path(directory)
        names[:] = [
            name
            for name in names
            if name != "generated" and not (directory_path / name).is_symlink()
        ]
        files.extend(directory_path / name for name in filenames if name.endswith(".rs"))
    return sorted(files)


def balanced_end(code, opening, path, label):
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [code[opening]]
    position = opening + 1
    while position < len(code):
        char = code[position]
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if not stack or pairs[stack[-1]] != char:
                fail(f"{path.relative_to(root)} has mismatched delimiters in {label}")
            stack.pop()
            if not stack:
                return position + 1
        position += 1
    fail(f"{path.relative_to(root)} has an unterminated {label}")


def impl_header(code, item, path):
    stack = []
    angle_depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    position = item.end()
    while position < len(code):
        char = code[position]
        if char == "{" and not stack and angle_depth == 0:
            return re.sub(r"\s+", "", code[item.start() : position])
        if char in "([":
            stack.append(char)
        elif char in ")]":
            if not stack or pairs[stack[-1]] != char:
                fail(f"{path.relative_to(root)} has mismatched delimiters in impl header")
            stack.pop()
        elif char == "{" and (stack or angle_depth):
            stack.append(char)
        elif char == "}":
            if not stack or stack[-1] != "{":
                fail(f"{path.relative_to(root)} has mismatched delimiters in impl header")
            stack.pop()
        elif char == "<" and not stack:
            angle_depth += 1
        elif char == ">" and not stack and angle_depth:
            angle_depth -= 1
        position += 1
    fail(f"{path.relative_to(root)} has an unterminated impl header")


s3_bridges = []
for path in handwritten_rust_files(root / "crates"):
    source = path.read_text()
    if "S3Error" not in source:
        continue
    _, code = rust_code(path, source)
    for item in top_level_matches(code, re.compile(r"\bimpl\b"), path):
        header = impl_header(code, item, path)
        if "From<" in header and re.search(r"for(?:[A-Za-z_][A-Za-z0-9_]*::)*S3Error(?:where|$)", header):
            s3_bridges.append((str(path.relative_to(root)), header))

expected_s3_bridges = [("crates/gateway/src/render.rs", "implFrom<ErrorResolution>forS3Error")]
if s3_bridges != expected_s3_bridges:
    fail("S3Error must have exactly one From<ErrorResolution> bridge")


def outer_attributes(code, start):
    attributes = []
    position = start
    while True:
        while position and code[position - 1].isspace():
            position -= 1
        if not position or code[position - 1] != "]":
            break
        end = position
        depth = 1
        position -= 1
        while position and depth:
            position -= 1
            if code[position] == "]":
                depth += 1
            elif code[position] == "[":
                depth -= 1
        if depth:
            break
        while position and code[position - 1].isspace():
            position -= 1
        if not position or code[position - 1] != "#":
            break
        position -= 1
        attributes.append(code[position:end])
    attributes.reverse()
    return attributes


def top_level_function(code, name):
    pattern = re.compile(rf"(?m)^[ \t]*fn\s+{re.escape(name)}\s*\(\s*\)[^;{{]*\{{")
    matches = [
        match
        for match in pattern.finditer(code)
        if all(value == 0 for value in delimiter_depth(code, match.start()).values())
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def function_body(code, item, path):
    opening = item.end() - 1
    depth = 1
    position = opening + 1
    while position < len(code) and depth:
        if code[position] == "{":
            depth += 1
        elif code[position] == "}":
            depth -= 1
        position += 1
    if depth:
        fail(f"{path.relative_to(root)} has an unterminated function body")
    return opening + 1, position - 1


def reject_cfg(code, path):
    if re.search(r"(?m)^[ \t]*#!?\s*\[\s*cfg(?:_attr)?\b", code):
        fail(f"{path.relative_to(root)} may disable error-resolution compile-fail evidence")


def validate_harness(relative, function, required_calls, exact_body=False):
    path = root / relative
    source, code = rust_code(path)
    reject_cfg(code, path)
    active_tests = []
    for candidate in re.finditer(r"(?m)^[ \t]*fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)[^;{]*\{", code):
        if any(delimiter_depth(code, candidate.start()).values()):
            continue
        attributes = outer_attributes(code, candidate.start())
        if any(re.fullmatch(r"#\s*\[\s*test\s*\]", attribute) for attribute in attributes):
            active_tests.append(candidate)
    item = top_level_function(code, function)
    attributes = outer_attributes(code, item.start()) if item is not None else []
    if (
        len(active_tests) != 1
        or item is None
        or active_tests[0].start() != item.start()
        or len(attributes) != 1
        or not re.fullmatch(r"#\s*\[\s*test\s*\]", attributes[0])
    ):
        fail(f"{relative} does not expose one active top-level #[test] harness")
    start, end = function_body(code, item, path)
    if exact_body:
        expected_body = "let cases = trybuild::TestCases::new();" + "".join(required_calls)
        actual_body = re.sub(r"\s+", "", source[start:end])
        if actual_body != re.sub(r"\s+", "", expected_body):
            fail(f"{relative} must use one unshadowed TestCases receiver for its exact call inventory")
    if code[start:end].count("trybuild::TestCases::new") != 1:
        fail(f"{relative} must construct exactly one trybuild TestCases value")
    found = []
    position = code.find("cases.compile_fail", start, end)
    while position != -1:
        statement_end = code.find(";", position, end)
        if (
            delimiter_depth(code, position) == {"{": 1, "(": 0, "[": 0}
            and not outer_attributes(code, position)
            and statement_end != -1
        ):
            found.append(re.sub(r"\s+", "", source[position : statement_end + 1]))
        position = code.find("cases.compile_fail", position + 1, end)
    expected = [re.sub(r"\s+", "", call) for call in required_calls]
    if found != expected:
        fail(f"{relative} must contain the exact ordered compile_fail call inventory")


fixtures = {
    "crates/core/tests/compile_fail/error_resolution_auth_context_into_handler.rs": (
        "let _error: HandlerError = context.into();",
        "error[E0277]",
        "the trait bound `HandlerError: From<ErrorContext>` is not satisfied",
    ),
    "crates/core/tests/compile_fail/error_resolution_auth_context_wrapped.rs": (
        "let _wrapped = HandlerErrorContext(context);",
        "error[E0423]",
        "cannot initialize a tuple struct which contains private fields",
    ),
    "crates/core/tests/compile_fail/error_resolution_context_fields.rs": (
        "let ErrorContext(_case) = context;",
        "error[E0532]",
        "cannot match against a tuple struct which contains private fields",
    ),
    "crates/core/tests/compile_fail/error_resolution_fields.rs": (
        "let _resolution = ErrorResolution {",
        "error[E0451]",
        "fields `status`, `code`, `body_policy`, `message`, `headers`, `details`, `etag` and `resource`",
    ),
    "crates/core/tests/compile_fail/error_resolution_handler_payload.rs": (
        "let _error = HandlerError {",
        "error[E0451]",
        "fields `code`, `message`, `headers`, `details` and `context`",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_closing.rs": (
        ".closing(ConnectionIntent::Close)",
        "error[E0599]",
        "no method named `closing` found",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_from_handler.rs": (
        "S3Error::from(HandlerError::internal_error",
        "error[E0277]",
        "the trait bound `S3Error: From<HandlerError>` is not satisfied",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_from_wire.rs": (
        "S3Error::from(WireReject::MalformedRequestTarget)",
        "error[E0277]",
        "the trait bound `S3Error: From<WireReject>` is not satisfied",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_new.rs": (
        "S3Error::new(ErrorCode::ACCESS_DENIED",
        "error[E0599]",
        "no associated function or constant named `new` found",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_resource.rs": (
        ".about_resource(",
        "error[E0599]",
        "no method named `about_resource` found",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_s3_status.rs": (
        ".with_status(http::StatusCode::OK)",
        "error[E0599]",
        "no method named `with_status` found",
    ),
    "crates/gateway/tests/compile_fail/error_resolution_stage_filter.rs": (
        "Result<(), S3Error>",
        "error[E0053]",
        "method `on_wire` has an incompatible type for trait",
    ),
}

resolution_path = root / "crates/core/src/error_resolution.rs"
_, resolution_code = rust_code(resolution_path)
marker = "impl HandlerErrorContext {"
if resolution_code.count(marker) != 1:
    fail("HandlerErrorContext must have one inherent implementation")
opening = resolution_code.index(marker) + len(marker) - 1
depth = 1
position = opening + 1
while position < len(resolution_code) and depth:
    if resolution_code[position] == "{":
        depth += 1
    elif resolution_code[position] == "}":
        depth -= 1
    position += 1
if depth:
    fail("HandlerErrorContext has an unterminated implementation")
wrapper = resolution_code[opening + 1 : position - 1]

public_items = []
for match in re.finditer(r"\bpub\b", wrapper):
    if any(delimiter_depth(wrapper, match.start()).values()):
        continue
    brace = wrapper.find("{", match.start())
    semicolon = wrapper.find(";", match.start())
    ends = [end for end in (brace, semicolon) if end != -1]
    if not ends:
        fail("HandlerErrorContext has an unterminated public associated item")
    public_items.append(re.sub(r"\s+", "", wrapper[match.start() : min(ends)]))

allowed_items = {
    "pubconstfnmissing_object(kind:MissingObject,visibility:ResourceVisibility)->Self",
    "pubfnmissing_object_for(key:ObjectKey,kind:MissingObject,visibility:ResourceVisibility)->Self",
    "pubconstfndelete_missing_key()->Self",
    "pubconstfnmissing_bucket()->Self",
    "pubconstfnforeign_bucket()->Self",
    "pubfnpermanent_redirect(region:RegionLabel)->Self",
    "pubfnpermanent_redirect_for(bucket:BucketName,region:RegionLabel)->Self",
    "pubfntemporary_redirect(region:RegionLabel,target:RedirectTarget)->Self",
    "pubconstfnowned_bucket_recreation()->Self",
    "pubfnversioned_delete_marker(version_id:&str,last_modified:i64)->Result<Self,InvalidErrorContext>",
    "pubfncurrent_delete_marker(visibility:ResourceVisibility,key:Option<ObjectKey>,last_modified:i64,)->Result<Self,InvalidErrorContext>",
    "pubfnnot_modified(etag:ETag)->Self",
    "pub(crate)fninto_error_context(self)->ErrorContext",
}
if len(public_items) != len(allowed_items) or set(public_items) != allowed_items:
    fail("HandlerErrorContext must expose only the exact named legal associated items")

impl_headers = []
for path in (root / "crates/core/src").rglob("*.rs"):
    source = path.read_text()
    if "HandlerErrorContext" not in source and "ErrorContext" not in source:
        continue
    _, code = rust_code(path, source)
    dense = re.sub(r"\s+", "", code)
    if re.search(r"type[A-Za-z0-9_]+=[^;]*HandlerErrorContext|HandlerErrorContextas[A-Za-z0-9_]", dense):
        fail(f"{path.relative_to(root)} aliases HandlerErrorContext")
    for macro in re.finditer(r"\bmacro_rules\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*([({\[])", code):
        opening = macro.end() - 1
        end = balanced_end(code, opening, path, "macro_rules body")
        body = code[opening + 1 : end - 1]
        if "HandlerErrorContext" in body or ("ErrorContext" in body and re.search(r"\bimpl\b", body)):
            fail(f"{path.relative_to(root)} may generate an ErrorContext carrier impl from macro_rules")
    for invocation in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*!\s*([({\[])", code):
        if invocation.group(1) == "macro_rules":
            continue
        opening = invocation.end() - 1
        end = balanced_end(code, opening, path, "macro invocation")
        arguments = code[opening + 1 : end - 1]
        if "HandlerErrorContext" in arguments:
            fail(f"{path.relative_to(root)} passes HandlerErrorContext through a token macro")
    for match in top_level_matches(code, re.compile(r"\bimpl\b"), path):
        brace = code.find("{", match.end())
        if brace == -1:
            fail(f"{path.relative_to(root)} has an unterminated impl")
        header = re.sub(r"\s+", "", code[match.start() : brace])
        if "HandlerErrorContext" in header:
            impl_headers.append((str(path.relative_to(root)), header))

allowed_impls = {
    ("crates/core/src/error_resolution.rs", "implHandlerErrorContext"),
    ("crates/core/src/handler.rs", "implFrom<HandlerErrorContext>forHandlerError"),
}
if len(impl_headers) != len(allowed_impls) or set(impl_headers) != allowed_impls:
    fail("HandlerErrorContext must have only its exact inherent impl and HandlerError bridge")

validate_harness(
    "crates/core/tests/compile_fail.rs",
    "compile_time_contracts_are_not_openable",
    [
        'cases.compile_fail("tests/compile_fail/authz_*.rs");',
        'cases.compile_fail("tests/compile_fail/c_err_1010_*.rs");',
        'cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");',
        'cases.compile_fail("tests/compile_fail/c_sig_0123_*.rs");',
        'cases.compile_fail("tests/compile_fail/error_resolution_*.rs");',
    ],
)
validate_harness(
    "crates/gateway/tests/compile_fail.rs",
    "gateway_compile_fail_contracts_are_enforced",
    [
        'cases.compile_fail("tests/compile_fail/azc_*.rs");',
        'cases.compile_fail("tests/compile_fail/error_resolution_*.rs");',
        'cases.compile_fail("tests/trybuild/credential/*.rs");',
    ],
    exact_body=True,
)
for legacy in (
    "crates/gateway/tests/authz_compile.rs",
    "crates/gateway/tests/error_resolution_compile.rs",
    "crates/gateway/tests/trybuild_credential.rs",
):
    if (root / legacy).exists():
        fail(f"legacy gateway trybuild harness remains active: {legacy}")

gateway_harness = root / "crates/gateway/tests/compile_fail.rs"
gateway_harness_target = gateway_harness.resolve()
gateway_root = root / "crates/gateway"

manifest_path = gateway_root / "Cargo.toml"
try:
    manifest = tomllib.loads(manifest_path.read_text())
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse crates/gateway/Cargo.toml: {error}")

package = manifest.get("package")
if not isinstance(package, dict):
    fail("crates/gateway/Cargo.toml has no package table")
autotests = package.get("autotests", True)
if autotests is not False:
    fail("crates/gateway must disable implicit integration-test discovery")

testable_targets = []
library = manifest.get("lib")
if isinstance(library, dict):
    testable_targets.append(("lib", library, True))
for kind, default_test in (("bin", True), ("test", True), ("example", False), ("bench", False)):
    targets = manifest.get(kind, [])
    if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
        fail(f"crates/gateway/Cargo.toml has an invalid [[{kind}]] target inventory")
    testable_targets.extend((kind, target, default_test) for target in targets)
for kind, target, default_test in testable_targets:
    enabled = target.get("test", default_test)
    target_path = target.get("path")
    if not isinstance(enabled, bool) or (target_path is not None and not isinstance(target_path, str)):
        fail(f"crates/gateway/Cargo.toml has an unresolvable {kind} test target")
    if enabled and kind != "test" and target_path is not None and (gateway_root / target_path).resolve() == gateway_harness_target:
        fail(f"crates/gateway/Cargo.toml reuses the unified trybuild harness as a {kind} target")

explicit_tests = manifest.get("test", [])
if not isinstance(explicit_tests, list) or len(explicit_tests) != 1 or not isinstance(explicit_tests[0], dict):
    fail("crates/gateway must declare exactly one consolidated [[test]] target")
integration_target = explicit_tests[0]
required_features = integration_target.get("required-features", [])
if (
    integration_target.get("name") != "integration"
    or integration_target.get("path") != "tests/integration.rs"
    or integration_target.get("test", True) is not True
    or integration_target.get("harness", True) is not True
    or not isinstance(required_features, list)
    or required_features
):
    fail("the consolidated gateway integration target must always run without required features")

gateway_integration = gateway_root / "tests/integration.rs"
_, integration_code = rust_code(gateway_integration)
reject_cfg(integration_code, gateway_integration)
integration_registrations = re.findall(
    r'#\s*\[\s*path\s*=\s*[ \t]+\]\s*mod\s+compile_fail\s*;',
    integration_code,
)
if len(integration_registrations) != 1:
    fail("the consolidated gateway target must register the unified trybuild harness exactly once")


def meta_ranges(code, start, end, path):
    ranges = []
    stack = []
    item_start = start
    pairs = {"(": ")", "{": "}", "[": "]"}
    for position in range(start, end):
        char = code[position]
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if not stack or pairs[stack[-1]] != char:
                fail(f"{path.relative_to(root)} has mismatched delimiters in cfg_attr")
            stack.pop()
        elif char == "," and not stack:
            ranges.append((item_start, position))
            item_start = position + 1
    if stack:
        fail(f"{path.relative_to(root)} has unterminated nested cfg_attr meta")
    ranges.append((item_start, end))
    return ranges


canonical_gateway_harness_paths = []


def inspect_path_meta(source, code, start, end, path):
    while start < end and code[start].isspace():
        start += 1
    if re.match(r"path\b", code[start:end]):
        raw = source[start:end].strip()
        literal = re.fullmatch(r'path\s*=\s*"([^"\n]+)"', raw)
        if literal is None:
            fail(f"{path.relative_to(root)} has a path attribute the guard cannot resolve")
        if (path.parent / literal.group(1)).resolve() == gateway_harness_target:
            if path == gateway_integration and raw == 'path = "compile_fail.rs"':
                canonical_gateway_harness_paths.append((start, end))
                return
            fail(f"{path.relative_to(root)} reuses the unified gateway trybuild harness")
        return
    cfg_attr = re.match(r"cfg_attr\s*\(", code[start:end])
    if cfg_attr is None:
        return
    opening = start + cfg_attr.end() - 1
    close = balanced_end(code, opening, path, "cfg_attr")
    if code[close:end].strip():
        fail(f"{path.relative_to(root)} has cfg_attr meta the guard cannot resolve")
    arguments = meta_ranges(code, opening + 1, close - 1, path)
    if len(arguments) < 2:
        fail(f"{path.relative_to(root)} has cfg_attr meta the guard cannot resolve")
    for argument_start, argument_end in arguments[1:]:
        inspect_path_meta(source, code, argument_start, argument_end, path)


gateway_rust_entries = set()
for directory in ("src", "tests", "examples", "benches"):
    candidate = gateway_root / directory
    if candidate.is_dir():
        gateway_rust_entries.update(candidate.rglob("*.rs"))
build_script = gateway_root / "build.rs"
if build_script.is_file():
    gateway_rust_entries.add(build_script)

for path in sorted(gateway_rust_entries):
    if path == gateway_harness:
        continue
    source, code = rust_code(path)
    if re.search(r"\btrybuild\b", code):
        fail(f"extra gateway trybuild entry point exists: {path.relative_to(root)}")
    for attribute in re.finditer(r"#\s*\[", code):
        opening = code.find("[", attribute.start(), attribute.end())
        end = balanced_end(code, opening, path, "path attribute")
        inspect_path_meta(source, code, opening + 1, end - 1, path)
    for invocation in re.finditer(r"\binclude\s*!\s*([({\[])", code):
        opening = invocation.end() - 1
        end = balanced_end(code, opening, path, "include invocation")
        raw = source[opening + 1 : end - 1].strip()
        literal = re.fullmatch(r'"([^"\n]+)"', raw)
        if literal is None:
            fail(f"{path.relative_to(root)} has an include path the guard cannot resolve")
        if (path.parent / literal.group(1)).resolve() == gateway_harness_target:
            fail(f"{path.relative_to(root)} includes the unified gateway trybuild harness")

if len(canonical_gateway_harness_paths) != 1:
    fail("the consolidated gateway target must have one direct path to the unified trybuild harness")

for path in sorted(gateway_rust_entries):
    if path.is_symlink() and path.resolve() == gateway_harness_target:
        fail(f"gateway Rust symlink reuses the unified trybuild harness: {path.relative_to(root)}")

gateway_fixture_groups = {
    "authorization": ("crates/gateway/tests/compile_fail", "azc_*", {
        "crates/gateway/tests/compile_fail/azc_0014_missing_input.rs",
        "crates/gateway/tests/compile_fail/azc_0015_forge_authorized.rs",
        "crates/gateway/tests/compile_fail/azc_0016_denial_code.rs",
        "crates/gateway/tests/compile_fail/azc_0020_service_config_default.rs",
        "crates/gateway/tests/compile_fail/azc_0021_allow_all.rs",
        "crates/gateway/tests/compile_fail/azc_0025_request_extensions.rs",
    }),
    "error resolution": ("crates/gateway/tests/compile_fail", "error_resolution_*", {
        "crates/gateway/tests/compile_fail/error_resolution_s3_closing.rs",
        "crates/gateway/tests/compile_fail/error_resolution_s3_from_handler.rs",
        "crates/gateway/tests/compile_fail/error_resolution_s3_from_wire.rs",
        "crates/gateway/tests/compile_fail/error_resolution_s3_new.rs",
        "crates/gateway/tests/compile_fail/error_resolution_s3_resource.rs",
        "crates/gateway/tests/compile_fail/error_resolution_s3_status.rs",
        "crates/gateway/tests/compile_fail/error_resolution_stage_filter.rs",
    }),
    "credential": ("crates/gateway/tests/trybuild/credential", "*", {
        "crates/gateway/tests/trybuild/credential/constructs_anonymous.rs",
        "crates/gateway/tests/trybuild/credential/prints_and_compares_token.rs",
        "crates/gateway/tests/trybuild/credential/provider_returns_secret.rs",
        "crates/gateway/tests/trybuild/credential/provider_returns_verdict.rs",
    }),
}
for label, (directory, pattern, expected_sources) in gateway_fixture_groups.items():
    actual_sources = {
        str(path.relative_to(root))
        for path in (root / directory).glob(f"{pattern}.rs")
    }
    if actual_sources != expected_sources:
        fail(f"gateway {label} compile-fail source inventory is not exact")
    actual_goldens = {
        str(path.relative_to(root))
        for path in (root / directory).glob(f"{pattern}.stderr")
    }
    expected_goldens = {str(Path(relative).with_suffix(".stderr")) for relative in expected_sources}
    if actual_goldens != expected_goldens:
        fail(f"gateway {label} compile-fail golden inventory is not exact")

actual = {
    str(path.relative_to(root))
    for crate in ("core", "gateway")
    for path in (root / "crates" / crate / "tests" / "compile_fail").glob("error_resolution_*.rs")
}
if actual != set(fixtures):
    fail("error-resolution compile-fail fixture inventory is not exact")
actual_goldens = {
    str(path.relative_to(root))
    for crate in ("core", "gateway")
    for path in (root / "crates" / crate / "tests" / "compile_fail").glob("error_resolution_*.stderr")
}
expected_goldens = {str(Path(relative).with_suffix(".stderr")) for relative in fixtures}
if actual_goldens != expected_goldens:
    fail("error-resolution compile-fail golden inventory is not exact")

for relative, (needle, error_code, diagnostic) in fixtures.items():
    path = root / relative
    source, code = rust_code(path)
    reject_cfg(code, path)
    main = top_level_function(code, "main")
    if main is None or outer_attributes(code, main.start()):
        fail(f"{relative} has no active top-level fn main()")
    if relative.endswith("error_resolution_stage_filter.rs"):
        pattern = re.compile(r"(?m)^impl\s+StageFilter\s+for\s+RenderedFilter\s*\{")
        implementations = [
            match
            for match in pattern.finditer(code)
            if all(value == 0 for value in delimiter_depth(code, match.start()).values())
        ]
        if len(implementations) != 1 or outer_attributes(code, implementations[0].start()):
            fail(f"{relative} has no active top-level forbidden StageFilter impl")
        opening = implementations[0].end() - 1
        end = balanced_end(code, opening, path, "StageFilter impl")
        evidence = code[opening + 1 : end - 1]
    else:
        start, end = function_body(code, main, path)
        evidence = code[start:end]
    if needle not in evidence:
        fail(f"{relative} does not exercise its forbidden expression in active code")
    golden = path.with_suffix(".stderr")
    if not golden.is_file():
        fail(f"{golden.relative_to(root)} is missing")
    stderr = golden.read_text()
    if error_code not in stderr or diagnostic not in stderr:
        fail(f"{golden.relative_to(root)} lost its case-specific diagnostic")
PYEOF

printf 'OK: ADR-0008 keeps one contextual carrier and one resolved facade bridge\n'
