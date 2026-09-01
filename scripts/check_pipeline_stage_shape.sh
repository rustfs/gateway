#!/usr/bin/env bash
set -euo pipefail

# The request pipeline's state carrier owns its data. Borrowing the wire request
# would make later async stages self-referential and force pinning or unsafe code.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_pipeline_stage_shape: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/gateway/src/request_config.rs"
service_source = root / "crates/gateway/src/service.rs"
mode_source = root / "crates/gateway/src/operation_mode.rs"
for required in (source, service_source, mode_source):
    if not required.is_file():
        print(f"check_pipeline_stage_shape: required input is missing: {required.relative_to(root)}", file=sys.stderr)
        raise SystemExit(1)

text = source.read_text()
code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
code = re.sub(r"//[^\n]*", "", code)

carrier = re.search(
    r"\bpub\(crate\)\s+struct\s+RequestConfig\s*<([^>{}]*)>\s*\{([^}]*)\}",
    code,
    re.S,
)
if carrier is None:
    print("check_pipeline_stage_shape: RequestConfig carrier is missing", file=sys.stderr)
    raise SystemExit(1)
parameters = carrier.group(1).strip()
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parameters) or "'" in parameters:
    print("crates/gateway/src/request_config.rs: RequestConfig must not carry a lifetime parameter", file=sys.stderr)
    raise SystemExit(1)

alias_pattern = re.compile(
    r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^;=]+>)?\s*=\s*([^;]+);",
    re.S,
)
aliases = {}
for match in alias_pattern.finditer(code):
    aliases.setdefault(match.group(1), []).append(match.group(2))

type_definitions = dict(aliases)
struct_pattern = re.compile(
    r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>{}();]*>)?\s*([({;])",
    re.S,
)
for match in struct_pattern.finditer(code):
    delimiter = match.group(2)
    if delimiter == ";":
        type_definitions.setdefault(match.group(1), []).append("")
        continue
    closing = "}" if delimiter == "{" else ")"
    depth = 1
    index = match.end()
    start = index
    while index < len(code) and depth:
        if code[index] == delimiter:
            depth += 1
        elif code[index] == closing:
            depth -= 1
        index += 1
    if depth == 0:
        type_definitions.setdefault(match.group(1), []).append(code[start : index - 1])

enum_pattern = re.compile(
    r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*<[^>{}();]*>)?\s*\{",
    re.S,
)
for match in enum_pattern.finditer(code):
    depth = 1
    index = match.end()
    start = index
    while index < len(code) and depth:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth == 0:
        type_definitions.setdefault(match.group(1), []).append(code[start : index - 1])

borrowed_types = set()
changed = True
while changed:
    changed = False
    for type_name, definitions in type_definitions.items():
        if type_name in borrowed_types:
            continue
        if any(
            "&" in definition
            or any(re.search(rf"\b{re.escape(borrowed)}\b", definition) for borrowed in borrowed_types)
            for definition in definitions
        ):
            borrowed_types.add(type_name)
            changed = True

carrier_body = carrier.group(2)
if "&" in carrier_body or any(
    re.search(rf"\b{re.escape(type_name)}\b", carrier_body)
    for type_name in borrowed_types
):
    print("crates/gateway/src/request_config.rs: RequestConfig must own its carried state", file=sys.stderr)
    raise SystemExit(1)

implemented = re.findall(r"\bimpl\s+RequestConfig\s*<\s*([^>]+)\s*>", code)
returned = re.findall(r"->\s*RequestConfig\s*<\s*([^>]+)\s*>", code)
arguments = implemented + returned
if not arguments:
    print("check_pipeline_stage_shape: RequestConfig state closure is missing", file=sys.stderr)
    raise SystemExit(1)
for argument in arguments:
    if "'" in argument:
        print("crates/gateway/src/request_config.rs: request stage must not carry a lifetime parameter", file=sys.stderr)
        raise SystemExit(1)

declarations = {
    match.group(1): match.group(2)
    for match in re.finditer(
        r"(?m)^\s*pub\(crate\)\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(<[^;{}()]*>)?\s*(?:;|\{|\()",
        code,
    )
}
stages = {argument.strip() for argument in arguments if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument.strip())}
for stage in sorted(stages & declarations.keys()):
    if declarations[stage] and "'" in declarations[stage]:
        print(f"crates/gateway/src/request_config.rs: {stage} must not carry a lifetime parameter", file=sys.stderr)
        raise SystemExit(1)

expected_chain = (
    ("Entered", "wire", "Wire"),
    ("Wire", "targeted", "Targeted"),
    ("Targeted", "routed", "Routed"),
    ("Routed", "governed", "Governed"),
    ("Governed", "meta_auth", "MetaAuth"),
    ("MetaAuth", "route_authorized", "RouteAuthorized"),
    ("RouteAuthorized", "guarded", "Guarded"),
    ("Guarded", "decoded", "Decoded"),
    ("Decoded", "authorized", "Authorized"),
)
expected_stages = {expected_chain[0][0], *(target for _, _, target in expected_chain)}
unit_stages = set(re.findall(r"(?m)^pub\(crate\) struct ([A-Za-z_][A-Za-z0-9_]*);$", code))
if unit_stages != expected_stages:
    missing = sorted(expected_stages - unit_stages)
    extra = sorted(unit_stages - expected_stages)
    print(
        "crates/gateway/src/request_config.rs: request stage closure differs from the exact production chain "
        f"(missing={missing}, extra={extra})",
        file=sys.stderr,
    )
    raise SystemExit(1)

impl_starts = list(re.finditer(r"\bimpl\s+RequestConfig\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>\s*\{", code))
stage_impls = {}
for index, match in enumerate(impl_starts):
    end = impl_starts[index + 1].start() if index + 1 < len(impl_starts) else len(code)
    stage_impls.setdefault(match.group(1), []).append(code[match.end():end])
expected_impl_stages = expected_stages - {expected_chain[-1][2]}
if set(stage_impls) != expected_impl_stages or any(len(bodies) != 1 for bodies in stage_impls.values()):
    print("crates/gateway/src/request_config.rs: request stages must have one transition root and one impl each", file=sys.stderr)
    raise SystemExit(1)

observed_edges = []
for stage, bodies in stage_impls.items():
    for method, target in re.findall(
        r"pub\(crate\)\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*->\s*RequestConfig\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>",
        bodies[0],
        re.S,
    ):
        observed_edges.append((stage, method, target))
if set(observed_edges) != set(expected_chain) or len(observed_edges) != len(expected_chain):
    print("crates/gateway/src/request_config.rs: request transition closure is not the exact ordered chain", file=sys.stderr)
    raise SystemExit(1)

service = service_source.read_text()
service_code = re.sub(r"/\*.*?\*/", "", service, flags=re.S)
service_code = re.sub(r"//[^\n]*", "", service_code)
production_transitions = (
    "let config = config.wire();",
    "let config = config.targeted();",
    "let config = config.routed();",
    "let config = config.governed(lease);",
    "let config = config.meta_auth();",
    "config: config.route_authorized(),",
    "config: state.config.guarded(sse).with_body_monitor(body_monitor),",
    "let config = state.config.decoded();",
    "let config = config.with_missing_object_visibility(visibility).authorized();",
)
cursor = -1
for transition in production_transitions:
    if service_code.count(transition) != 1:
        print(f"crates/gateway/src/service.rs: production transition must occur once: {transition}", file=sys.stderr)
        raise SystemExit(1)
    position = service_code.find(transition)
    if position <= cursor:
        print("crates/gateway/src/service.rs: production request transitions are out of order", file=sys.stderr)
        raise SystemExit(1)
    cursor = position

mode = mode_source.read_text()
mode_code = re.sub(r"/\*.*?\*/", "", mode, flags=re.S)
mode_code = re.sub(r"//[^\n]*", "", mode_code)
dynamic_start = mode_code.find("impl OperationMode for DynamicMode")
static_start = mode_code.find("pub(crate) struct MonomorphicMode", dynamic_start)
if dynamic_start < 0 or static_start < 0:
    print("crates/gateway/src/operation_mode.rs: dynamic dispatch boundary is missing", file=sys.stderr)
    raise SystemExit(1)
dynamic = mode_code[dynamic_start:static_start]
decode_boundary = (
    "let (body_state, body) = read_body(route_state).await.map_err(StaticDispatchError::Body)?;",
    "let decoded = entry.decode(meta, body).map_err(StaticDispatchError::Codec)?;",
    "let resources = entry.resources(&decoded).map_err(StaticDispatchError::Codec)?;",
    "authorize_input_callback(body_state, resources)",
    "let authorized = entry.authorize(decoded, &decisions).map_err(StaticDispatchError::Denied)?;",
)
cursor = -1
for boundary in decode_boundary:
    if dynamic.count(boundary) != 1:
        print(f"crates/gateway/src/operation_mode.rs: erased decode boundary must occur once: {boundary}", file=sys.stderr)
        raise SystemExit(1)
    position = dynamic.find(boundary)
    if position <= cursor:
        print("crates/gateway/src/operation_mode.rs: erased decode crossed its guarded/authorized boundary", file=sys.stderr)
        raise SystemExit(1)
    cursor = position
PY
