#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"

# WHAT: Keeps codegen, facade and conformance verification on a bounded xtask dependency surface.
# WHY: Cargo builds every normal xtask dependency before dispatch, so one heavy dependency makes
# code generation pay for the facade, core and conformance crates before generation can start.
# HOW TO EXEMPT: There is no further exemption. Keep other exact crate requests on the full runner.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
    printf 'check_xtask_codegen_surface: %s\n' "$1" >&2
    exit 1
}

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_xtask_codegen_surface)" || exit 1
for required in .cargo/config.toml Cargo.toml xtask-launcher/Cargo.toml xtask-launcher/src/main.rs xtask/Cargo.toml xtask/src/main.rs xtask/src/catalog.rs xtask/src/verify.rs xtask/src/verify/launcher.rs \
    crates/conformance/Cargo.toml crates/conformance/src/cli.rs scripts/check_case_keys_honoured.sh \
    crates/gateway/tests/cors_runtime.rs crates/server/tests/server_load.rs \
    crates/server/tests/server_load/per_ip.rs; do
    [[ -f "${ROOT}/${required}" ]] || fail "required input is missing: ${required}"
done

"$PYTHON" - "$ROOT" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])

def fail(message):
    raise SystemExit(f"check_xtask_codegen_surface: {message}")

def load(relative):
    path = root / relative
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {relative}: {error}")
config = load(".cargo/config.toml")
alias = config.get("alias", {}).get("xtask")
expected_alias = "run --quiet --package xtask-launcher --"
if alias != expected_alias:
    fail("the cargo xtask alias must enter the budget-aware launcher")

workspace = load("Cargo.toml")
manifest = load("xtask/Cargo.toml")
launcher_manifest = load("xtask-launcher/Cargo.toml")
conformance_manifest = load("crates/conformance/Cargo.toml")
if launcher_manifest.get("package", {}).get("name") != "xtask-launcher":
    fail("the xtask launcher package name drifted")
if launcher_manifest.get("dependencies", {}):
    fail("the xtask launcher must stay dependency-free")
members = workspace.get("workspace", {}).get("members", [])
default_members = workspace.get("workspace", {}).get("default-members", [])
if "xtask-launcher" not in members or "xtask-launcher" not in default_members:
    fail("workspace tests must prebuild the xtask launcher")
conformance_features = conformance_manifest.get("features", {})
if conformance_features.get("default") != ["production-transports"] or conformance_features.get(
    "production-transports"
) != ["rustfs-gateway/server"]:
    fail("conformance must default to the production transport graph behind one feature")
if conformance_manifest.get("dependencies", {}).get("rustfs-gateway") != {"workspace": True}:
    fail("conformance must enable the facade server only through production-transports")
case_keys_guard = (root / "scripts/check_case_keys_honoured.sh").read_text()
audit_command = "cargo run -q -p rustfs-gateway-conformance --no-default-features --bin rustfs-gateway-conformance -- audit-keys"
if case_keys_guard.count(audit_command) != 1:
    fail("the case-key audit must stay off the production transport compile graph")
features = manifest.get("features")
if not isinstance(features, dict):
    fail("xtask must have dependency and feature tables")
if features.get("default") != ["full"]:
    fail("workspace tests must select the full xtask surface by default")
workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
if not isinstance(workspace_dependencies, dict):
    fail("the workspace dependency table is missing")


def dependency(alias_name, local):
    if isinstance(local, str):
        return alias_name, False
    if not isinstance(local, dict):
        fail(f"xtask dependency {alias_name} has an unsupported shape")
    if "features" in local or "default-features" in local:
        fail(f"xtask dependency {alias_name} may not alter dependency feature policy locally")
    inherited = {}
    if local.get("workspace") is True:
        if alias_name not in workspace_dependencies:
            fail(f"xtask dependency {alias_name} is missing from workspace dependencies")
        inherited = workspace_dependencies[alias_name]
        if isinstance(inherited, str):
            inherited = {}
        if not isinstance(inherited, dict):
            fail(f"workspace dependency {alias_name} has an unsupported shape")
        expected_features = {
            "proc-macro2": ["span-locations"],
            "serde": ["derive"],
            "syn": ["full", "extra-traits", "visit"],
        }.get(alias_name)
        expected_default_features = (
            False if alias_name in {"jsonschema", "rustfs-gateway", "rustfs-gateway-conformance"} else None
        )
        actual_features = inherited.get("features")
        actual_default_features = inherited.get("default-features")
        if actual_features != expected_features or actual_default_features != expected_default_features:
            fail(f"workspace dependency {alias_name} changed its inherited feature policy")
    package = local.get("package", inherited.get("package", alias_name))
    optional = local.get("optional", inherited.get("optional", False))
    if not isinstance(package, str) or not isinstance(optional, bool):
        fail(f"xtask dependency {alias_name} has unresolved package or optional metadata")
    return package, optional


def dependency_tables():
    tables = []
    for name in ("dependencies", "build-dependencies"):
        table = manifest.get(name, {})
        if not isinstance(table, dict):
            fail(f"xtask {name} must be a table")
        tables.append((name, table))
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        fail("xtask target dependencies must be tables")
    for target, target_manifest in targets.items():
        if not isinstance(target, str) or not isinstance(target_manifest, dict):
            fail("xtask target dependencies have an unsupported shape")
        for name in ("dependencies", "build-dependencies"):
            table = target_manifest.get(name, {})
            if not isinstance(table, dict):
                fail(f"xtask target {target} {name} must be a table")
            tables.append((f"target.{target}.{name}", table))
    return tables


resolved = []
for table_name, table in dependency_tables():
    for name, value in table.items():
        if not isinstance(name, str):
            fail(f"xtask {table_name} has a non-string dependency alias")
        package, optional = dependency(name, value)
        resolved.append((name, package, optional))

light = {package for _, package, optional in resolved if not optional}
expected_light = {
    "command-group",
    "rustfs-gateway-codegen",
    "rustfs-gateway-model",
    "serde",
    "serde_json",
    "signal-hook",
}
if light != expected_light:
    fail(f"the light xtask surface selected unexpected direct packages: {sorted(light)}")

banned = {"rustfs-gateway", "rustfs-gateway-core", "rustfs-gateway-conformance"}
actual = {package for _, package, _ in resolved}
missing = sorted(banned - actual)
if missing:
    fail(f"the full xtask surface lost required packages: {missing}")
if any(not optional for _, package, optional in resolved if package in banned):
    fail("gateway, core and conformance must remain optional from the light runner")


def feature_closure(name, seen):
    if name in seen:
        return set()
    seen.add(name)
    entries = features.get(name)
    if not isinstance(entries, list) or any(not isinstance(entry, str) for entry in entries):
        fail(f"feature {name} has an unsupported shape")
    enabled = set()
    for entry in entries:
        if "/" in entry or "?" in entry:
            fail(f"feature {name} may not forward dependency features: {entry}")
        if entry.startswith("dep:"):
            enabled.add(entry.removeprefix("dep:"))
        else:
            enabled.update(feature_closure(entry, seen))
    return enabled


full_dependencies = feature_closure("full", set())
optional_aliases = {name for name, _, optional in resolved if optional}
if full_dependencies != optional_aliases:
    fail("the full feature must enable every and only full-only optional dependency")
operation_dependencies = feature_closure("operation", set())
if operation_dependencies != {"http", "jsonschema", "rustfs-gateway", "rustfs-gateway-conformance", "rustfs-gateway-core"}:
    fail("the operation feature must carry only its in-process verification graph")

def rust_views(text):
    comments_removed = list(text)
    syntax = list(text)

    def blank(start, end, *, comments=True):
        targets = (comments_removed, syntax) if comments else (syntax,)
        for target in targets:
            for index in range(start, end):
                if target[index] != "\n":
                    target[index] = " "

    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                fail("xtask/src/main.rs has an unterminated block comment")
            blank(index, end)
            index = end
            continue

        raw_start = index
        prefix = None
        for candidate in ("br", "cr", "r"):
            if text.startswith(candidate, index):
                cursor = index + len(candidate)
                hashes = 0
                while cursor < len(text) and text[cursor] == "#":
                    hashes += 1
                    cursor += 1
                if cursor < len(text) and text[cursor] == '"':
                    prefix = (cursor, hashes)
                    break
        if prefix is not None:
            quote, hashes = prefix
            closing = '"' + ("#" * hashes)
            end = text.find(closing, quote + 1)
            if end < 0:
                fail("xtask/src/main.rs has an unterminated raw string")
            end += len(closing)
            blank(raw_start, end, comments=False)
            index = end
            continue

        string_start = index
        quote = index
        if text.startswith(('b"', 'c"'), index):
            quote += 1
        if quote < len(text) and text[quote] == '"':
            end = quote + 1
            escaped = False
            while end < len(text):
                char = text[end]
                if char == '"' and not escaped:
                    end += 1
                    break
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                end += 1
            else:
                fail("xtask/src/main.rs has an unterminated string")
            blank(string_start, end, comments=False)
            index = end
            continue

        char_start = index
        quote = index + 1 if text.startswith("b'", index) else index
        if quote < len(text) and text[quote] == "'":
            end = quote + 1
            escaped = False
            while end < len(text) and text[end] != "\n":
                char = text[end]
                if char == "'" and not escaped:
                    end += 1
                    blank(char_start, end, comments=False)
                    index = end
                    break
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                end += 1
            else:
                index += 1
            continue
        index += 1
    return "".join(comments_removed), "".join(syntax)


def balanced_end(code, start, opener, closer):
    depth = 0
    for index in range(start, len(code)):
        if code[index] == opener:
            depth += 1
        elif code[index] == closer:
            depth -= 1
            if depth == 0:
                return index + 1
    fail(f"xtask/src/main.rs has an unbalanced {opener}{closer} construct")


def outer_attributes(syntax, comments_removed, start):
    attributes = []
    cursor = start
    while True:
        cursor -= 1
        while cursor >= 0 and syntax[cursor].isspace():
            cursor -= 1
        if cursor < 0 or syntax[cursor] != "]":
            break
        depth = 1
        end = cursor + 1
        cursor -= 1
        while cursor >= 0 and depth:
            if syntax[cursor] == "]":
                depth += 1
            elif syntax[cursor] == "[":
                depth -= 1
            cursor -= 1
        if depth or cursor < 0 or syntax[cursor] != "#":
            break
        attributes.append(comments_removed[cursor:end])
    return list(reversed(attributes))


def functions_named(name, syntax, comments_removed):
    import re

    depths = []
    depth = 0
    for char in syntax:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                fail("xtask/src/main.rs has an unmatched closing brace")
    if depth:
        fail("xtask/src/main.rs has an unmatched opening brace")

    found = []
    pattern = re.compile(rf"\bfn\s+{re.escape(name)}\s*\(")
    for match in pattern.finditer(syntax):
        if depths[match.start()] != 0:
            continue
        body_start = syntax.find("{", match.end())
        if body_start < 0:
            fail(f"top-level function {name} has no body")
        body_end = balanced_end(syntax, body_start, "{", "}")
        found.append((outer_attributes(syntax, comments_removed, match.start()), comments_removed[body_start + 1:body_end - 1]))
    return found


def compact(text):
    result = []
    index = 0
    while index < len(text):
        raw = None
        for candidate in ("br", "cr", "r"):
            if text.startswith(candidate, index):
                cursor = index + len(candidate)
                hashes = 0
                while cursor < len(text) and text[cursor] == "#":
                    hashes += 1
                    cursor += 1
                if cursor < len(text) and text[cursor] == '"':
                    raw = (cursor, hashes)
                    break
        if raw is not None:
            quote, hashes = raw
            closing = '"' + ("#" * hashes)
            end = text.find(closing, quote + 1)
            if end < 0:
                fail("Rust comparison input has an unterminated raw string")
            end += len(closing)
            result.append(text[index:end])
            index = end
            continue

        quote = index + 1 if text.startswith(('b"', 'c"'), index) else index
        if quote < len(text) and text[quote] == '"':
            end = quote + 1
            escaped = False
            while end < len(text):
                char = text[end]
                if char == '"' and not escaped:
                    end += 1
                    result.append(text[index:end])
                    index = end
                    break
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                end += 1
            else:
                fail("Rust comparison input has an unterminated string")
            continue

        quote = index + 1 if text.startswith("b'", index) else index
        if quote < len(text) and text[quote] == "'":
            end = quote + 1
            escaped = False
            while end < len(text) and text[end] != "\n":
                char = text[end]
                if char == "'" and not escaped:
                    end += 1
                    result.append(text[index:end])
                    index = end
                    break
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                end += 1
            else:
                result.append(text[index])
                index += 1
            continue

        if not text[index].isspace():
            result.append(text[index])
        index += 1
    return "".join(result)


source = (root / "xtask/src/main.rs").read_text()
comments_removed, syntax = rust_views(source)
launcher_comments, launcher_syntax = rust_views((root / "xtask-launcher/src/main.rs").read_text())
launcher_request = functions_named("crate_request_name", launcher_syntax, launcher_comments)
expected_launcher_request = compact('''
if arguments.first().map(String::as_str) != Some("verify") {
    return None;
}
let mut verify_arguments = arguments[1..].iter().map(String::as_str).filter(|argument| *argument != "--json");
match (verify_arguments.next(), verify_arguments.next(), verify_arguments.next()) {
    (Some("--crate"), Some(name), None) => Some(name),
    _ => None,
}
''')
if len(launcher_request) != 1 or compact(launcher_request[0][1]) != expected_launcher_request:
    fail("the launcher must identify only an exact crate request")
launcher_runner = functions_named("runner_for_request", launcher_syntax, launcher_comments)
expected_launcher_runner = compact('''
if matches!(arguments, [command, flag, _] if command == "verify" && flag == "--op")
    || matches!(arguments, [command, json, flag, _] if command == "verify" && json == "--json" && flag == "--op")
{
    return OPERATION_RUNNER;
}
match crate_request_name(arguments) {
    Some("rustfs-gateway" | "s3gate" | "rustfs-gateway-conformance" | "s3gate-conformance" | "conformance") | None => {
        LIGHT_RUNNER
    }
    Some(_) => FULL_RUNNER,
}
''')
if len(launcher_runner) != 1 or compact(launcher_runner[0][1]) != expected_launcher_runner:
    fail("the launcher must select each bounded runner exactly")
launcher_source = compact(launcher_comments)
launcher_constants = {
    'const FULL_RUNNER: &[&str] = &["--features", "full"];',
    'const LIGHT_RUNNER: &[&str] = &["--no-default-features"];',
    'const OPERATION_RUNNER: &[&str] = &["--no-default-features", "--features", "operation"];',
}
if any(compact(constant) not in launcher_source for constant in launcher_constants):
    fail("the launcher runner arguments drifted")
launcher_main = functions_named("main", launcher_syntax, launcher_comments)
launcher_body = compact(launcher_main[0][1]) if len(launcher_main) == 1 else ""
launcher_fragments = {
    "runner split": 'let runner = runner_for_request(&arguments);',
    "startup clock": 'Ok(started) => started.as_nanos().to_string()',
    "budget handoff": '.env(STARTED_ENV, started)',
    "xtask child": '.args(["run", "--quiet", "--package", "xtask"]).args(runner).arg("--").args(arguments)',
}
if not launcher_body or any(compact(fragment) not in launcher_body for fragment in launcher_fragments.values()):
    fail("the launcher must preserve runner selection, child arguments, and startup recording")
dispatches = functions_named("dispatch", syntax, comments_removed)
expected_full_attribute = compact('#[cfg(feature = "full")]')
expected_light_attribute = compact('#[cfg(not(feature = "full"))]')
expected_operation_attribute = compact('#[cfg(feature = "operation")]')
full_dispatches = [body for attrs, body in dispatches if [compact(attr) for attr in attrs] == [expected_full_attribute]]
light_dispatches = [body for attrs, body in dispatches if [compact(attr) for attr in attrs] == [expected_light_attribute]]
if len(full_dispatches) != 1 or len(light_dispatches) != 1 or len(dispatches) != 2:
    fail("xtask must have exactly one full and one light top-level dispatch function")

expected_light_dispatch = compact('''
match first.as_deref() {
    Some("codegen") => codegen::codegen(&rest),
    Some("spec") if rest.first().map(String::as_str) == Some("verify") => codegen::verify(&rest[1..]),
    Some("verify") if verify::is_available_request(&rest) => verify::verify(&rest),
    _ => run_full(first, &rest),
}
''')
if compact(light_dispatches[0]) != expected_light_dispatch:
    fail("the bounded dispatcher must directly handle codegen, crate, and operation verification")

run_full_functions = functions_named("run_full", syntax, comments_removed)
if len(run_full_functions) != 1 or [compact(attr) for attr in run_full_functions[0][0]] != [expected_light_attribute]:
    fail("xtask must have exactly one light-only full-runner bridge")
expected_run_full = compact('''
let mut command = std::process::Command::new(env!("CARGO"));
command.args(["run", "--quiet", "--package", "xtask", "--features", "full", "--"]);
if let Some(first) = first {
    command.arg(first);
}
command.args(rest);
#[cfg(unix)]
{
    use std::os::unix::process::CommandExt;
    let error = command.exec();
    eprintln!("failed to run full xtask: {error}");
    ExitCode::FAILURE
}
#[cfg(not(unix))]
match command.status() {
    Ok(status) => std::process::exit(status.code().unwrap_or(1)),
    Err(error) => {
        eprintln!("failed to run full xtask: {error}");
        std::process::exit(1)
    }
}
''')
if compact(run_full_functions[0][1]) != expected_run_full:
    fail("the full-runner bridge must preserve argument order and child status")


def top_level_items(pattern):
    import re

    depth = 0
    depths = []
    for char in syntax:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return [
        (match, outer_attributes(syntax, comments_removed, match.start()))
        for match in re.finditer(pattern, syntax)
        if depths[match.start()] == 0
    ]


catalog_items = top_level_items(r"\bmod\s+catalog\s*;")
verify_items = top_level_items(r"\bmod\s+verify\s*;")
usage_items = top_level_items(r"\bconst\s+USAGE\s*:")
if len(catalog_items) != 1 or catalog_items[0][1]:
    fail("the catalog module must remain available to the light codegen runner")
if len(verify_items) != 1 or verify_items[0][1]:
    fail("the verify module must remain available to the light crate-verification runner")
if len(usage_items) != 1 or [compact(attr) for attr in usage_items[0][1]] != [expected_full_attribute]:
    fail("the USAGE constant must remain full-only so light commands emit no dead-code warnings")

catalog_source = (root / "xtask/src/catalog.rs").read_text()
catalog_comments, catalog_syntax = rust_views(catalog_source)
main_comments, main_syntax = comments_removed, syntax
comments_removed, syntax = catalog_comments, catalog_syntax
light_catalog_items = ["operations", "verify_map_path", "render_verify_map", "quoted_value", "operation_cases", "collect_toml"]
operation_catalog_items = ["nearest", "verify_entry", "scaffold_entry", "parse_verify_map", "split_cases", "quoted_field", "distance"]
for name in light_catalog_items:
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bfn\s+{name}\s*\(")
    if len(items) != 1 or items[0][1]:
        fail(f"catalog item {name} must remain on the light codegen surface")
for name in operation_catalog_items:
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bfn\s+{name}\s*\(")
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_operation_attribute]:
        fail(f"catalog item {name} must remain operation-only")
for name in ("VerifyEntry", "ScaffoldEntry"):
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bstruct\s+{name}\b")
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_operation_attribute]:
        fail(f"catalog item {name} must remain operation-only")
comments_removed, syntax = main_comments, main_syntax

verify_source = (root / "xtask/src/verify.rs").read_text()
verify_comments, verify_syntax = rust_views(verify_source)
for relative, test_name in (
    ("crates/conformance/src/cli.rs", "feedback_case_c_object_0001"),
    ("crates/gateway/tests/cors_runtime.rs", "a_million_unique_keys_keep_rss_within_the_entry_budget"),
    ("crates/server/tests/server_load.rs", "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget"),
    (
        "crates/server/tests/server_load.rs",
        "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic",
    ),
    (
        "crates/server/tests/server_load/per_ip.rs",
        "c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99",
    ),
):
    _, test_syntax = rust_views((root / relative).read_text())
    pattern = re.compile(
        rf"#\s*\[\s*(?:test|tokio\s*::\s*test(?:\s*\([^]]*\))?)\s*\]\s*(?:async\s+)?fn\s+"
        rf"{re.escape(test_name)}\s*\("
    )
    if len(pattern.findall(test_syntax)) != 1:
        fail(f"workspace-only fast-scope contract is missing or inactive: {test_name}")
comments_removed, syntax = verify_comments, verify_syntax
for name in ("verify", "verify_crate", "conformance_test_step"):
    items = functions_named(name, syntax, comments_removed)
    if len(items) != 1 or items[0][0]:
        fail(f"verify item {name} must remain on the light crate-verification surface")
selection_path = root / "xtask/src/verify/selection.rs"
selection_modules = top_level_items(r"\bmod\s+selection\s*;")
selection_imports = top_level_items(r"\buse\s+selection\s*::\s*crate_steps\s*;")
if selection_path.is_file():
    if len(selection_modules) != 1 or selection_modules[0][1] or len(selection_imports) != 1 or selection_imports[0][1]:
        fail("the crate-step selection module must remain unconditionally available to the light runner")
    if functions_named("crate_steps", syntax, comments_removed):
        fail("crate_steps must have one source of truth")
    selection_comments, selection_syntax = rust_views(selection_path.read_text())
    crate_steps_items = functions_named("crate_steps", selection_syntax, selection_comments)
else:
    if selection_modules or selection_imports:
        fail("the crate-step selection module wiring requires its source file")
    crate_steps_items = functions_named("crate_steps", syntax, comments_removed)
if len(crate_steps_items) != 1 or crate_steps_items[0][0]:
    fail("verify item crate_steps must remain on the light crate-verification surface")
request_items = functions_named("is_available_request", syntax, comments_removed)
request_declarations = top_level_items(r"\bpub\s*\(\s*crate\s*\)\s+fn\s+is_available_request\s*\(")
if len(request_items) != 1 or len(request_declarations) != 1 or [compact(attr) for attr in request_declarations[0][1]] != [expected_light_attribute]:
    fail("bounded-request classification must remain non-full-only")
expected_request_body = compact('''
let (args, _) = take_json(args);
matches!(args.as_slice(), [flag, _] if flag == "--crate")
    || cfg!(feature = "operation") && matches!(args.as_slice(), [flag, _] if flag == "--op")
''')
if compact(request_items[0][1]) != expected_request_body:
    fail("bounded verification must recognize only exact crate and enabled operation pairs")
verify_items = functions_named("verify", syntax, comments_removed)
expected_verify_body = compact('''
let (args, json) = take_json(args);
match args.as_slice() {
    [flag, name] if flag == "--crate" => return verify_crate(name, json),
    _ => {}
}
#[cfg(feature = "full")]
{
    verify_full(&args, json)
}
#[cfg(not(feature = "full"))]
{
    #[cfg(feature = "operation")]
    if let [flag, name] = args.as_slice() && flag == "--op" {
        return verify_operation(name, json);
    }
    usage()
}
''')
if compact(verify_items[0][1]) != expected_verify_body:
    fail("verify must execute exact crate and operation requests on their bounded surfaces")
verify_crate_items = functions_named("verify_crate", syntax, comments_removed)
expected_verify_crate_body = compact('''
let started = match launcher_started() {
    Ok(started) => started,
    Err(error) => return diagnostic("xtask launcher timestamp is invalid", "crate verification", &error),
};
let package = match resolve_workspace_package(name) {
    Ok(package) => package,
    Err(error) => {
        if json {
            println!("{}", package_resolution_failure_json(name, &error));
            return ExitCode::FAILURE;
        }
        return diagnostic("workspace package could not be resolved", &format!("crate {name}"), &error.to_string());
    }
};
let step_batches = crate_step_batches(&package);
let conformance_case = standalone_crate_case(&package);
let subject = if package == "rustfs-gateway" {
    format!(
        "crate {package} fast runtime scope; compile-time, representative conformance, and million-key RSS contracts remain in cargo test --workspace"
    )
} else if package == "rustfs-gateway-core" {
    format!("crate {package} runtime scope; compile-time contracts remain in cargo test --workspace")
} else if package == "rustfs-gateway-conformance" {
    format!("crate {package} library scope; integration contracts remain in cargo test --workspace")
} else if package == "rustfs-gateway-server" {
    format!("crate {package} runtime scope; thousand-connection load contracts remain in cargo test --workspace")
} else {
    format!("crate {package}")
};
let build = match run_prebuild(&prebuild_commands(&step_batches, conformance_case), &subject) {
    Ok(build) => build,
    Err(exit) => return exit,
};
eprintln!(
    "verify: {subject} build compiled {} crate(s) in {:.2}s outside the budget",
    build.compiled_crates,
    build.elapsed.as_secs_f64()
);
run_step_batches(
    &step_batches,
    Duration::from_secs(30),
    &subject,
    "a crate verification loop must finish within 30 seconds",
    RunOptions {
        json,
        operation_cases: None,
        started: started.and_then(|started| started.checked_add(build.elapsed)),
        conformance_case,
    },
)
''')
if compact(verify_crate_items[0][1]) != expected_verify_crate_body:
    fail("crate verification must disclose each fast-scope boundary and keep the 30-second deadline")
expected_crate_steps_body = compact('''
if package == "xtask" {
    let target_scope = ["--workspace", "--bin", "xtask", "--test", "xtask-integration"];
    return vec![
        std::iter::once("test")
            .chain(target_scope)
            .map(str::to_owned)
            .collect(),
        std::iter::once("clippy")
            .chain(target_scope)
            .chain(["--", "-D", "warnings"])
            .map(str::to_owned)
            .collect(),
    ];
}
let clippy_step = vec![
    "clippy".to_owned(),
    "-p".to_owned(),
    package.to_owned(),
    match package {
        "rustfs-gateway-conformance" => "--lib",
        _ => "--all-targets",
    }
    .to_owned(),
    "--".to_owned(),
    "-D".to_owned(),
    "warnings".to_owned(),
];
if package == "rustfs-gateway-core" {
    return vec![
        vec![
            "test".to_owned(),
            "-p".to_owned(),
            package.to_owned(),
            "--lib".to_owned(),
            "--test".to_owned(),
            "integration".to_owned(),
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
        ],
        clippy_step,
    ];
}
let mut test_step = vec!["test".to_owned(), "-p".to_owned(), package.to_owned()];
if package == "rustfs-gateway" {
    test_step.extend(["--lib".to_owned(), "--test".to_owned(), "integration".to_owned()]);
    test_step.extend([
        "--".to_owned(),
        "--skip".to_owned(),
        "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
    ]);
} else if package == "rustfs-gateway-sig" {
    test_step.extend(
        [
            "--",
            "--skip",
            "timing::c_sig_0552_sigv2_difference_position_does_not_change_the_latency",
            "--skip",
            "timing::c_sig_0111_an_unknown_key_costs_the_same_as_a_bad_signature",
            "--skip",
            "timing::a_match_and_a_mismatch_cost_the_same",
            "--skip",
            "timing::c_sig_0107_and_0108_the_position_of_the_difference_does_not_change_the_latency",
            "--exact",
        ]
        .map(str::to_owned),
    );
} else if package == "rustfs-gateway-conformance" {
    test_step.push("--lib".to_owned());
}
vec![test_step, clippy_step]
''')
if compact(crate_steps_items[0][1]) != expected_crate_steps_body:
    fail("crate verification steps must preserve xtask workspace target reuse, both core runtime targets, gateway library and integration targets, exact signature timing skips, compile-fail skips, and conformance library-only test and clippy scopes")
conformance_test_items = functions_named("conformance_test_step", syntax, comments_removed)
expected_conformance_test_body = compact('''
vec![
    "test".to_owned(),
    "-p".to_owned(),
    "rustfs-gateway-conformance".to_owned(),
    "--lib".to_owned(),
    format!("cli::tests::feedback_case_{}", case.replace('-', "_")),
    "--".to_owned(),
    "--exact".to_owned(),
]
''')
if compact(conformance_test_items[0][1]) != expected_conformance_test_body:
    fail("crate verification must reuse the workspace-built conformance library target")
run_step_batches_items = functions_named("run_step_batches", syntax, comments_removed)
run_step_batches_body = compact(run_step_batches_items[0][1])
expected_crate_batch_order = compact('''
let mut command_batches = Vec::new();
if let Some(case) = conformance_case {
    command_batches.push(vec![(
        env!("CARGO").to_owned(),
        conformance_test_step(case),
        format!("{subject} conformance case {case}"),
    )]);
}
let mut step_number = 0;
''')
if run_step_batches_body.count(expected_crate_batch_order) != 1:
    fail("standalone crate conformance verification must precede the scheduled command batches")
crate_step_batches_items = functions_named("crate_step_batches", syntax, comments_removed)
expected_gateway_batch = compact('''
let mut test = steps.remove(0);
test.extend(["--skip".to_owned(), GATEWAY_RSS_TEST.to_owned()]);
let clippy = steps.remove(0);
return vec![vec![test, clippy]];
''')
if compact(crate_step_batches_items[0][1]).count(expected_gateway_batch) != 1:
    fail("gateway fast verification must retain ordinary runtime tests and all-target Clippy")
expected_server_batch = compact('''
let mut test = steps.remove(0);
test.extend([
    "--".to_owned(),
    "--skip".to_owned(),
    "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget".to_owned(),
    "--skip".to_owned(),
    "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic".to_owned(),
    "--skip".to_owned(),
    "c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99".to_owned(),
]);
let clippy = steps.remove(0);
return vec![vec![test, clippy]];
''')
if compact(crate_step_batches_items[0][1]).count(expected_server_batch) != 1:
    fail("server fast verification must retain ordinary runtime tests and defer only the three workspace load contracts")
standalone_case_items = functions_named("standalone_crate_case", syntax, comments_removed)
expected_standalone_case = compact('''
(package != "rustfs-gateway").then(|| crate_case(package)).flatten()
''')
if compact(standalone_case_items[0][1]) != expected_standalone_case:
    fail("gateway representative evidence must run exactly once inside its bounded batch")
for name in (
    "verify_operation",
    "run_representative_case",
    "run_operation_contract",
    "verify_scaffold",
    "snake_case",
    "run_steps",
):
    items = functions_named(name, syntax, comments_removed)
    if len(items) != 1 or [compact(attr) for attr in items[0][0]] != [expected_operation_attribute]:
        fail(f"verify item {name} must remain operation-only")
for name in (
    "verify_full",
    "run_all",
    "run_setup_then_concurrently",
    "run_commands_concurrently",
    "run",
):
    items = functions_named(name, syntax, comments_removed)
    if len(items) != 1 or [compact(attr) for attr in items[0][0]] != [expected_full_attribute]:
        fail(f"verify item {name} must remain full-only")
run_representative_body = functions_named("run_representative_case", syntax, comments_removed)[0][1]
expected_run_representative_body = compact('''
for case in cases {
    let report = match rustfs_gateway_conformance::cli::run_filtered(case) {
        Ok(report) => report,
        Err(_) => continue,
    };
    match rustfs_gateway_conformance::cli::status_code(
        &report,
        None,
        rustfs_gateway_conformance::cli::Command::Run
    ) {
        rustfs_gateway_conformance::cli::exit::SUCCESS => return Ok(Some(case.clone())),
        rustfs_gateway_conformance::cli::exit::ENVIRONMENT => continue,
        code => {
            eprint!("{}", report.render_text(None));
            print_json_failure(json, "operation conformance case failed", case);
            return Err(diagnostic(
                "operation conformance case failed",
                case,
                &format!("a-xt-0002 requires {name} conformance evidence; conformance exited with {code}"),
            ));
        }
    }
}
if cases.is_empty() {
    return Ok(None);
}
print_json_failure(json, "no mapped conformance case could execute", name);
Err(diagnostic(
    "no mapped conformance case could execute",
    name,
    "a-xt-0002 requires an observed conformance result, not a skipped case",
))
''')
if compact(run_representative_body) != expected_run_representative_body:
    fail("operation conformance verification must stay on the reviewed in-process, fail-closed path")
run_operation_contract_body = functions_named("run_operation_contract", syntax, comments_removed)[0][1]
expected_run_operation_contract_body = compact('''
catalog::verify_operation_contract(name, mapped_cases)
''')
if compact(run_operation_contract_body) != expected_run_operation_contract_body:
    fail("operation route verification must stay a direct in-process catalog contract")
verify_full_items = functions_named("verify_full", syntax, comments_removed)
expected_verify_full_body = compact('''
match args {
    [] => run(
        &["test", "--workspace"],
        Duration::from_secs(600),
        "workspace",
        "the full gate must finish within 10 minutes",
        json,
    ),
    [flag] if flag == "--all" => run_all(json),
    [flag, name] if flag == "--op" => verify_operation(name, json),
    _ => usage(),
}
''')
if compact(verify_full_items[0][1]) != expected_verify_full_body:
    fail("full verification must match its borrowed argument slice without unstable conversion")
for name in ("GateCommand", "GateResult"):
    items = top_level_items(rf"\btype\s+{name}\s*=")
    if len(items) != 1 or items[0][1]:
        fail(f"verify item {name} must remain on the light crate-verification surface")
process_items = top_level_items(r"\bmod\s+process\s*;")
if len(process_items) != 1 or process_items[0][1]:
    fail("the process supervisor must remain on the light crate-verification surface")
for pattern, description in (
    (r"\buse\s+crate\s*::\s*\{\s*catalog\s*,\s*codegen\s*\}\s*;", "the operation catalog imports"),
):
    items = top_level_items(pattern)
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_operation_attribute]:
        fail(f"{description} must remain operation-only")
output_imports = top_level_items(r"\buse\s+std\s*::\s*process\s*::\s*\{[^}]*\bOutput\b[^}]*\}\s*;")
if len(output_imports) != 1 or output_imports[0][1]:
    fail("the process output import must remain on the light crate-verification surface")
tests_items = top_level_items(r"\bmod\s+tests\s*;")
expected_tests_attribute = compact('#[cfg(all(test, feature = "full"))]')
if len(tests_items) != 1 or [compact(attr) for attr in tests_items[0][1]] != [expected_tests_attribute]:
    fail("verify module tests must require the full feature")

print("OK: cargo xtask keeps codegen, facade and conformance verification light while other crates reuse the full runner")
PYEOF
