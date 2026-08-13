#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keeps codegen and exact crate verification on a bounded xtask dependency surface.
# WHY: Cargo builds every normal xtask dependency before dispatch, so one heavy dependency makes
# code generation pay for the facade, core and conformance crates before generation can start.
# HOW TO EXEMPT: There is no exemption. Keep the command and split new full-only work behind `full`.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
    printf 'check_xtask_codegen_surface: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
for required in .cargo/config.toml Cargo.toml xtask/Cargo.toml xtask/src/main.rs xtask/src/catalog.rs xtask/src/verify.rs; do
    [[ -f "${ROOT}/${required}" ]] || fail "required input is missing: ${required}"
done

python3 - "$ROOT" <<'PYEOF'
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
expected_alias = "run --quiet --package xtask --no-default-features --"
if alias != expected_alias:
    fail("the cargo xtask alias must select the no-default-feature dispatcher")

workspace = load("Cargo.toml")
manifest = load("xtask/Cargo.toml")
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
        expected_default_features = False if alias_name == "jsonschema" else None
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
dispatches = functions_named("dispatch", syntax, comments_removed)
expected_full_attribute = compact('#[cfg(feature = "full")]')
expected_light_attribute = compact('#[cfg(not(feature = "full"))]')
full_dispatches = [body for attrs, body in dispatches if [compact(attr) for attr in attrs] == [expected_full_attribute]]
light_dispatches = [body for attrs, body in dispatches if [compact(attr) for attr in attrs] == [expected_light_attribute]]
if len(full_dispatches) != 1 or len(light_dispatches) != 1 or len(dispatches) != 2:
    fail("xtask must have exactly one full and one light top-level dispatch function")

expected_light_dispatch = compact('''
match first.as_deref() {
    Some("codegen") => codegen::codegen(&rest),
    Some("spec") if rest.first().map(String::as_str) == Some("verify") => codegen::verify(&rest[1..]),
    Some("verify") if verify::is_crate_request(&rest) => verify::verify(&rest),
    _ => run_full(first, &rest),
}
''')
if compact(light_dispatches[0]) != expected_light_dispatch:
    fail("the light dispatcher must directly handle codegen, spec verify and exact crate verification")

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
full_catalog_items = ["nearest", "verify_entry", "scaffold_entry", "parse_verify_map", "split_cases", "quoted_field", "distance"]
for name in light_catalog_items:
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bfn\s+{name}\s*\(")
    if len(items) != 1 or items[0][1]:
        fail(f"catalog item {name} must remain on the light codegen surface")
for name in full_catalog_items:
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bfn\s+{name}\s*\(")
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_full_attribute]:
        fail(f"catalog item {name} must remain full-only")
for name in ("VerifyEntry", "ScaffoldEntry"):
    items = top_level_items(rf"(?:\bpub\s*\(\s*crate\s*\)\s+)?\bstruct\s+{name}\b")
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_full_attribute]:
        fail(f"catalog item {name} must remain full-only")
comments_removed, syntax = main_comments, main_syntax

verify_source = (root / "xtask/src/verify.rs").read_text()
verify_comments, verify_syntax = rust_views(verify_source)
comments_removed, syntax = verify_comments, verify_syntax
for name in ("verify", "verify_crate", "crate_steps"):
    items = functions_named(name, syntax, comments_removed)
    if len(items) != 1 or items[0][0]:
        fail(f"verify item {name} must remain on the light crate-verification surface")
request_items = functions_named("is_crate_request", syntax, comments_removed)
request_declarations = top_level_items(r"\bpub\s*\(\s*crate\s*\)\s+fn\s+is_crate_request\s*\(")
if len(request_items) != 1 or len(request_declarations) != 1 or [compact(attr) for attr in request_declarations[0][1]] != [expected_light_attribute]:
    fail("crate-request classification must remain light-only")
expected_request_body = compact('''
let (args, _) = take_json(args);
matches!(args.as_slice(), [flag, _] if flag == "--crate")
''')
if compact(request_items[0][1]) != expected_request_body:
    fail("light crate verification must recognize only one crate pair with optional JSON output")
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
    usage()
}
''')
if compact(verify_items[0][1]) != expected_verify_body:
    fail("verify must execute exact crate requests before delegating full-only forms")
verify_crate_items = functions_named("verify_crate", syntax, comments_removed)
expected_verify_crate_body = compact('''
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
let steps = crate_steps(&package);
let subject = if package == "rustfs-gateway-core" {
    format!("crate {package} runtime scope; compile-time contracts remain in cargo test --workspace")
} else if package == "rustfs-gateway-conformance" {
    format!("crate {package} library scope; integration contracts remain in cargo test --workspace")
} else {
    format!("crate {package}")
};
run_steps(
    &steps,
    Duration::from_secs(30),
    &subject,
    "a crate verification loop must finish within 30 seconds",
    json,
    None,
    None,
)
''')
if compact(verify_crate_items[0][1]) != expected_verify_crate_body:
    fail("crate verification must disclose each fast-scope boundary and keep the 30-second deadline")
crate_steps_items = functions_named("crate_steps", syntax, comments_removed)
expected_crate_steps_body = compact('''
let mut test_step = vec!["test".to_owned(), "-p".to_owned(), package.to_owned()];
if package == "rustfs-gateway-core" {
    test_step.extend([
        "--".to_owned(),
        "--skip".to_owned(),
        "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
    ]);
} else if package == "rustfs-gateway-conformance" {
    test_step.push("--lib".to_owned());
}
let mut steps = vec![
    test_step,
    vec![
        "clippy".to_owned(),
        "-p".to_owned(),
        package.to_owned(),
        "--all-targets".to_owned(),
        "--".to_owned(),
        "-D".to_owned(),
        "warnings".to_owned(),
    ],
];
if let Some(case) = crate_case(package) {
    steps.push(conformance_step("validate", case));
}
steps
''')
if compact(crate_steps_items[0][1]) != expected_crate_steps_body:
    fail("crate verification steps must preserve the core skip, conformance library scope and all-target clippy")
for name in (
    "verify_full",
    "verify_operation",
    "run_representative_case",
    "run_operation_contract",
    "verify_scaffold",
    "snake_case",
    "run_all",
    "run_setup_then_concurrently",
    "run_commands_concurrently",
    "run",
):
    items = functions_named(name, syntax, comments_removed)
    if len(items) != 1 or [compact(attr) for attr in items[0][0]] != [expected_full_attribute]:
        fail(f"verify item {name} must remain full-only")
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
    if len(items) != 1 or [compact(attr) for attr in items[0][1]] != [expected_full_attribute]:
        fail(f"{description} must remain full-only")
output_imports = top_level_items(r"\buse\s+std\s*::\s*process\s*::\s*\{[^}]*\bOutput\b[^}]*\}\s*;")
if len(output_imports) != 1 or output_imports[0][1]:
    fail("the process output import must remain on the light crate-verification surface")
tests_items = top_level_items(r"\bmod\s+tests\s*\{")
expected_tests_attribute = compact('#[cfg(all(test, feature = "full"))]')
if len(tests_items) != 1 or [compact(attr) for attr in tests_items[0][1]] != [expected_tests_attribute]:
    fail("verify module tests must require the full feature")

print("OK: cargo xtask keeps codegen and exact crate verification on the bounded light surface")
PYEOF
