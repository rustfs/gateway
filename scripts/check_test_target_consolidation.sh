#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   Core, gateway, and conformance integration suites each use one explicit Cargo target with every
#   test source registered exactly once, and gateway's compile-fail cases share one trybuild batch.
# WHY
#   rustfs/gateway#60 measured separate integration targets and trybuild batches rebuilding the
#   same test products until the 30-second verification budget expired.
# HOW TO EXEMPT
#   There are no exemptions for the three crates below. Add or remove a test by updating the source
#   inventory and its single harness registration together.
#
#   That sentence used to be written without the qualifier, and for the workspace it was not true:
#   this guard names three crates, and every other member was exempt by omission with nothing
#   saying so (rustfs/gateway#277). scripts/check_test_target_coverage.sh is what makes the
#   workspace-wide claim, by discovering the members instead of listing them.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_test_target_consolidation)" || exit 1

"$PYTHON" - "$REPO_ROOT" <<'PYEOF'
from pathlib import Path
import re
import sys
import tomllib


root = Path(sys.argv[1]).resolve()


def fail(message: str) -> None:
    raise SystemExit(f"test-target consolidation violation: {message}")


# Matched at a position rather than against `source[index:]`. Slicing the remainder of the file
# on every character makes the scan quadratic in file size, and this function runs once per source
# file per guard invocation — sixty-one of them in the self-test alone. Neither pattern is anchored
# or uses a lookbehind, so matching at an offset is the same match.
#
# A token this scanner cares about can only begin at one of these characters: `//` and `/*` start
# with a slash, `"` and `b"` with a quote or a `b`, a raw string with `r` or `b`, a character
# literal with `'` or `b`. Every other position is passed over, so the scanner skips runs of
# ordinary code in one C-level search instead of one Python loop iteration per byte. The set is
# what makes that equivalent to walking every index, and it must be widened in step with the
# branches below.
#
# `b` is in the set for the branches that read it and not because dropping it would break
# anything: `b"…"` ends where the `"…"` inside it ends, `b'x'` where `'x'` does, and `br"…"` where
# `r"…"` does, so every byte-prefixed form falls through to the same close via its unprefixed
# opener. It is listed because the branches below genuinely begin there and a reader checking the
# set against them should find it — but `scripts/test_test_target_consolidation.sh` cannot kill a
# mutation that removes it, and that is a property of Rust's grammar rather than a gap in the
# suite. Removing `/`, `"` or `'` is caught.
TOKEN_START = re.compile(r"""[/"'br]""")
RUST_RAW_STRING = re.compile(r'(?:b)?r(#{0,255})"')
RUST_CHAR_LITERAL = re.compile(r"(?:b)?'(?:\\.|[^'\\\n])+'")


def rust_views(source: str, path: Path) -> tuple[str, str]:
    """Return comment-free source and code with comments/literals masked."""
    comment_free = list(source)
    code_only = list(source)
    index = 0
    length = len(source)

    def mask(start: int, end: int, *, comments: bool) -> None:
        segment = source[start:end]
        blanks = [" "] * len(segment) if "\n" not in segment else [" " if c != "\n" else "\n" for c in segment]
        code_only[start:end] = blanks
        if comments:
            comment_free[start:end] = blanks

    while index < length:
        step = TOKEN_START.search(source, index)
        if step is None:
            break
        index = step.start()
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end < 0 else end
            mask(index, end, comments=True)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                fail(f"{path.relative_to(root)} has an unterminated block comment")
            mask(index, end, comments=True)
            index = end
            continue

        raw = RUST_RAW_STRING.match(source, index)
        if raw:
            delimiter = '"' + raw.group(1)
            body_start = raw.end()
            close = source.find(delimiter, body_start)
            if close < 0:
                fail(f"{path.relative_to(root)} has an unterminated raw string")
            end = close + len(delimiter)
            mask(index, end, comments=False)
            index = end
            continue

        prefix = 2 if source.startswith('b"', index) else 1 if source[index] == '"' else 0
        if prefix:
            end = index + prefix
            escaped = False
            while end < length:
                char = source[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            else:
                fail(f"{path.relative_to(root)} has an unterminated string")
            mask(index, end, comments=False)
            index = end
            continue

        char_literal = RUST_CHAR_LITERAL.match(source, index)
        if char_literal:
            end = char_literal.end()
            mask(index, end, comments=False)
            index = end
            continue
        index += 1
    return "".join(comment_free), "".join(code_only)


def balanced_end(code: str, opening: int, path: Path) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [code[opening]]
    position = opening + 1
    while position < len(code) and stack:
        char = code[position]
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if pairs[stack[-1]] != char:
                fail(f"{path.relative_to(root)} has mismatched Rust delimiters")
            stack.pop()
        position += 1
    if stack:
        fail(f"{path.relative_to(root)} has an unterminated Rust delimiter")
    return position


def inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


license_header = """// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"""

core_modules = (
    "acl_contract",
    "acl_roundtrip",
    "authz_consumption",
    "bucketconfig_roundtrip",
    "codec_binding",
    "committed_head",
    "compile_fail",
    "configuration_error_declarations",
    "cors_roundtrip",
    "dialect",
    "dialect_claims",
    "dialect_claims_refusals",
    "dto_cold_split",
    "empty_enumeration",
    "encryption_roundtrip",
    "error_resolution",
    "event_stream_frame_replay",
    "ext_field_policy",
    "golden",
    "hot_path",
    "legacy_rustfs_refusal",
    "lifecycle_roundtrip",
    "limit_layering",
    "lock_roundtrip",
    "not_configured_declarations",
    "notification_roundtrip",
    "operation_spec_semver",
    "params_and_dispatch",
    "policy_json_replay",
    "post_object",
    "pre_auth_errors",
    "precondition_range",
    "purity_guard",
    "range_part_table",
    "registration",
    "replication_invariants",
    "replication_roundtrip",
    "response_override_safety",
    "restore_header_replay",
    "route_only",
    "route_sizes",
    "route_table",
    "rule_filter_boundaries",
    "security_request_policy",
    "select_records_framing",
    "select_restore_roundtrip",
    "selector_required_params",
    "static_dispatch",
    "tagging_contract",
    "tagging_roundtrip",
    "tolerant_conditions",
    "update_object_encryption_roundtrip",
    "upload_capability",
    "website_roundtrip",
    "xml_character_range",
    "xml_parse_replay",
)
core_tests = root / "crates/core/tests"
actual_core_sources = tuple(
    sorted(path.stem for path in core_tests.glob("*.rs") if path.name != "integration.rs")
)
if actual_core_sources != core_modules:
    fail("core test source inventory does not match the consolidated module suite")

resolved_core_sources: dict[Path, str] = {}
for module in core_modules:
    source_path = core_tests / f"{module}.rs"
    if source_path.is_symlink():
        fail(f"{source_path.relative_to(root)} may not be a symlink")
    try:
        resolved_source = source_path.resolve(strict=True)
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read {source_path.relative_to(root)}: {error}")
    if not inside(resolved_source, core_tests.resolve()):
        fail(f"{source_path.relative_to(root)} resolves outside the core test directory")
    previous = resolved_core_sources.get(resolved_source)
    if previous is not None:
        fail(f"core test sources {previous} and {module} resolve to the same file")
    resolved_core_sources[resolved_source] = module
    _, code_only = rust_views(source, source_path)
    if re.search(r"#!\s*\[\s*(?:cfg|cfg_attr)\b", code_only):
        fail(f"{source_path.relative_to(root)} may not disable its registered module with a file-level cfg")

core_manifest_path = root / "crates/core/Cargo.toml"
try:
    core_manifest = tomllib.loads(core_manifest_path.read_text())
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse crates/core/Cargo.toml: {error}")
package = core_manifest.get("package")
if not isinstance(package, dict) or package.get("autotests") is not False:
    fail("crates/core must set package.autotests = false")
targets = core_manifest.get("test")
if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], dict):
    fail("crates/core must declare exactly one explicit [[test]] target")
target = targets[0]
if target.get("name") != "integration" or target.get("path") != "tests/integration.rs":
    fail("crates/core explicit test target must be integration at tests/integration.rs")
if target.get("test", True) is not True or target.get("harness", True) is not True:
    fail("crates/core integration target must use the active Rust test harness")
required_features = target.get("required-features", [])
if not isinstance(required_features, list) or required_features:
    fail("crates/core integration target must run without required features")

core_harness = license_header + """
//! Consolidated integration-test entry point for `rustfs-gateway-core`.
//!
//! Responsible for: registering every core integration-test source in one Cargo target.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the core integration-test modules. Downstream: Cargo's test harness.

mod support;

""" + "\n".join(f'#[path = "{module}.rs"]\nmod {module};\n' for module in core_modules)
core_harness_path = core_tests / "integration.rs"
try:
    actual_core_harness = core_harness_path.read_text()
except OSError as error:
    fail(f"cannot read crates/core/tests/integration.rs: {error}")
if actual_core_harness != core_harness:
    fail("core integration harness must register each frozen source exactly once")

conformance_modules = (
    "bucket_family",
    "bucket_lifecycle",
    "copy_family",
    "corpus",
    "corpus_drafts",
    "domain_wiring",
    "encryption_blocked_types",
    "lifecycle_family",
    "list_family",
    "multipart_family",
    "object",
    "range_cond_family",
    "tagging",
    "tagging_family",
    "wired",
)
conformance_root = root / "crates/conformance"
conformance_tests = conformance_root / "tests"
actual_conformance_sources = tuple(
    sorted(
        path.relative_to(conformance_tests).with_suffix("").as_posix()
        for path in conformance_tests.rglob("*.rs")
        if path != conformance_tests / "integration.rs"
    )
)
if actual_conformance_sources != conformance_modules:
    fail("conformance test source inventory does not match the consolidated module suite")

resolved_conformance_sources: dict[Path, str] = {}
for module in conformance_modules:
    source_path = conformance_tests / f"{module}.rs"
    if source_path.is_symlink():
        fail(f"{source_path.relative_to(root)} may not be a symlink")
    try:
        resolved_source = source_path.resolve(strict=True)
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read {source_path.relative_to(root)}: {error}")
    if not inside(resolved_source, conformance_tests.resolve()):
        fail(f"{source_path.relative_to(root)} resolves outside the conformance test directory")
    previous = resolved_conformance_sources.get(resolved_source)
    if previous is not None:
        fail(f"conformance test sources {previous} and {module} resolve to the same file")
    resolved_conformance_sources[resolved_source] = module
    _, code_only = rust_views(source, source_path)
    if re.search(r"#!\s*\[\s*(?:cfg|cfg_attr)\b", code_only):
        fail(f"{source_path.relative_to(root)} may not disable its registered module with a file-level cfg")

conformance_manifest_path = conformance_root / "Cargo.toml"
try:
    conformance_manifest = tomllib.loads(conformance_manifest_path.read_text())
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse crates/conformance/Cargo.toml: {error}")
conformance_package = conformance_manifest.get("package")
if not isinstance(conformance_package, dict) or conformance_package.get("autotests") is not False:
    fail("crates/conformance must set package.autotests = false")
conformance_targets = conformance_manifest.get("test")
if (
    not isinstance(conformance_targets, list)
    or len(conformance_targets) != 1
    or not isinstance(conformance_targets[0], dict)
):
    fail("crates/conformance must declare exactly one explicit [[test]] target")
conformance_target = conformance_targets[0]
if conformance_target.get("name") != "integration" or conformance_target.get("path") != "tests/integration.rs":
    fail("crates/conformance explicit test target must be integration at tests/integration.rs")
conformance_required_features = conformance_target.get("required-features", [])
if (
    conformance_target.get("test", True) is not True
    or conformance_target.get("harness", True) is not True
    or not isinstance(conformance_required_features, list)
    or conformance_required_features
):
    fail("crates/conformance integration target must use the active harness without required features")

conformance_harness_path = conformance_tests / "integration.rs"
conformance_harness = license_header + """
//! Consolidated integration-test entry point for `rustfs-gateway-conformance`.
//!
//! Responsible for: registering every conformance integration-test source in one Cargo target.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the conformance integration-test modules. Downstream: Cargo's test harness.

""" + "\n".join(f'#[path = "{module}.rs"]\nmod {module};' for module in conformance_modules) + "\n"
try:
    actual_conformance_harness = conformance_harness_path.read_text()
except OSError as error:
    fail(f"cannot read crates/conformance/tests/integration.rs: {error}")
if actual_conformance_harness != conformance_harness:
    fail("conformance integration harness must register each frozen source exactly once")


def conformance_target_path(kind: str, target: dict[str, object]) -> Path:
    target_path = target.get("path")
    if target_path is not None:
        if not isinstance(target_path, str) or not target_path:
            fail(f"crates/conformance/Cargo.toml has an unresolvable {kind} target path")
        try:
            return (conformance_root / target_path).resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve crates/conformance {kind} target path: {error}")

    if kind == "lib":
        candidates = [conformance_root / "src/lib.rs"]
    else:
        name = target.get("name")
        if not isinstance(name, str) or not name:
            fail(f"crates/conformance/Cargo.toml has an unnamed {kind} target without a path")
        if kind == "bin":
            candidates = [
                conformance_root / "src/bin" / f"{name}.rs",
                conformance_root / "src/bin" / name / "main.rs",
            ]
            package_name = conformance_package.get("name")
            if not isinstance(package_name, str):
                fail("crates/conformance package name is not a string")
            if name == package_name:
                candidates.insert(0, conformance_root / "src/main.rs")
        else:
            directories = {"example": "examples", "bench": "benches", "test": "tests"}
            directory = directories.get(kind)
            if directory is None:
                fail(f"crates/conformance has an unsupported explicit target kind: {kind}")
            candidates = [
                conformance_root / directory / f"{name}.rs",
                conformance_root / directory / name / "main.rs",
            ]
    existing = [candidate for candidate in candidates if candidate.exists()]
    if len(existing) != 1:
        fail(f"crates/conformance {kind} target default path is missing or ambiguous")
    try:
        return existing[0].resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve crates/conformance {kind} target default path: {error}")


for kind, default_test in (("lib", True), ("bin", True), ("example", False), ("bench", False)):
    raw_targets = conformance_manifest.get(kind, [] if kind != "lib" else None)
    if kind == "lib":
        targets = [] if raw_targets is None else [raw_targets]
    else:
        targets = raw_targets
    if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
        fail(f"crates/conformance/Cargo.toml has an invalid {kind} target inventory")
    for target in targets:
        enabled = target.get("test", default_test)
        if not isinstance(enabled, bool):
            fail(f"crates/conformance/Cargo.toml has an unresolvable {kind} target")
        resolved_target = conformance_target_path(kind, target)
        if resolved_target in resolved_conformance_sources:
            fail(f"crates/conformance/Cargo.toml reuses a registered test source as a {kind} target")
        if resolved_target == conformance_harness_path.resolve():
            fail(f"crates/conformance/Cargo.toml reuses the integration harness as a {kind} target")

protected_conformance_entries = set(resolved_conformance_sources) | {conformance_harness_path.resolve()}
registered_conformance_entries = {
    conformance_tests / f"{module}.rs" for module in conformance_modules
} | {conformance_harness_path}

for source_path in conformance_root.rglob("*.rs"):
    try:
        resolved = source_path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve conformance Rust entry {source_path.relative_to(root)}: {error}")
    if resolved in protected_conformance_entries and source_path not in registered_conformance_entries:
        fail(f"{source_path.relative_to(root)} aliases a registered conformance test entry")
    if source_path == conformance_harness_path:
        continue
    try:
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read {source_path.relative_to(root)}: {error}")
    comments_removed, code_only = rust_views(source, source_path)
    for attribute in re.finditer(r"#\s*!?\s*\[", code_only):
        opening = code_only.find("[", attribute.start(), attribute.end())
        end = balanced_end(code_only, opening, source_path)
        attribute_code = code_only[opening + 1 : end - 1]
        for path_meta in re.finditer(r"\bpath\s*=", attribute_code):
            value_start = opening + 1 + path_meta.end()
            literal = re.match(r'\s*"([^"\n]+)"', comments_removed[value_start:])
            if literal is None:
                fail(f"{source_path.relative_to(root)} has a path attribute the guard cannot resolve")
            literal_path = literal.group(1)
            if "\\" in literal_path:
                fail(f"{source_path.relative_to(root)} has an escaped path attribute the guard cannot resolve")
            if (source_path.parent / literal_path).resolve() in protected_conformance_entries:
                fail(f"{source_path.relative_to(root)} reuses a registered conformance test entry through #[path]")
    for include in re.finditer(r"\binclude\s*!\s*([({\[])", code_only):
        opening = include.end() - 1
        end = balanced_end(code_only, opening, source_path)
        arguments = comments_removed[opening + 1 : end - 1]
        literal = re.fullmatch(r'\s*"([^"\n]+)"\s*', arguments)
        if literal is None:
            fail(f"{source_path.relative_to(root)} has a non-literal include the guard cannot resolve")
        literal_path = literal.group(1)
        if "\\" in literal_path:
            fail(f"{source_path.relative_to(root)} has an escaped include the guard cannot resolve")
        if (source_path.parent / literal_path).resolve() in protected_conformance_entries:
            fail(f"{source_path.relative_to(root)} includes a registered conformance test entry")

core_compile_harness_path = core_tests / "compile_fail.rs"
core_compile_source = core_compile_harness_path.read_text()
core_compile_comments_removed, _ = rust_views(core_compile_source, core_compile_harness_path)
core_compile_code = "".join(core_compile_comments_removed.split())
core_compile_dir = core_tests / "compile_fail"
core_error_sources = {path.stem for path in core_compile_dir.glob("error_resolution_*.rs")}
core_error_goldens = {path.stem for path in core_compile_dir.glob("error_resolution_*.stderr")}
if core_error_sources != core_error_goldens:
    fail("core error-resolution trybuild sources and goldens must remain paired")
core_arity_sources = {path.stem for path in core_compile_dir.glob("c_err_1010_*.rs")}
core_arity_goldens = {path.stem for path in core_compile_dir.glob("c_err_1010_*.stderr")}
if core_arity_sources != core_arity_goldens:
    fail("core error-code arity trybuild sources and goldens must remain paired")
core_upload_sources = {path.stem for path in core_compile_dir.glob("upload_*.rs")}
core_upload_goldens = {path.stem for path in core_compile_dir.glob("upload_*.stderr")}
if core_upload_sources != core_upload_goldens:
    fail("core upload-capability trybuild sources and goldens must remain paired")
core_registry_sources = {path.stem for path in core_compile_dir.glob("registry_*.rs")}
core_registry_goldens = {path.stem for path in core_compile_dir.glob("registry_*.stderr")}
if core_registry_sources != core_registry_goldens:
    fail("core registry trybuild sources and goldens must remain paired")
core_calls = [
    'cases.compile_fail("tests/compile_fail/authz_*.rs");',
    'cases.pass("tests/compile_pass/authz_authorized.rs");',
]
if core_arity_sources:
    core_calls.append('cases.compile_fail("tests/compile_fail/c_err_1010_*.rs");')
core_calls.append('cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");')
if any(core_compile_dir.glob("c_sig_0123_*.rs")):
    core_calls.append('cases.compile_fail("tests/compile_fail/c_sig_0123_*.rs");')
if any(core_compile_dir.glob("committed_*.rs")):
    core_calls.append('cases.compile_fail("tests/compile_fail/committed_*.rs");')
if core_error_sources:
    core_calls.append('cases.compile_fail("tests/compile_fail/error_resolution_*.rs");')
if core_registry_sources:
    core_calls.append('cases.compile_fail("tests/compile_fail/registry_*.rs");')
if core_upload_sources:
    core_calls.append('cases.compile_fail("tests/compile_fail/upload_*.rs");')
expected_core_compile_code = "".join(
    (
        "#[test]fn compile_time_contracts_are_not_openable(){"
        "let cases=trybuild::TestCases::new();"
        + "".join(core_calls)
        + "}"
    ).split()
)
if core_compile_code != expected_core_compile_code:
    fail("core compile-fail contracts must use one TestCases batch and the ordered fixture patterns")

golden_path = core_tests / "golden.rs"
golden_source = golden_path.read_text()
golden_command = (
    "//! UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-core --test integration "
    "golden::the_rendered_route_table_matches_the_golden -- --exact"
)
if golden_source.count(golden_command) != 1 or "--test golden" in golden_source:
    fail("core route-table golden must document the exact consolidated-target restore command")

monomorphic_guard_path = root / "scripts/check_monomorphic_dispatch.sh"
monomorphic_guard = monomorphic_guard_path.read_text()
monomorphic_command = "cargo rustc -q -p rustfs-gateway --test integration --release --"
if monomorphic_guard.count(monomorphic_command) != 1 or "--test monomorphic" in monomorphic_guard:
    fail("monomorphic LLVM guard must compile the consolidated gateway integration target")
monomorphic_symbols = (
    "integration7support4Ping",
    "rustfs_gateway_core::static_dispatch::decode::<integration::support::Ping>",
    "<integration::support::Backend as rustfs_gateway_core::handler::Handler<integration::support::Ping>>::call",
    "<integration::support::Ping as rustfs_gateway_core::codec::OperationCodec>::decode",
)
if any(symbol not in monomorphic_guard for symbol in monomorphic_symbols) or "monomorphic::support" in monomorphic_guard:
    fail("monomorphic LLVM guard must match the consolidated target's root support module")

tsan_runner_path = root / "scripts/run_gateway_tsan.sh"
tsan_runner = tsan_runner_path.read_text()
tsan_target = "-p rustfs-gateway --test integration"
tsan_filter = "service_concurrency::one_hundred_clones_answer_concurrently -- --exact --test-threads=1"
if tsan_runner.count(tsan_target) != 1 or tsan_runner.count(tsan_filter) != 1 or "--test service_concurrency" in tsan_runner:
    fail("gateway TSAN runner must use the consolidated target and exact concurrency test filter")

gateway_harness_path = root / "crates/gateway/tests/compile_fail.rs"
try:
    actual_gateway_harness = gateway_harness_path.read_text()
except OSError as error:
    fail(f"cannot read crates/gateway/tests/compile_fail.rs: {error}")
gateway_compile_dir = root / "crates/gateway/tests/compile_fail"
error_sources = {path.stem for path in gateway_compile_dir.glob("error_resolution_*.rs")}
error_goldens = {path.stem for path in gateway_compile_dir.glob("error_resolution_*.stderr")}
if error_sources != error_goldens:
    fail("gateway error-resolution trybuild sources and goldens must remain paired")
middleware_sources = {path.stem for path in gateway_compile_dir.glob("c_mw_*.rs")}
middleware_goldens = {path.stem for path in gateway_compile_dir.glob("c_mw_*.stderr")}
if not middleware_sources or middleware_sources != middleware_goldens:
    fail("gateway middleware trybuild sources and goldens must exist and remain paired")
gateway_calls = ['cases.compile_fail("tests/compile_fail/azc_*.rs");']
gateway_calls.append('cases.compile_fail("tests/compile_fail/c_ck_0020_*.rs");')
gateway_calls.append('cases.compile_fail("tests/compile_fail/c_gov_*.rs");')
gateway_calls.append('cases.compile_fail("tests/compile_fail/c_mw_*.rs");')
if error_sources:
    gateway_calls.append('cases.compile_fail("tests/compile_fail/error_resolution_*.rs");')
gateway_calls.append('cases.compile_fail("tests/compile_fail/host_resolver_*.rs");')
gateway_calls.append('cases.compile_fail("tests/trybuild/credential/*.rs");')
expected_gateway_code = "".join(
    (
        "#[test]fn gateway_compile_fail_contracts_are_enforced(){"
        "let cases=trybuild::TestCases::new();"
        + "".join(gateway_calls)
        + "}"
    ).split()
)
gateway_comments_removed, _ = rust_views(actual_gateway_harness, gateway_harness_path)
if "".join(gateway_comments_removed.split()) != expected_gateway_code:
    fail("gateway compile-fail harness must use one exact TestCases batch and ordered fixture patterns")
for legacy in (
    root / "crates/gateway/tests/authz_compile.rs",
    root / "crates/gateway/tests/trybuild_credential.rs",
):
    if legacy.exists():
        fail(f"legacy gateway trybuild harness remains: {legacy.relative_to(root)}")

gateway_root = root / "crates/gateway"
gateway_manifest_path = gateway_root / "Cargo.toml"
try:
    gateway_manifest = tomllib.loads(gateway_manifest_path.read_text())
except (OSError, tomllib.TOMLDecodeError) as error:
    fail(f"cannot parse crates/gateway/Cargo.toml: {error}")
gateway_package = gateway_manifest.get("package")
if not isinstance(gateway_package, dict):
    fail("crates/gateway/Cargo.toml has no package table")
gateway_autotests = gateway_package.get("autotests", True)
if gateway_autotests is not False:
    fail("crates/gateway must set package.autotests = false")

explicit_tests = gateway_manifest.get("test", [])
if not isinstance(explicit_tests, list) or len(explicit_tests) != 1 or not isinstance(explicit_tests[0], dict):
    fail("crates/gateway must declare exactly one explicit [[test]] target")
gateway_target = explicit_tests[0]
if gateway_target.get("name") != "integration" or gateway_target.get("path") != "tests/integration.rs":
    fail("crates/gateway explicit test target must be integration at tests/integration.rs")
gateway_required_features = gateway_target.get("required-features", [])
if (
    gateway_target.get("test", True) is not True
    or gateway_target.get("harness", True) is not True
    or not isinstance(gateway_required_features, list)
    or gateway_required_features
):
    fail("crates/gateway integration target must use the active harness without required features")

gateway_modules = (
    "action_rules_runtime",
    "anonymous_chunked_upload",
    "anonymous_delegation_runtime",
    "assembly",
    "assembly_order",
    "assembly_snapshot",
    "authz_consumption",
    "authz_contract",
    "authz_implementations",
    "backend_reachability",
    "body_literals",
    "body_refusal_sentences",
    "bodyless_payload_digest",
    "bucket_config_reachability",
    "checksum_omissions",
    "chunked_allocations",
    "classification",
    "committed_head_runtime",
    "committed_progress",
    "compat_aliases",
    "compile_fail",
    "connection_teardown",
    "copy_source_reachability",
    "cors_runtime",
    "credential_runtime",
    "custom_signature_verifier",
    "dialect_claims_runtime",
    "dialect_entry",
    "empty_upload_without_length",
    "error_context_filters",
    "extra_response_headers",
    "facade_probe",
    "file_responses",
    "file_transfer",
    "governor_runtime",
    "governor_streaming",
    "handler_panic",
    "host_deadlines",
    "host_resolve_replay",
    "ingest_assembly",
    "lifecycle_reachability",
    "lock_encryption_reachability",
    "macro_scenarios",
    "middleware",
    "monomorphic",
    "naming_policy",
    "object_attributes_etag",
    "object_lock_intent",
    "observer_panic",
    "operation_registry_hot_update",
    "operation_registry_wire",
    "patch_layer_landings",
    "payload_transport",
    "perf_evidence",
    "pipeline",
    "policy_reachability",
    "post_object_legacy_form",
    "post_object_runtime",
    "post_object_streaming",
    "precondition_contract",
    "precondition_reachability",
    "presigned_put",
    "raw_path_fallback",
    "refusal_order_guards",
    "reject_rendering",
    "replica_put",
    "replication_token",
    "request_allocations",
    "request_context_runtime",
    "response_invariants",
    "response_stream_termination",
    "rustfs_addressing",
    "rustfs_key_floor",
    "rustfs_selection",
    "rustfs_vhost",
    "select_frame_records",
    "select_restore_intent",
    "select_restore_reachability",
    "self_held_http1",
    "service_clone_allocations",
    "service_concurrency",
    "service_config",
    "sigv2_runtime",
    "sse_runtime",
    "steady_state_allocations",
    "streaming_request",
    "streaming_without_length",
    "tagging_reachability",
    "throughput_request",
    "unknown_checksum_algorithms",
    "unread_body_refusal",
    "upload_object_ceiling",
    "verified_scope_runtime",
    "vhost_resolution",
)
gateway_tests = gateway_root / "tests"
actual_gateway_sources = tuple(
    sorted(path.stem for path in gateway_tests.glob("*.rs") if path.name != "integration.rs")
)
if actual_gateway_sources != gateway_modules:
    fail("gateway test source inventory does not match the consolidated module suite")

resolved_gateway_sources: dict[Path, str] = {}
for module in gateway_modules:
    source_path = gateway_tests / f"{module}.rs"
    if source_path.is_symlink():
        fail(f"{source_path.relative_to(root)} may not be a symlink")
    try:
        resolved_source = source_path.resolve(strict=True)
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read {source_path.relative_to(root)}: {error}")
    if not inside(resolved_source, gateway_tests.resolve()):
        fail(f"{source_path.relative_to(root)} resolves outside the gateway test directory")
    previous = resolved_gateway_sources.get(resolved_source)
    if previous is not None:
        fail(f"gateway test sources {previous} and {module} resolve to the same file")
    resolved_gateway_sources[resolved_source] = module
    _, code_only = rust_views(source, source_path)
    if re.search(r"#!\s*\[\s*(?:cfg|cfg_attr)\b", code_only):
        fail(f"{source_path.relative_to(root)} may not disable its registered module with a file-level cfg")
    if re.search(r"\bmod\s+support\s*;", code_only):
        fail(f"{source_path.relative_to(root)} must use the consolidated crate-root support module")

gateway_integration_path = gateway_tests / "integration.rs"
gateway_integration = license_header + """
//! Consolidated integration-test entry point for `rustfs-gateway`.
//!
//! Responsible for: registering every gateway integration-test source in one Cargo target.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the gateway integration-test modules. Downstream: Cargo's test harness.

mod support;

""" + "\n".join(f'#[path = "{module}.rs"]\nmod {module};' for module in gateway_modules) + "\n"
try:
    actual_gateway_integration = gateway_integration_path.read_text()
except OSError as error:
    fail(f"cannot read crates/gateway/tests/integration.rs: {error}")
if actual_gateway_integration != gateway_integration:
    fail("gateway integration harness must register each frozen source exactly once")

for kind, default_test in (("lib", True), ("bin", True), ("example", False), ("bench", False)):
    raw_targets = gateway_manifest.get(kind, [] if kind != "lib" else None)
    if kind == "lib":
        targets = [] if raw_targets is None else [raw_targets]
    else:
        targets = raw_targets
    if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
        fail(f"crates/gateway/Cargo.toml has an invalid {kind} target inventory")
    for target in targets:
        enabled = target.get("test", default_test)
        target_path = target.get("path")
        if not isinstance(enabled, bool) or (target_path is not None and not isinstance(target_path, str)):
            fail(f"crates/gateway/Cargo.toml has an unresolvable {kind} target")
        if target_path is not None:
            resolved_target = (gateway_root / target_path).resolve()
            if not inside(resolved_target, gateway_root.resolve()):
                fail(f"crates/gateway/Cargo.toml {kind} targets may not escape the gateway crate")
            if resolved_target == gateway_harness_path.resolve():
                fail(f"crates/gateway/Cargo.toml reuses the unified trybuild harness as a {kind} target")
            if resolved_target == gateway_integration_path.resolve():
                fail(f"crates/gateway/Cargo.toml reuses the consolidated integration harness as a {kind} target")

for source_path in gateway_root.rglob("*.rs"):
    try:
        resolved = source_path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve gateway Rust entry {source_path.relative_to(root)}: {error}")
    if resolved == gateway_harness_path.resolve():
        if source_path != gateway_harness_path:
            fail(f"{source_path.relative_to(root)} aliases the unified gateway trybuild harness")
        continue
    if resolved == gateway_integration_path.resolve() and source_path != gateway_integration_path:
        fail(f"{source_path.relative_to(root)} aliases the consolidated gateway integration harness")
    try:
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read {source_path.relative_to(root)}: {error}")
    comments_removed, code_only = rust_views(source, source_path)
    if re.search(r"\btrybuild\b", code_only):
        fail(f"{source_path.relative_to(root)} creates an additional gateway trybuild entry")
    for attribute in re.finditer(r"#\s*!?\s*\[", code_only):
        opening = code_only.find("[", attribute.start(), attribute.end())
        end = balanced_end(code_only, opening, source_path)
        attribute_code = code_only[opening + 1 : end - 1]
        for path_meta in re.finditer(r"\bpath\s*=", attribute_code):
            value_start = opening + 1 + path_meta.end()
            literal = re.match(r'\s*"([^"\n]+)"', comments_removed[value_start:])
            if literal is None:
                fail(f"{source_path.relative_to(root)} has a path attribute the guard cannot resolve")
            target = (source_path.parent / literal.group(1)).resolve()
            # One reviewed exception, as a pair and not a directory: the stable replay runs the
            # same property file as the `host_resolve` fuzz target, so a finding and its replay
            # can never assert different things. Any other file, or any other target, escapes.
            if (
                source_path == gateway_root / "tests/host_resolve_replay.rs"
                and target == (root / "fuzz/support/host_resolve.rs").resolve()
            ):
                continue
            if not inside(target, gateway_root.resolve()):
                fail(f"{source_path.relative_to(root)} has a path attribute escaping the gateway crate")
            if target == gateway_harness_path.resolve() and source_path != gateway_integration_path:
                fail(f"{source_path.relative_to(root)} reuses the unified gateway trybuild harness through #[path]")
            if target == gateway_integration_path.resolve():
                fail(f"{source_path.relative_to(root)} reuses the consolidated gateway integration harness through #[path]")

    for include in re.finditer(r"\binclude\s*!\s*([({\[])", code_only):
        opening = include.end() - 1
        end = balanced_end(code_only, opening, source_path)
        arguments = comments_removed[opening + 1 : end - 1]
        literal = re.fullmatch(r'\s*"([^"\n]+)"\s*', arguments)
        if literal is None:
            fail(f"{source_path.relative_to(root)} has a non-literal include the guard cannot resolve")
        target = (source_path.parent / literal.group(1)).resolve()
        if not inside(target, gateway_root.resolve()):
            fail(f"{source_path.relative_to(root)} includes Rust code from outside the gateway crate")
        if target == gateway_harness_path.resolve():
            fail(f"{source_path.relative_to(root)} includes the unified gateway trybuild harness")
        if target == gateway_integration_path.resolve():
            fail(f"{source_path.relative_to(root)} includes the consolidated gateway integration harness")

# A list, not a dict keyed by directory: two sets share crates/gateway/tests/compile_fail, and a
# dict silently kept only the last one, so the azc_* pairs were never checked.
fixture_sets = [
    (root / "crates/gateway/tests/compile_fail", "azc_*", {
        "azc_0014_missing_input",
        "azc_0015_forge_authorized",
        "azc_0016_denial_code",
        "azc_0020_service_config_default",
        "azc_0021_allow_all",
        "azc_0025_request_extensions",
    }),
    (root / "crates/gateway/tests/compile_fail", "c_gov_*", {
        "c_gov_0016_request_is_framework_built",
        "c_gov_0021_unacknowledged_clock",
        "c_gov_0025_clocks_do_not_convert",
    }),
    (root / "crates/gateway/tests/compile_fail", "host_resolver_*", {
        "host_resolver_async",
    }),
    (root / "crates/gateway/tests/trybuild/credential", "*", {
        "constructs_anonymous",
        "prints_and_compares_token",
        "provider_returns_secret",
        "provider_returns_verdict",
    }),
]
for directory, pattern, expected_stems in fixture_sets:
    try:
        sources = {path.stem for path in directory.glob(f"{pattern}.rs")}
        goldens = {path.stem for path in directory.glob(f"{pattern}.stderr")}
    except OSError as error:
        fail(f"cannot inspect {directory.relative_to(root)}: {error}")
    if sources != expected_stems or goldens != expected_stems:
        fail(f"{directory.relative_to(root)} must retain exact source/golden pairs")

print("test-target consolidation guard passed")
PYEOF
