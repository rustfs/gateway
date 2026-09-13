#!/usr/bin/env bash
set -euo pipefail

# Locks the explicit handler-deadline class of every standard operation. Third-party
# operations migrate separately before registration makes their class mandatory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_handler_deadline_class: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
authority = root / "crates/core/src/registry/mod.rs"
registration = root / "crates/core/src/registry/reject.rs"
config = root / "crates/gateway/src/config.rs"
facade = root / "crates/gateway/src/lib.rs"
dispatch = root / "crates/gateway/src/dispatch.rs"
runtime = root / "crates/gateway/src/request_deadline.rs"
request_config = root / "crates/gateway/src/request_config.rs"
monomorphic = root / "crates/gateway/src/monomorphic.rs"
service = root / "crates/gateway/src/service.rs"
observer = root / "crates/gateway/src/ext/observer.rs"
connection_tests = root / "crates/gateway/tests/connection_teardown.rs"
ops_dir = root / "crates/core/src/ops"


def fail(message: str) -> None:
    print(f"check_handler_deadline_class: {message}", file=sys.stderr)
    raise SystemExit(1)


if not authority.is_file() or authority.is_symlink():
    fail("deadline-class authority is missing or not a regular file")
if not registration.is_file() or registration.is_symlink():
    fail("registration deadline check is missing or not a regular file")
if not config.is_file() or config.is_symlink():
    fail("handler deadline configuration is missing or not a regular file")
if not facade.is_file() or facade.is_symlink():
    fail("handler deadline facade is missing or not a regular file")
if not dispatch.is_file() or dispatch.is_symlink():
    fail("handler deadline dispatch is missing or not a regular file")
if not runtime.is_file() or runtime.is_symlink():
    fail("handler deadline runtime is missing or not a regular file")
for path, label in (
    (request_config, "handler deadline report slot"),
    (monomorphic, "monomorphic handler deadline dispatch"),
    (service, "handler deadline response policy"),
    (observer, "handler deadline observer contract"),
    (connection_tests, "handler deadline connection evidence"),
):
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or not a regular file")
if not ops_dir.is_dir() or ops_dir.is_symlink():
    fail("standard operation directory is missing or not a directory")

try:
    source = authority.read_text(encoding="utf-8")
    registration_source = registration.read_text(encoding="utf-8")
    config_source = config.read_text(encoding="utf-8")
    facade_source = facade.read_text(encoding="utf-8")
    dispatch_source = dispatch.read_text(encoding="utf-8")
    runtime_source = runtime.read_text(encoding="utf-8")
    request_config_source = request_config.read_text(encoding="utf-8")
    monomorphic_source = monomorphic.read_text(encoding="utf-8")
    service_source = service.read_text(encoding="utf-8")
    observer_source = observer.read_text(encoding="utf-8")
    connection_test_source = connection_tests.read_text(encoding="utf-8")
except (OSError, UnicodeError) as error:
    fail(f"cannot read deadline-class source: {error}")


def function_body(text: str, function_signature: str, label: str) -> str:
    if text.count(function_signature) != 1:
        fail(f"{label} function is missing or duplicated")
    start = text.find("{", text.find(function_signature) + len(function_signature))
    if start < 0:
        fail(f"{label} function has no body")
    depth = 1
    index = start + 1
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    if depth:
        fail(f"{label} function has unbalanced braces")
    return text[start + 1 : index - 1]


standard_default = "pub const DEFAULT_STANDARD_HANDLER_DEADLINE: Duration = Duration::from_secs(30);"
extended_default = "pub const DEFAULT_EXTENDED_HANDLER_DEADLINE: Duration = Duration::from_secs(15 * 60);"
cleanup_default = "const DEFAULT_HANDLER_CLEANUP_GRACE: Duration = Duration::from_secs(1);"
if config_source.count(standard_default) != 1 or config_source.count(extended_default) != 1:
    fail("handler deadline defaults are not Standard=30s and Extended=15m")
if config_source.count(cleanup_default) != 1:
    fail("handler cleanup grace default is not one second")

constructor_body = function_body(
    config_source,
    "pub const fn new(standard: Duration, extended: Duration) -> Result<Self, HandlerDeadlineConfigError>",
    "handler deadline configuration constructor",
)
zero_standard = """        if standard.is_zero() {
            return Err(HandlerDeadlineConfigError::ZeroStandard);
        }
"""
zero_extended = """        if extended.is_zero() {
            return Err(HandlerDeadlineConfigError::ZeroExtended);
        }
"""
if constructor_body.count(zero_standard) != 1 or constructor_body.count(zero_extended) != 1:
    fail("handler deadline configuration does not reject both zero durations")

cleanup_body = function_body(
    config_source,
    "pub const fn try_with_cleanup_grace(mut self, cleanup_grace: Duration) -> Option<Self>",
    "handler cleanup grace configuration",
)
zero_cleanup = """        if cleanup_grace.is_zero() {
            return None;
        }
"""
if (
    cleanup_body.count(zero_cleanup) != 1
    or cleanup_body.count("self.cleanup_grace = cleanup_grace;") != 1
    or cleanup_body.count("Some(self)") != 1
):
    fail("handler cleanup grace is not validated and stored")

duration_body = function_body(
    config_source,
    "pub const fn duration_for(self, class: HandlerDeadlineClass) -> Duration",
    "handler deadline class mapping",
)
if duration_body.count("HandlerDeadlineClass::Standard => self.standard") != 1:
    fail("Standard handler deadline is not mapped to its configured duration")
if duration_body.count("HandlerDeadlineClass::Extended => self.extended") != 1:
    fail("Extended handler deadline is not mapped to its configured duration")

invoke_body = function_body(
    dispatch_source,
    "pub(crate) fn layered<O, B>(backend: Arc<B>, layers: Vec<Arc<dyn OpLayer<O>>>) -> Self",
    "dynamic handler dispatch",
)
for required in (
    "O::spec()\n                .deadline_class()",
    "request_config.config().handler_deadline(deadline_class)",
    "request_config.config().handler_cleanup_grace()",
    "let request_cancellation = request_config.request_cancellation();",
    "handler_with_request_cancellation(",
):
    if invoke_body.count(required) != 1:
        fail("dynamic dispatch does not consume one request snapshot's handler deadline configuration")
if invoke_body.count("handler deadline exceeded after cleanup completed") != 1:
    fail("dynamic dispatch can commit a handler result completed after its deadline")
if invoke_body.count("handler deadline exceeded before cleanup completed") != 1:
    fail("dynamic dispatch does not distinguish an exhausted cleanup grace")

runtime_body = function_body(runtime_source, "pub(crate) async fn handler_with_request_cancellation<T>", "handler deadline race")
deadline_poll = "if deadline.as_mut().poll(context).is_ready()"
handler_output_poll = "if let Poll::Ready(output) = handler.as_mut().poll(context)"
request_cancel = "return Poll::Ready(Err(HandlerCancellation::RequestAborted));"
cancel = "cancellation.cancel(reason);"
grace_poll = "if grace.as_mut().poll(context).is_ready()"
cleanup_poll = "if handler.as_mut().poll(context).is_ready()"
for required in (deadline_poll, handler_output_poll, request_cancel, cancel, grace_poll, cleanup_poll):
    if runtime_body.count(required) != 1:
        fail("handler deadline race is missing a required poll or cancellation signal")
if runtime_body.find(deadline_poll) > runtime_body.find(handler_output_poll):
    fail("handler completion wins a simultaneous deadline race")
if runtime_body.find(request_cancel) > runtime_body.find(handler_output_poll):
    fail("handler completion wins after the transport has already cancelled the request")
if runtime_body.find(cancel) > runtime_body.find(grace_poll):
    fail("handler cleanup grace starts before the deadline cancellation signal")
if runtime_body.find(grace_poll) > runtime_body.find(cleanup_poll):
    fail("handler cleanup completion wins an exhausted grace race")
after_cancel = runtime_body.partition(cancel)[2]
if handler_output_poll in after_cancel or "HandlerCancellationOutcome::Completed(handler.await)" in after_cancel:
    fail("a handler result completed after its deadline can be committed")
if runtime_body.count("HandlerCancellationOutcome::RequestAborted { cleanup_completed }") != 1:
    fail("request cancellation does not report bounded cleanup completion")
if runtime_body.count("HandlerCancellationOutcome::Expired { cleanup_completed }") != 1:
    fail("handler deadline race does not report bounded cleanup completion")

for required in (
    "request_cancellation: Option<tokio::sync::watch::Receiver<bool>>,",
    "request_cancellation: self.request_cancellation,",
    "pub(crate) fn request_cancellation(&self) -> Option<tokio::sync::watch::Receiver<bool>>",
):
    if request_config_source.count(required) != 1:
        fail("request cancellation is not carried through the typed request snapshot")
request_cancellation_extract = (
    "request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned()"
)
if service_source.count(request_cancellation_extract) != 1:
    fail("the service does not extract the server request-cancellation signal")
for required in (
    "HandlerCancellationOutcome::RequestAborted { cleanup_completed }",
    "request ended after handler cleanup completed",
    "request ended before handler cleanup completed",
):
    if invoke_body.count(required) != 1:
        fail("dynamic dispatch does not classify bounded request-abort cleanup")

if request_config_source.count("self.handler_deadline_report.record(cleanup_completed);") != 1:
    fail("request config does not record the handler cleanup acknowledgement")
for required in (
    "0 => None,",
    "1 => Some(HandlerDeadlineReport::Acknowledged),",
    "_ => Some(HandlerDeadlineReport::Unacknowledged),",
):
    if request_config_source.count(required) != 1:
        fail("handler deadline report slot does not fail closed on unacknowledged cleanup")
for source_text, label in (
    (dispatch_source, "dynamic dispatch"),
    (monomorphic_source, "monomorphic dispatch"),
):
    if source_text.count("record_handler_deadline(true);") != 1:
        fail(f"{label} does not record acknowledged handler cleanup")
    if source_text.count("record_handler_deadline(false);") != 1:
        fail(f"{label} does not record an exhausted cleanup grace")
close_policy = """        let handler_deadline = handler_deadline_report.outcome();
        if handler_deadline == Some(HandlerDeadlineReport::Unacknowledged) {
            response.extensions_mut().insert(ConnectionIntent::Close);
        }
"""
if service_source.count(close_policy) != 1:
    fail("an unacknowledged handler cancellation does not close the response path")
if request_config_source.count("pub enum HandlerDeadlineReport {") != 1:
    fail("handler deadline report is not a public typed contract")
if facade_source.count("pub use crate::request_config::HandlerDeadlineReport;") != 1:
    fail("facade does not export the handler deadline report")
if observer_source.count("pub handler_deadline: Option<HandlerDeadlineReport>,") != 1:
    fail("request observer does not expose the typed handler deadline report")
event_body = service_source.partition("runtime.observer.on_response(&RequestEvent {")[2].partition("});")[0]
if not event_body or event_body.count("handler_deadline,") != 1:
    fail("response observation does not carry the request handler deadline report")
for test_name in (
    "an_unacknowledged_handler_deadline_closes_the_observed_socket",
    "an_acknowledged_handler_deadline_keeps_the_observed_socket_reusable",
    "a_monomorphic_unacknowledged_handler_deadline_carries_close_intent",
    "a_completed_handler_reports_no_deadline",
    "c_wire_0060_c_ing_0060_c_lim_0060_a_client_reset_cancels_the_handler_rolls_back_and_releases_its_permit",
):
    if connection_test_source.count(f"async fn {test_name}()") != 1:
        fail("handler deadline connection evidence is missing or duplicated")
reset_body = function_body(
    connection_test_source,
    "async fn c_wire_0060_c_ing_0060_c_lim_0060_a_client_reset_cancels_the_handler_rolls_back_and_releases_its_permit()",
    "c-lim-0060 reset cancellation evidence",
)
for required in (
    "max_global_inflight_requests: 1,",
    "socket.set_linger(Some(Duration::ZERO))",
    "backend.rollback_completed.load(Ordering::Acquire)",
    'String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 ")',
    "[HandlerCancellation::RequestAborted]",
):
    if reset_body.count(required) != 1:
        fail("c-lim-0060 does not prove reset cancellation, rollback, and permit reuse")
if connection_test_source.count("seen.push(event.handler_deadline);") != 1:
    fail("handler deadline observer evidence does not record the live event")
for report, expected in (
    ("Some(HandlerDeadlineReport::Acknowledged)", 2),
    ("Some(HandlerDeadlineReport::Unacknowledged)", 2),
    ("recorder.seen.lock().expect(\"not poisoned\").as_slice(), [None]", 1),
):
    if connection_test_source.count(report) != expected:
        fail("handler deadline observer evidence does not distinguish all report outcomes")

core_exports = facade_source.partition("pub use rustfs_gateway_core::{")[2].partition("};")[0]
config_exports = facade_source.partition("pub use crate::config::{")[2].partition("};")[0]
if not core_exports or "HandlerDeadlineClass" not in core_exports.replace("\n", " ").replace(",", " ").split():
    fail("facade does not export HandlerDeadlineClass")
for exported in (
    "HandlerDeadlineConfig",
    "HandlerDeadlineConfigError",
    "DEFAULT_STANDARD_HANDLER_DEADLINE",
    "DEFAULT_EXTENDED_HANDLER_DEADLINE",
):
    if exported not in config_exports.replace("\n", " ").replace(",", " ").split():
        fail(f"facade does not export {exported}")


check_spec_body = function_body(
    registration_source,
    "pub(crate) fn check_spec(spec: &'static OperationSpec) -> Result<(), RegistryError>",
    "shared registration check",
)
registration_check = """    if spec.deadline_class().is_none() {
        return Err(RegistryError::MissingHandlerDeadlineClass { name });
    }
"""
if check_spec_body.count(registration_check) != 1 or registration_source.count(registration_check) != 1:
    fail("shared registration does not fail closed without a handler deadline class")

signature = "fn standard_handler_deadline_class(name: &str) -> Option<HandlerDeadlineClass>"
if source.count(signature) != 1:
    fail("deadline-class authority function is missing or duplicated")
start = source.find("{", source.find(signature) + len(signature))
if start < 0:
    fail("deadline-class authority function has no body")
depth = 1
index = start + 1
while index < len(source) and depth:
    if source[index] == "{":
        depth += 1
    elif source[index] == "}":
        depth -= 1
    index += 1
if depth:
    fail("deadline-class authority function has unbalanced braces")
body = source[start + 1 : index - 1]

arm_pattern = re.compile(
    r'((?:"[A-Za-z0-9]+"\s*\|\s*)*"[A-Za-z0-9]+")\s*=>\s*'
    r'Some\(HandlerDeadlineClass::(Standard|Extended)\)'
)
declared: dict[str, str] = {}
for names, deadline_class in arm_pattern.findall(body):
    for name in re.findall(r'"([A-Za-z0-9]+)"', names):
        if name in declared:
            fail(f"standard operation {name} declares two deadline classes")
        declared[name] = deadline_class
if re.search(r'_\s*=>\s*Some\(', body):
    fail("deadline-class authority has an implicit wildcard class")
if not re.search(r'_\s*=>\s*None', body):
    fail("deadline-class authority does not fail closed for unknown operations")

operations: set[str] = set()
for path in sorted(ops_dir.glob("*.rs")):
    if path.name == "mod.rs":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read standard operation source {path.name}: {error}")
    names = re.findall(r'^\s*const NAME: &\'static str = "([A-Za-z0-9]+)";\s*$', text, re.MULTILINE)
    if len(names) != 1:
        fail(f"standard operation source {path.name} has {len(names)} exact NAME declarations")
    name = names[0]
    if name in operations:
        fail(f"standard operation name is duplicated: {name}")
    operations.add(name)

if len(operations) != 93:
    fail(f"standard operation census is {len(operations)}, expected 93")
missing = sorted(operations - declared.keys())
extra = sorted(declared.keys() - operations)
if missing or extra:
    fail(f"deadline-class authority differs from standard operations: missing={missing}, extra={extra}")
if declared.get("CompleteMultipartUpload") != "Extended":
    fail("CompleteMultipartUpload must use the Extended handler deadline")
wrong_standard = sorted(name for name in operations - {"CompleteMultipartUpload"} if declared.get(name) != "Standard")
if wrong_standard:
    fail(f"standard handler deadline drifted for: {wrong_standard}")

# gateway#242: a standard operation constructs its specification with `OperationSpec::standard`,
# which reads the success status and the unconfigured code out of the generated route table instead
# of taking them as arguments. The census is about the deadline class, which neither constructor
# carries, so both spellings enter it and the counts below are unchanged.
builder_pattern = re.compile(r"OperationSpec::(?:builder|standard)\(.*?\.build\(\)", re.DOTALL)
authority_builders = [match.group(0) for match in builder_pattern.finditer(source)]
authority_builder_names = [
    re.findall(r'OperationSpec::(?:builder|standard)\(\s*"([A-Za-z0-9:]+)"', chain) for chain in authority_builders
]
authority_explicit_classes = [
    chain.count(".handler_deadline_class(HandlerDeadlineClass::Standard)") for chain in authority_builders
]
if authority_builder_names != [
    ["vendor:Probe"],
    ["GetObject"],
    ["CompleteMultipartUpload"],
    ["vendor:Probe"],
    ["vendor:Probe"],
] or authority_explicit_classes != [0, 0, 0, 0, 1]:
    fail("deadline-class authority test-builder census drifted")

central_builders = 0
explicit_builders = 0
for path in sorted((root / "crates").rglob("*.rs")):
    relative = path.relative_to(root).as_posix()
    if relative == "crates/core/src/registry/mod.rs" or relative.startswith("crates/types/generated/"):
        continue
    if path.is_symlink() or not path.is_file():
        fail(f"deadline-class Rust source is not a regular file: {relative}")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read deadline-class Rust source {relative}: {error}")
    if re.search(r"\bOperationSpec\s+as\s+\w+|\btype\s+\w+\s*=\s*[^;]*\bOperationSpec\b", text):
        fail(f"OperationSpec aliases are forbidden from the deadline-class census: {relative}")
    builders = list(builder_pattern.finditer(text))
    # Rustdoc that links a constructor is prose, not a construction site. `OperationSpec::standard`
    # is referenced from `route/generated.rs`, which builds no specification at all, so the
    # inventory question is asked of code lines only.
    code_text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    if ("OperationSpec::builder" in code_text or "OperationSpec::standard" in code_text) and not builders:
        fail(f"OperationSpec builder cannot be inventoried: {relative}")
    in_standard_source = path.parent == ops_dir and path.name != "mod.rs"
    if in_standard_source and len(builders) != 1:
        fail(f"standard operation source has {len(builders)} specification builders instead of one: {relative}")
    for builder in builders:
        chain = builder.group(0)
        names = re.findall(r'OperationSpec::(?:builder|standard)\(\s*"([A-Za-z0-9:]+)"', chain)
        standard = chain.count(".handler_deadline_class(HandlerDeadlineClass::Standard)")
        extended = chain.count(".handler_deadline_class(HandlerDeadlineClass::Extended)")
        if standard + extended > 1:
            fail(f"OperationSpec builder declares multiple deadline classes: {relative}")
        if in_standard_source:
            if len(names) != 1 or names[0] not in operations or standard or extended:
                fail(f"standard operation specification bypasses the central deadline authority: {relative}")
            central_builders += 1
        elif len(names) == 1 and names[0] in operations:
            if standard or extended:
                if relative != "crates/gateway/tests/support/mod.rs":
                    fail(f"standard builder bypasses the central deadline authority: {names[0]}")
                if standard != 1 or extended:
                    fail(f"explicit OperationSpec builder does not use Standard: {relative}")
                explicit_builders += 1
            else:
                central_builders += 1
        else:
            if standard != 1 or extended:
                if standard + extended == 0:
                    fail(f"unclassified OperationSpec builder: {relative}")
                fail(f"explicit OperationSpec builder does not use Standard: {relative}")
            explicit_builders += 1

if central_builders != 102 or explicit_builders != 27:
    fail(
        "repository builder census drifted: "
        f"central={central_builders} explicit={explicit_builders}, expected central=102 explicit=27"
    )

print(
    "check_handler_deadline_class: 134 repository builder sites are inventoried "
    "(129 classified: 102 central standard, 27 explicit; 5 authority tests)"
)
PY
