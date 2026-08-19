#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every one of the 24 acceptance ids in rustfs/backlog#1694 §7 — routing versus
# parameter validation, and the error code to HTTP status contract — to a named assertion inside a
# real conformance case, Rust test or guard mutation, or to an explicitly declared block with the
# issue that owns it.
# WHY: #1694 asks for 24 cases. Four of them were written as doc comments on Rust tests, twelve
# more were already settled elsewhere in the tree under other ids, and the rest were never written.
# Counting `grep c-err-` gives four; counting behaviours gives twenty. Neither number is a check,
# and an audit that has to be redone by hand every time is an audit nobody redoes.
# HOW TO EXEMPT: There is no exemption. A row moves out of `blocked` only by naming an assertion
# that resolves, and moves into it only by editing the ledger below, which is reviewed.
#
# Three mutations this ledger is built to die on:
#   1. delete a mapping    — the id roll call stops seeing 24 ids exactly once.
#   2. delete an assertion — the pointer no longer resolves, or resolves to something other than
#                            the literal recorded here.
#   3. flip a polarity     — §7's own 9/15 split stops adding up, or a named case's declared
#                            polarity stops matching the table below.
#
# # The rustfs/gateway#189 regression net
#
# #189 fixed six conformance regressions with one root cause each in error resolution. The first
# was that `NoSuchBucket`/`NoSuchKey` became contextual codes and two not-found messages were
# reworded away from AWS's exact bytes. `conformance/cases/object/c-object-0007.toml` and
# `c-object-0025.toml` are what caught it, and until now nothing named them: either could have been
# deleted, or its `exact_utf8` weakened to a status assertion, and every gate would have stayed
# green. `c-err-0003` below binds both — the exact byte string `The specified key does not exist.`
# and the sibling case that answers `NoSuchBucket` for the same request shape — so weakening either
# is now a build failure and not a code review nobody scheduled.
#
# # What `c-err-1006` is bound to, and what it is not
#
# §4.4's hardest rule is that a caller without `s3:ListBucket` must be answered `AccessDenied` for
# an object that is not there, because a `404` in that position is an existence oracle over every
# key in the bucket. `ResourceVisibility::Hidden` is where the gateway decides that, and the two
# tests this row names prove the decision and prove the masked message reveals nothing. What they
# do not prove is that anything ever selects it: every production and fixture construction site
# passes `Visible` — `crates/gateway/src/commit.rs:138`, `crates/conformance/src/fixture.rs:1849`
# and `:1859` — so `Hidden` is reachable from tests alone. The row is `bound` because the rule has
# a real assertion at the layer that owns it, and this paragraph is here so that nobody reads the
# green line as "the oracle is closed end to end". rustfs/backlog#1680 tracks the case form as
# `c-obj-0048`, blocked on a fixture that cannot deny a permission.
#
# # Why some rows point at a shell function
#
# Two of §7's rules are properties of the mapping table rather than of a request: no code outside
# the allowlist may land in the 5xx band, and no row may sit in the table unreached. Both are
# enforced by `scripts/check_error_status_total.sh`, and a guard is only worth as much as its
# negative control — so the evidence for those two is the mutation in
# `scripts/test_guard_scripts.sh` that makes the guard go red, not the guard itself.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# id|polarity|status|evidence
#
# `bound`   — evidence is one or more `<path>::<selector>` entries separated by `;`.
#             A `.toml` selector is `<json pointer>`, `<pointer>=<literal>` or
#             `<pointer>~<substring>`, resolved against the parsed case document.
#             A `.rs` selector is `fn <name>`, which must be an enabled `#[test]`.
#             A `.sh` selector is `fn <name>`, which must be a shell function that some
#             `expect_fail` line in the same file names — a negative control, not a definition.
# `blocked` — evidence is `<owner issue>::<why it is not an assertion yet>`; naming a path is
#             refused, because a blocked row that cites a file reads like a bound one.
#
# The polarity column is §7's own, per rule, not the polarity of the case that carries the
# assertion: the corpus labels a case by its input and one case settles several rules.
requirements=(
    'c-param-0001|positive|bound|crates/core/tests/params_and_dispatch.rs::fn analytics_with_an_id_routes_and_validates'
    'c-param-0002|positive|bound|crates/core/tests/params_and_dispatch.rs::fn an_object_get_has_nothing_to_validate'
    'c-err-0003|positive|bound|conformance/cases/object/c-object-0007.toml::/expect/error/code=NoSuchKey;conformance/cases/object/c-object-0007.toml::/expect/body/exact_utf8~<Message>The specified key does not exist.</Message>;conformance/cases/object/c-object-0025.toml::/exchanges/0/expect/error/code=NoSuchBucket'
    'c-err-0004|positive|bound|conformance/cases/object/c-object-0003.toml::/expect/status=204;conformance/cases/object/c-object-0003.toml::/expect/body/size=0'
    'c-err-0005|positive|bound|conformance/cases/bkt/c-bkt-0027.toml::/expect/status=301;conformance/cases/bkt/c-bkt-0027.toml::/expect/headers_present/x-amz-bucket-region=eu-west-1'
    'c-err-0006|positive|bound|crates/core/tests/params_and_dispatch.rs::fn an_unconfigured_subresource_has_its_own_code'
    'c-err-0007|positive|blocked|rustfs/backlog#1694::the read form of the delete-marker 404 needs a version stack the in-process fixture does not expose to a case; rustfs/backlog#1680 tracks the same gap as c-obj-0050, and a case that cannot mint the marker asserts the unversioned 404 instead'
    'c-err-0008|positive|blocked|rustfs/backlog#1694::c-copy-0035 and c-tagging-0024 pin the 405 for a copy source and a tagging read; the GET form needs a delete-marker version id the fixture does not mint, which rustfs/backlog#1680 tracks as c-obj-0049'
    'c-err-0009|positive|bound|crates/core/tests/params_and_dispatch.rs::fn the_delete_family_succeeds_with_204'
    'c-param-1001|negative|bound|crates/core/tests/params_and_dispatch.rs::fn a_missing_required_query_parameter_is_a_400_not_a_501;crates/core/tests/params_and_dispatch.rs::fn the_route_still_resolves_when_a_required_parameter_is_missing'
    'c-param-1002|negative|bound|crates/core/tests/params_and_dispatch.rs::fn a_missing_parameter_error_echoes_nothing_from_the_request'
    'c-param-1003|negative|blocked|rustfs/backlog#1694::no operation in the pinned model is both a route discriminator and a required parameter, so the rule has no subject to be violated by; every one of the sixty QueryPresent keys is a discriminator and the single required parameter is a header, and a guard over an empty intersection would be a check that cannot fail'
    'c-route-1004|negative|bound|crates/core/tests/params_and_dispatch.rs::fn the_unrouted_message_says_what_to_check'
    'c-route-1005|negative|bound|crates/core/tests/params_and_dispatch.rs::fn the_two_not_implemented_messages_are_different;crates/core/tests/params_and_dispatch.rs::fn an_empty_registry_answers_the_second_not_implemented'
    'c-err-1006|negative|bound|crates/core/tests/error_resolution.rs::fn a_missing_key_is_hidden_from_a_caller_who_may_not_list;crates/core/tests/error_resolution.rs::fn a_masked_missing_object_reveals_nothing_through_its_message'
    'c-err-1007|negative|bound|conformance/cases/object/c-object-0008.toml::/expect/body/size=0;crates/core/tests/error_resolution.rs::fn c_err_n007_head_removes_body_and_framing_without_changing_status'
    'c-err-1008|negative|bound|conformance/cases/cond/c-cond-0023.toml::/exchanges/0/expect/body/not_contains_utf8/0=xmlns'
    'c-err-1009|negative|bound|scripts/test_guard_scripts.sh::fn mut_error_status_unflagged_5xx;scripts/test_guard_scripts.sh::fn mut_error_status_server_fault_on_a_client_error'
    'c-err-1010|negative|bound|crates/core/tests/compile_fail/c_err_1010_custom_code_without_a_status.rs::text ErrorCode::custom("Foo");crates/core/tests/compile_fail.rs::text cases.compile_fail("tests/compile_fail/c_err_1010_*.rs")'
    'c-err-1011|negative|bound|crates/model/src/tests/overlay_tests.rs::fn refuses_a_row_without_a_status'
    'c-err-1012|negative|bound|scripts/test_guard_scripts.sh::fn mut_error_status_unlisted_dead_row;scripts/test_guard_scripts.sh::fn mut_error_status_stale_allowance'
    'c-err-1013|negative|bound|crates/core/tests/purity_guard.rs::fn the_pre_auth_error_never_formats_a_message'
    'c-err-1014|negative|bound|conformance/cases/object/c-object-0011.toml::/expect/body/exact_utf8~<Error><Key>batch/retained</Key>;conformance/cases/object/c-object-0004.toml::/expect/body/exact_utf8~<Deleted><Key>batch/absent</Key></Deleted>'
    'c-err-1015|negative|blocked|rustfs/backlog#1694::the 301 carries x-amz-bucket-region and nothing else today, and only the 307 attaches a Location; whether AWS puts a Location on the permanent redirect is a protocol question that needs evidence before an ErrorHeader variant is added to a closed enum'
)

# §7 counts itself: 9 positive and 15 negative. Transcribed once, so that relabelling a rule to
# make it look like the other kind of evidence stops the build.
EXPECTED_POSITIVE=9
EXPECTED_NEGATIVE=15

# The polarity each named case declares, transcribed from the case files. The row column above is
# the *rule's* polarity; this is the *corpus's*, and the corpus's is what `negative >= positive` in
# the suite is counted from. A case relabelled to move that ratio stops this ledger.
case_polarity=(
    'conformance/cases/bkt/c-bkt-0027.toml|negative'
    'conformance/cases/cond/c-cond-0023.toml|negative'
    'conformance/cases/object/c-object-0003.toml|positive'
    'conformance/cases/object/c-object-0004.toml|positive'
    'conformance/cases/object/c-object-0007.toml|negative'
    'conformance/cases/object/c-object-0008.toml|negative'
    'conformance/cases/object/c-object-0011.toml|negative'
    'conformance/cases/object/c-object-0025.toml|negative'
)

command -v python3 >/dev/null 2>&1 || {
    printf 'check_error_contract_ledger: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT" "$EXPECTED_POSITIVE" "$EXPECTED_NEGATIVE" "$(printf '%s\n' "${case_polarity[@]}")" "${requirements[@]}" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
expected_positive = int(sys.argv[2])
expected_negative = int(sys.argv[3])
declared_case_polarity = [line for line in sys.argv[4].splitlines() if line.strip()]
rows = sys.argv[5:]

# §7 of rustfs/backlog#1694, transcribed once, in the order the issue lists them.
EXPECTED_IDS = [
    "c-param-0001",
    "c-param-0002",
    "c-err-0003",
    "c-err-0004",
    "c-err-0005",
    "c-err-0006",
    "c-err-0007",
    "c-err-0008",
    "c-err-0009",
    "c-param-1001",
    "c-param-1002",
    "c-param-1003",
    "c-route-1004",
    "c-route-1005",
    "c-err-1006",
    "c-err-1007",
    "c-err-1008",
    "c-err-1009",
    "c-err-1010",
    "c-err-1011",
    "c-err-1012",
    "c-err-1013",
    "c-err-1014",
    "c-err-1015",
]

failures = []


def fail(message):
    failures.append(message)


# -- The roll call ---------------------------------------------------------------------------
parsed = {}
order = []
for row in rows:
    parts = row.split("|", 3)
    if len(parts) != 4:
        fail(f"row is not id|polarity|status|evidence: {row}")
        continue
    identifier, polarity, status, evidence = parts
    if identifier in parsed:
        fail(f"duplicate acceptance id: {identifier}")
        continue
    if polarity not in ("positive", "negative"):
        fail(f"{identifier}: polarity must be positive or negative, not {polarity!r}")
        continue
    if status not in ("bound", "blocked"):
        fail(f"{identifier}: status must be bound or blocked, not {status!r}")
        continue
    parsed[identifier] = (polarity, status, evidence)
    order.append(identifier)

for identifier in EXPECTED_IDS:
    if identifier not in parsed:
        fail(f"§7 acceptance id has no ledger row: {identifier}")
for identifier in order:
    if identifier not in EXPECTED_IDS:
        fail(f"ledger row names an id §7 does not list: {identifier}")

# -- The polarity arithmetic -----------------------------------------------------------------
positive = sum(1 for polarity, _, _ in parsed.values() if polarity == "positive")
negative = sum(1 for polarity, _, _ in parsed.values() if polarity == "negative")
if (positive, negative) != (expected_positive, expected_negative):
    fail(
        f"§7 is {expected_positive} positive and {expected_negative} negative; "
        f"the ledger reads {positive} positive and {negative} negative"
    )

# -- The case labels -------------------------------------------------------------------------
documents = {}


def load(relative):
    if relative not in documents:
        path = root / relative
        if not path.is_file():
            documents[relative] = None
        else:
            try:
                documents[relative] = tomllib.loads(path.read_text())
            except (OSError, tomllib.TOMLDecodeError) as error:
                fail(f"{relative}: {error}")
                documents[relative] = None
    return documents[relative]


labelled = set()
for line in declared_case_polarity:
    relative, _, polarity = line.partition("|")
    labelled.add(relative)
    document = load(relative)
    if document is None:
        fail(f"case named by the polarity table is missing or unreadable: {relative}")
        continue
    observed = document.get("case", {}).get("polarity")
    if observed != polarity:
        fail(f"{relative}: the ledger records polarity {polarity!r}, the case declares {observed!r}")


# -- The assertions --------------------------------------------------------------------------
def resolve(document, pointer):
    """Walk a JSON pointer through a parsed TOML document. `None` for anything unreachable."""
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                return None
            current = current[int(token)]
        else:
            return None
    return current


def check_toml_evidence(identifier, relative, selector):
    document = load(relative)
    if document is None:
        fail(f"{identifier}: evidence file is missing: {relative}")
        return
    if relative not in labelled:
        fail(f"{identifier}: {relative} carries an assertion but no row in the case polarity table")
        return
    for separator in ("~", "="):
        pointer, found, literal = selector.partition(separator)
        if found:
            break
    else:
        pointer, separator, literal = selector, "", ""
    if not pointer.startswith("/"):
        fail(f"{identifier}: selector is not a JSON pointer: {selector}")
        return
    value = resolve(document, pointer)
    if value is None:
        fail(f"{identifier}: {relative} no longer carries an assertion at {pointer}")
        return
    if separator == "" and value in ("", [], {}):
        fail(f"{identifier}: {relative}{pointer} resolves to an empty value")
        return
    if separator == "=" and str(value) != literal:
        fail(f"{identifier}: {relative}{pointer} is {value!r}, the ledger records {literal!r}")
        return
    if separator == "~" and literal not in str(value):
        fail(f"{identifier}: {relative}{pointer} does not contain {literal!r}")


def uncommented(source):
    """The source with comments blanked: a rule named only in prose is not a rule."""
    source = re.sub(r"(?m)//.*$", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return source


def check_rust_evidence(identifier, relative, selector):
    path = root / relative
    if not path.is_file():
        fail(f"{identifier}: evidence file is missing: {relative}")
        return
    if selector.startswith("text "):
        literal = selector.removeprefix("text ")
        if literal not in uncommented(path.read_text()):
            fail(f"{identifier}: {relative} no longer contains {literal!r} outside a comment")
        return
    if not selector.startswith("fn "):
        fail(f"{identifier}: Rust evidence must name a test function or a literal, not {selector!r}")
        return
    name = selector.removeprefix("fn ")
    source = uncommented(path.read_text())
    pattern = re.compile(rf"(?m)^[ \t]*(?:async\s+)?fn\s+{re.escape(name)}\s*\(")
    if len(pattern.findall(source)) != 1:
        fail(f"{identifier}: {relative} has no single top-level fn {name}")
        return
    attributed = re.compile(
        rf"#\s*\[\s*(?:test|tokio::test[^\]]*)\s*\]\s*(?:async\s+)?fn\s+{re.escape(name)}\s*\("
    )
    if not attributed.search(source):
        fail(f"{identifier}: {relative}::{name} is not an enabled test")


def check_shell_evidence(identifier, relative, selector):
    """A shell mutation is evidence only when some `expect_fail` line actually runs it."""
    path = root / relative
    if not path.is_file():
        fail(f"{identifier}: evidence file is missing: {relative}")
        return
    if not selector.startswith("fn "):
        fail(f"{identifier}: shell evidence must name a mutation function, not {selector!r}")
        return
    name = selector.removeprefix("fn ")
    source = path.read_text()
    defined = re.compile(rf"(?m)^{re.escape(name)}\s*\(\)\s*\{{")
    if len(defined.findall(source)) != 1:
        fail(f"{identifier}: {relative} has no single {name}() definition")
        return
    invoked = re.compile(rf"(?m)^\s+{re.escape(name)}\s*\\?$")
    if not invoked.search(source):
        fail(
            f"{identifier}: {relative} defines {name}() but no expect_fail line runs it; "
            "a mutation nothing replays is not a negative control"
        )


OWNER = re.compile(r"^rustfs/(backlog|gateway)#[0-9]+$")

for identifier in EXPECTED_IDS:
    if identifier not in parsed:
        continue
    _, status, evidence = parsed[identifier]
    if status == "blocked":
        owner, _, reason = evidence.partition("::")
        if not OWNER.match(owner):
            fail(f"{identifier}: a blocked row must open with an owning issue, not {owner!r}")
            continue
        if len(reason) < 40:
            fail(f"{identifier}: a blocked row must say why in a sentence, not {reason!r}")
        if "::" in reason:
            fail(f"{identifier}: a blocked row must not name evidence")
        continue
    entries = [entry for entry in evidence.split(";") if entry]
    if not entries:
        fail(f"{identifier}: a bound row names no evidence")
        continue
    for entry in entries:
        relative, separator, selector = entry.partition("::")
        if not separator:
            fail(f"{identifier}: evidence is not <path>::<selector>: {entry}")
            continue
        if relative.endswith(".toml"):
            check_toml_evidence(identifier, relative, selector)
        elif relative.endswith(".rs"):
            check_rust_evidence(identifier, relative, selector)
        elif relative.endswith(".sh"):
            check_shell_evidence(identifier, relative, selector)
        else:
            fail(f"{identifier}: evidence is neither a case, a Rust test nor a guard: {relative}")

# Every case the polarity table pins must actually be used, or the table becomes a place where a
# deleted mapping can hide.
used = set()
for _, status, evidence in parsed.values():
    if status != "bound":
        continue
    for entry in evidence.split(";"):
        relative, separator, _ = entry.partition("::")
        if separator and relative.endswith(".toml"):
            used.add(relative)
for relative in sorted(labelled - used):
    fail(f"the case polarity table pins {relative}, which no bound row names")

if failures:
    for message in failures:
        print(f"check_error_contract_ledger: {message}", file=sys.stderr)
    raise SystemExit(1)

bound = sum(1 for _, status, _ in parsed.values() if status == "bound")
blocked = len(parsed) - bound
print(
    f"OK: {len(parsed)} error-contract acceptance ids — {bound} bound to a resolved assertion, "
    f"{blocked} blocked with an owning issue"
)
PYEOF
