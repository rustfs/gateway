#!/usr/bin/env bash
set -euo pipefail

# Proves that the bucket configuration family keeps its graded write policies (rustfs/backlog#1728,
# ADR-0007): the security configurations refuse what is not registered on the write path —
# PutPublicAccessBlock through its generated allow-registered element guard, PutBucketPolicy through
# the strict, duplicate-aware JSON check every write is gated on — while their persisted reads stay
# lenient, and the six persisted switch configurations (versioning, website, notification,
# accelerate, logging, requestPayment) stay lenient on the write path too, because a stricter
# decoder there silently turns the setting off.
#
# Also proves that CORS selects its deliberately lenient persisted-runtime policy and that Lifecycle
# keeps two deliberately different XML policies:
# the generic HTTP codec is lenient when no dialect is selected, while the
# persisted MinIO dialect accepts only its registered field and blocks a
# lossy rewrite on every other unknown. Runtime tests prove the behavior; this
# guard makes the selected/unselected wiring and its protected ledger record
# impossible to drift independently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_codec_policy: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path


root = Path(sys.argv[1])


def fail(message: str) -> None:
    print(f"check_codec_policy: {message}", file=sys.stderr)
    raise SystemExit(1)


def source(path: str) -> str:
    candidate = root / path
    if not candidate.is_file():
        fail(f"required input is missing: {path}")
    return candidate.read_text(encoding="utf-8")


def require(pattern: str, text: str, message: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        fail(message)


ext = source("crates/types/src/ext.rs")
require(
    r"pub fn security_relevant\(\) -> Self \{\s*Self::new\(UnknownElementPolicy::AllowRegistered\)\s*\}",
    ext,
    "security-relevant persisted XML no longer defaults to AllowRegistered",
)

cors = source("crates/types/src/cors_tagging.rs")
require(
    r"pub fn parse_runtime_cors\(input: &\[u8\]\) -> PersistedXml<PersistedCorsConfiguration> \{\s*"
    r"let policy = CodecPolicy::new\(UnknownElementPolicy::Lenient\);\s*"
    r"parse_cors_with_policy\(input, &policy\)\s*\}",
    cors,
    "the persisted runtime CORS reader no longer selects Lenient explicitly",
)

dialect = source("crates/dialect-minio/src/lib.rs")
for pattern, message in [
    (r'const PARENT: &\'static str = "LifecycleRule";', "DelMarkerExpiration changed parent"),
    (r'const LOCAL_NAME: &\'static str = "DelMarkerExpiration";', "DelMarkerExpiration changed local name"),
    (r'const INSERT_AFTER: &\'static str = "Expiration";', "DelMarkerExpiration changed insertion slot"),
    (
        r"pub fn new\(\) -> Result<Self, ExtError> \{\s*let mut policy = CodecPolicy::security_relevant\(\);\s*policy\.register::<DelMarkerExpiration>\(\)\?;\s*Ok\(Self \{ policy \}\)\s*\}",
        "the selected MinIO lifecycle dialect no longer registers DelMarkerExpiration",
    ),
    (
        r"pub fn without_extensions\(\) -> Self \{\s*Self \{\s*policy: CodecPolicy::security_relevant\(\),\s*\}\s*\}",
        "the no-dialect control no longer carries an empty fail-closed policy",
    ),
]:
    require(pattern, dialect, message)

persistence = source("crates/types/src/persistence/lifecycle.rs")
static_children = re.search(r"const STATIC_RULE_CHILDREN: &\[&str\] = &\[(.*?)\];", persistence, re.DOTALL)
if static_children is None:
    fail("cannot locate LifecycleRule's static child set")
if '"DelMarkerExpiration"' in static_children.group(1):
    fail("DelMarkerExpiration bypasses the runtime extension policy as a static child")
require(
    r'policy\.decode_unknown\("LifecycleRule", child, &mut extensions\)\?;',
    persistence,
    "unknown LifecycleRule children no longer flow through the borrowed policy",
)
require(
    r'policy\.validate_slots\("LifecycleRule", &\["Expiration"\]\)\?;',
    persistence,
    "the persisted writer no longer validates the exact extension insertion slot",
)

case = source("conformance/cases/lifecycle/c-lifecycle-0018.toml")
quirks = re.search(r'^quirks = \[(.*?)\]$', case, re.MULTILINE)
if quirks is None or set(re.findall(r'"([^"]+)"', quirks.group(1))) != {"q-lc-0006", "q-lc-0015"}:
    fail("c-lifecycle-0018 no longer binds both leniency and dialect selection")
not_contains = re.search(r'^not_contains_utf8 = \[(.*?)\]$', case, re.MULTILINE)
if not_contains is None or set(re.findall(r'"([^"]+)"', not_contains.group(1))) != {
    "DelMarkerExpiration",
    "FutureKnob",
}:
    fail("c-lifecycle-0018 no longer proves the unselected codec drops both unknown children")

overlay = source("model/overlays/quirks/lifecycle.toml")
records = re.findall(r'\[\[quirk\]\]\n(.*?)(?=\n\[\[quirk\]\]|\Z)', overlay, re.DOTALL)
records = [record for record in records if re.search(r'^id\s*=\s*"q-lc-0015"$', record, re.MULTILINE)]
if len(records) != 1:
    fail("the lifecycle overlay must declare q-lc-0015 exactly once")
record = records[0]
if not re.search(r'^classification\s*=\s*"contract"$', record, re.MULTILINE) or not re.search(
    r'^target\s*=\s*"PersistedLifecycleRule\.DelMarkerExpiration"$', record, re.MULTILINE
):
    fail("q-lc-0015 no longer names the persisted DelMarkerExpiration contract")
if not re.search(r'^cases\s*=\s*\["c-lifecycle-0018"\]$', record, re.MULTILINE):
    fail("q-lc-0015 is not bound to its no-dialect control case")
if "[[quirk.evidence]]" not in record:
    fail("q-lc-0015 has no protocol evidence")

ledger = source("crates/conformance/tests/lifecycle_family.rs")
if ledger.count('"q-lc-0015"') != 1:
    fail("the deterministic lifecycle ledger does not declare q-lc-0015 exactly once")

tests = source("crates/dialect-minio/tests/integration.rs")
for name in [
    "registered_lifecycle_field_survives_real_rmw_in_its_exact_slot",
    "without_the_registration_preserves_bytes_and_blocks_rmw",
    "unregistered_persisted_sibling_preserves_bytes_and_blocks_rmw",
    "malformed_persisted_lifecycle_document_is_never_absent_or_rewritten",
]:
    if name not in tests:
        fail(f"the executable lifecycle policy matrix lost {name}")

# --- The bucket configuration family: security writes allow-registered, persisted reads and the
# persisted switch configurations lenient (rustfs/backlog#1728, ADR-0007). ---------------------

def quirk_record(overlay_text: str, quirk_id: str) -> str:
    found = [
        record
        for record in re.findall(r'\[\[quirk\]\]\n(.*?)(?=\n\[\[quirk\]\]|\Z)', overlay_text, re.DOTALL)
        if re.search(rf'^id\s*=\s*"{re.escape(quirk_id)}"$', record, re.MULTILINE)
    ]
    if len(found) != 1:
        fail(f"the overlay must declare {quirk_id} exactly once")
    return found[0]


pab_rule = quirk_record(source("model/overlays/quirks/bucket-policy.toml"), "q-pab-0005")
for pattern, message in [
    (r'^mutation_dimension\s*=\s*"unknown_element_policy"$', "q-pab-0005 no longer governs the unknown-element policy"),
    (r'^codec_value\s*=\s*"reject"$', "PutPublicAccessBlock's write path is no longer allow-registered (q-pab-0005)"),
    (r'^target\s*=\s*"PutPublicAccessBlock"$', "q-pab-0005 no longer targets PutPublicAccessBlock"),
    (r'^cases\s*=\s*\["c-bucketconfig-0061"\]$', "q-pab-0005 is not bound to its refusal case"),
]:
    require(pattern, pab_rule, message)
require(
    r'^codec_value = "reject"$',
    source("spec/quirks/q-pab-0005.toml"),
    "the generated rule table no longer records q-pab-0005 as reject",
)
require(
    r'^quirks = \[[^\]]*"q-pab-0005"[^\]]*\]$',
    source("spec/operations/PutPublicAccessBlock.toml"),
    "PutPublicAccessBlock no longer carries q-pab-0005",
)

UNKNOWN_GUARD = 'return Err(CodecError::malformed_xml("the body contains an unknown element"));'
require(
    r'let known = \[\s*"BlockPublicAcls",\s*"IgnorePublicAcls",\s*"BlockPublicPolicy",\s*"RestrictPublicBuckets",\s*\];\s*'
    r'if node\.children\.iter\(\)\.any\(\|child\| !known\.contains\(&child\.name\.as_str\(\)\)\) \{\s*'
    + re.escape(UNKNOWN_GUARD),
    source("generated/codec/ops/put_public_access_block.rs"),
    "the generated PutPublicAccessBlock decoder no longer refuses an unregistered element",
)
refusal_case = source("conformance/cases/bucketconfig/c-bucketconfig-0061.toml")
require(r'^quirks = \["q-pab-0005"\]$', refusal_case, "c-bucketconfig-0061 no longer binds q-pab-0005")
require(r'^status = 400$\s*(?:\n.*?)*?^code = "MalformedXML"$', refusal_case, "c-bucketconfig-0061 no longer expects 400 MalformedXML")

persisted = source("crates/types/src/persistence.rs")
reader = re.search(
    r'pub fn parse_public_access_block\(input: &\[u8\]\) -> Result<PersistedPublicAccessBlockConfiguration, PersistenceCodecError> \{\n(.*?)\n\}\n',
    persisted,
    re.DOTALL,
)
if reader is None:
    fail("cannot locate the persisted PublicAccessBlock reader")
if 'parse_persistence_root(input, "PublicAccessBlockConfiguration")' not in reader.group(1):
    fail("the persisted PublicAccessBlock reader no longer reads its root")
if "children" in reader.group(1) or "nknown" in reader.group(1):
    fail("the persisted PublicAccessBlock reader inspects unknown children; persisted reads stay lenient (ADR-0007)")
boundary = source("crates/core/tests/security_request_policy.rs")
for name in [
    "n_a_security_request_refuses_unknown_public_access_root",
    "persisted_public_access_bytes_with_an_unknown_root_element_stay_readable",
]:
    if f"fn {name}()" not in boundary:
        fail(f"the executable PublicAccessBlock write/read boundary lost {name}")

policy_codec = source("generated/codec/ops/put_bucket_policy.rs")
for needle, message in [
    ("value::require_integrity(request)?;", "the PutBucketPolicy decoder no longer requires an integrity claim"),
    ("value::verify_body_digest(request, raw_body.as_ref())?;", "the PutBucketPolicy decoder no longer verifies the body digest"),
    ('input.policy = value::text_payload(raw_body.as_ref(), "Policy")?;', "the PutBucketPolicy body is no longer carried as one text payload"),
]:
    if needle not in policy_codec:
        fail(message)
policy_check = source("crates/core/src/ops/shared/bucket_policy.rs")
require(
    r'if !names\.insert\(name\) \{\s*return Err\(PolicyRejection::NotJson\);',
    policy_check,
    "the bucket policy check no longer refuses a repeated member name",
)
fixture = source("crates/conformance/src/fixture.rs")
require(
    r'fn put_bucket_policy\(&self, input: &dto::PutBucketPolicyInput\)[^{]*\{[^}]*validate_policy\(&input\.policy\)[^}]*fixture\.set_policy\(',
    fixture,
    "the PutBucketPolicy handler no longer gates the write on validate_policy",
)
policy_read = re.search(r'fn get_bucket_policy\(&self, input: &dto::GetBucketPolicyInput\)[^{]*\{([^}]*)\}', fixture)
if policy_read is None:
    fail("cannot locate the GetBucketPolicy handler")
if "validate_policy" in policy_read.group(1):
    fail("the GetBucketPolicy read validates the stored document; persisted reads stay lenient")
if "fn a_member_name_repeated_under_an_escaped_spelling_is_refused()" not in source("crates/core/tests/policy_json_replay.rs"):
    fail("the policy_json replay lost its repeated-name refusal")

LENIENT_WRITES = {
    "PutBucketVersioning": "put_bucket_versioning",
    "PutBucketWebsite": "put_bucket_website",
    "PutBucketNotificationConfiguration": "put_bucket_notification_configuration",
    "PutBucketAccelerateConfiguration": "put_bucket_accelerate_configuration",
    "PutBucketLogging": "put_bucket_logging",
    "PutBucketRequestPayment": "put_bucket_request_payment",
}
for operation, stem in LENIENT_WRITES.items():
    codec = source(f"generated/codec/ops/{stem}.rs")
    if not re.search(r"^fn read_", codec, re.MULTILINE):
        fail(f"{operation}'s generated decoder no longer reads an XML document; the lenient check would be vacuous")
    if UNKNOWN_GUARD.removeprefix("return ").removesuffix(";") in codec:
        fail(f"{operation}'s generated decoder refuses unknown elements; persisted configuration writes stay lenient")
overlays = root / "model/overlays/quirks"
if not overlays.is_dir():
    fail("required input is missing: model/overlays/quirks")
for overlay in sorted(overlays.glob("*.toml")):
    for record in re.findall(r'\[\[quirk\]\]\n(.*?)(?=\n\[\[quirk\]\]|\Z)', overlay.read_text(encoding="utf-8"), re.DOTALL):
        target = re.search(r'^target\s*=\s*"([^".]+)', record, re.MULTILINE)
        if (
            target is not None
            and target.group(1) in LENIENT_WRITES
            and re.search(r'^mutation_dimension\s*=\s*"unknown_element_policy"$', record, re.MULTILINE)
            and not re.search(r'^codec_value\s*=\s*"skip"$', record, re.MULTILINE)
        ):
            fail(f"{overlay.relative_to(root)} makes {target.group(1)} stricter than lenient")

# --- Object lock: the three security writes allow-registered, the persisted configuration read
# lenient at its root (rustfs/backlog#1726, ADR-0007). A write that skipped an unknown WORM setting
# answers 200 for a lock nobody stored; a persisted reader that refused an unknown root element would
# turn a stored WORM configuration into an unreadable one. Unknown *nested* children are refused by
# the historical reader and the current one alike (crates/goldens/src/object_lock.rs, D1-D5), so that
# is compatibility, not a leniency this guard could hold the reader to. -------------------------

lock_rule = quirk_record(source("model/overlays/quirks/object-lock.toml"), "q-lock-0014")
for pattern, message in [
    (r'^mutation_dimension\s*=\s*"unknown_element_policy"$', "q-lock-0014 no longer governs the unknown-element policy"),
    (r'^codec_value\s*=\s*"reject"$', "the object-lock write path is no longer allow-registered (q-lock-0014)"),
    (r'^target\s*=\s*"PutObjectLockConfiguration"$', "q-lock-0014 no longer targets PutObjectLockConfiguration"),
    (r'^cases\s*=\s*\[[^\]]*"c-lock-0010"[^\]]*\]$', "q-lock-0014 is not bound to its refusal case"),
]:
    require(pattern, lock_rule, message)
require(
    r'^codec_value = "reject"$',
    source("spec/quirks/q-lock-0014.toml"),
    "the generated rule table no longer records q-lock-0014 as reject",
)
LOCK_WRITES = {
    "PutObjectLockConfiguration": "put_object_lock_configuration",
    "PutObjectRetention": "put_object_retention",
    "PutObjectLegalHold": "put_object_legal_hold",
}
for operation, stem in LOCK_WRITES.items():
    require(
        r'^quirks = \[[^\]]*"q-lock-0014"[^\]]*\]$',
        source(f"spec/operations/{operation}.toml"),
        f"{operation} no longer carries q-lock-0014",
    )
    # Every reader in the decoder — the document root and each nested shape — carries a `known`
    # member list, and each list must be followed by the refusal. Counting the pair rather than
    # searching for one guard is what catches a single reader turning lenient while a sibling
    # (the nested EventHoldDuration reader of the 2026-09-17 model, say) still refuses.
    decoder = source(f"generated/codec/ops/{stem}.rs")
    known_lists = decoder.count("let known = [")
    guards = decoder.count(UNKNOWN_GUARD)
    if known_lists == 0 or guards != known_lists:
        fail(
            f"the generated {operation} decoder no longer refuses an unregistered element in every reader "
            f"({guards} refusal(s) for {known_lists} member list(s))"
        )
lock_case = source("conformance/cases/lock/c-lock-0010.toml")
require(r'^quirks = \["q-lock-0014"\]$', lock_case, "c-lock-0010 no longer binds q-lock-0014")
require(r'^status = 400$\s*(?:\n.*?)*?^code = "MalformedXML"$', lock_case, "c-lock-0010 no longer expects 400 MalformedXML")
lock_reader = re.search(
    r'pub fn parse_object_lock\(input: &\[u8\]\) -> Result<PersistedObjectLockConfiguration, PersistenceCodecError> \{\n(.*?)\n\}\n',
    persisted,
    re.DOTALL,
)
if lock_reader is None:
    fail("cannot locate the persisted ObjectLockConfiguration reader")
if 'root.name != "ObjectLockConfiguration"' not in lock_reader.group(1):
    fail("the persisted ObjectLockConfiguration reader no longer reads its root")
if "children" in lock_reader.group(1) or "nknown" in lock_reader.group(1):
    fail("the persisted ObjectLockConfiguration reader inspects unknown root children; persisted reads stay lenient (ADR-0007)")
for name in [
    "n_a_security_request_refuses_unknown_lock_root",
    "n_a_security_request_refuses_unknown_retention_root",
    "n_a_security_request_refuses_unknown_legal_hold_root",
    "persisted_lock_bytes_with_an_unknown_root_element_stay_readable",
]:
    if f"fn {name}()" not in boundary:
        fail(f"the executable object-lock write/read boundary lost {name}")

# --- Replication: the one fail-closed stored configuration (rustfs/backlog#1725). RustFS parses the
# stored replication document fail-closed, so a write decoder that grew stricter would not switch the
# feature off the way it would for the six switches above — it would make the bucket unusable on the
# next read. The narrow q-repl-0015 refusal (a non-empty <Filter> whose every child is unknown) is a
# different dimension on a different target and is deliberately not what this checks. -------------

replication_codec = source("generated/codec/ops/put_bucket_replication.rs")
if not re.search(r"^fn read_", replication_codec, re.MULTILINE):
    fail("PutBucketReplication's generated decoder no longer reads an XML document; the lenient check would be vacuous")
if UNKNOWN_GUARD.removeprefix("return ").removesuffix(";") in replication_codec:
    fail("PutBucketReplication's generated decoder refuses unknown elements; the fail-closed replication write stays lenient")
replication_overlay = source("model/overlays/quirks/replication.toml")
for record in re.findall(r'\[\[quirk\]\]\n(.*?)(?=\n\[\[quirk\]\]|\Z)', replication_overlay, re.DOTALL):
    if (
        re.search(r'^target\s*=\s*"PutBucketReplication"', record, re.MULTILINE)
        and re.search(r'^mutation_dimension\s*=\s*"unknown_element_policy"$', record, re.MULTILINE)
        and not re.search(r'^codec_value\s*=\s*"skip"$', record, re.MULTILINE)
    ):
        fail("model/overlays/quirks/replication.toml makes PutBucketReplication stricter than lenient")
leniency = quirk_record(replication_overlay, "q-repl-0005")
for pattern, message in [
    (r'^kind\s*=\s*"lenient_unknown_elements"$', "q-repl-0005 no longer records the replication write as lenient"),
    (r'^target\s*=\s*"PutBucketReplication"$', "q-repl-0005 no longer targets PutBucketReplication"),
    (r'^cases\s*=\s*\[[^\]]*"c-replication-0019"[^\]]*\]$', "q-repl-0005 is not bound to its acceptance case"),
]:
    require(pattern, leniency, message)
leniency_case = source("conformance/cases/replication/c-replication-0019.toml")
require(r'^quirks = \[[^\]]*"q-repl-0005"[^\]]*\]$', leniency_case, "c-replication-0019 no longer binds q-repl-0005")
statuses = re.findall(r'^status = (\d+)$', leniency_case, re.MULTILINE)
if not statuses or set(statuses) != {"200"}:
    fail("c-replication-0019 no longer expects the unknown-element write and its read-back to succeed")

print(
    "check_codec_policy: bucket configuration and object-lock write grading, replication leniency, CORS "
    "leniency and selected/unselected Lifecycle XML policies are bound"
)
PY
