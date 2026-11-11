#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Read RustFS's metadata listing selector: the two S3-shaped listing routes RustFS's metadata
route claims ahead of its admin router and its S3 service (rustfs/gateway#1588).

This is a deliberately narrow source reader, not a Rust interpreter. It accepts exactly one shape:
a GET-only selector over a bucket, gated on the first `metadata` value being `true`, whose arms
each name one listing operation by one query rule, and an access check that maps each operation to
one `S3Action`. Anything else fails instead of producing a row. The inventory supplies its
literal-aware delimiter reader; no RustFS runtime is imported.
"""

import re

METADATA_ROUTE = "rustfs/src/app/metadata_route.rs"
SELECTOR = "metadata_operation"
ACCESS = "check_metadata_access"
ENUM = "MetadataOperation"
GATE = re.compile(r'if\s+query_value\(query,\s*"metadata"\)\.as_deref\(\)\s*!=\s*Some\("true"\)\s*\{\s*return\s+None;\s*\}')
ARM = re.compile(
    r'(?:if|else\s+if)\s+(?P<cond>[^{]*?)\s*\{\s*' + ENUM + r'::(?P<variant>\w+)\s*\}'
)
PRESENT = re.compile(r'^query_has\(query,\s*"([^"]+)"\)$')
EQUALS = re.compile(r'^query_value\(query,\s*"([^"]+)"\)\.as_deref\(\)\s*==\s*Some\("([^"]*)"\)$')


def body_of(text, function, relative, fail, close):
    match = re.search(rf"fn {function}\([^{{]*\{{", text)
    if not match:
        fail(f"{relative}: {function} not found")
    return text[match.end():close(text, match.end() - 1, "{", "}")]


def metadata_listing_routes(text, relative, fail, close):
    """The metadata listing rows, in the order the selector tries them."""
    body = body_of(text, SELECTOR, relative, fail, close)
    if not re.search(r"if\s+method\s*!=\s*Method::GET\s*\{\s*return\s+None;\s*\}", body):
        fail(f"{relative}: {SELECTOR} is not GET-only")
    if "bucket_from_request(" not in body:
        fail(f"{relative}: {SELECTOR} does not address a bucket through bucket_from_request")
    gate = GATE.search(body)
    if not gate:
        fail(f"{relative}: {SELECTOR} has no exact metadata=true gate")
    rows = []
    for arm in ARM.finditer(body, gate.end()):
        condition = re.sub(r"\s+", " ", arm.group("cond")).strip()
        present, equals = PRESENT.match(condition), EQUALS.match(condition)
        if present:
            discriminator = {"key": present.group(1), "rule": "present"}
        elif equals:
            discriminator = {"key": equals.group(1), "rule": f"equals:{equals.group(2)}"}
        else:
            fail(f"{relative}: unreadable {ENUM} arm condition {condition!r}")
        rows.append({
            "name": f"{ENUM}::{arm.group('variant')}",
            "method": "GET",
            "target": "bucket",
            "query_discriminator": discriminator,
            "query_requires": [{"key": "metadata", "rule": "equals:true"}],
            "claimed_by": METADATA_ROUTE,
            "auth_mode": "custom",
            "auth_detail": "SignedOrAnonymousThenBucketListing",
        })
    named = re.findall(rf"{ENUM}::(\w+)", body[gate.end():])
    if not rows or [row["name"] for row in rows] != [f"{ENUM}::{variant}" for variant in named]:
        fail(f"{relative}: unreadable {ENUM} arms {named}")
    access = body_of(text, ACCESS, relative, fail, close)
    actions = dict(re.findall(rf"{ENUM}::(\w+)\s*=>\s*S3Action::(\w+)", access))
    for row in rows:
        variant = row["name"].split("::", 1)[1]
        if variant not in actions:
            fail(f"{relative}: no authorisation action for {row['name']}")
        row["iam_action_enum"], row["iam_action"] = "S3Action", actions[variant]
    return rows
