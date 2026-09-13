// Copyright 2026 RustFS Team
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

//! Every SSE-sensitive member reaches the DTO `Debug` output as a placeholder.
//!
//! Responsible for: walking the emitter's own [`Registry`] over the pinned IR, finding every
//! struct that carries an SSE-C key, its MD5, a KMS key id or a KMS encryption context, and
//! rendering that struct's `Debug` implementation with the emitter's own [`debug_impl`], so a
//! mapping dropped from [`REDACTED_WIRE_NAMES`] goes red here by the member it exposed.
//! NOT responsible for: whether the rendered code compiles (`rustfs-gateway-types` proves that), or
//! the error bodies, which the conformance cases measure.
//! Upstream: [`crate::emit::dto`]. Downstream: none (test-only module).
//!
//! The expected list below is deliberately independent of [`REDACTED_WIRE_NAMES`]: a test that
//! read the constant it guards would agree with any edit made to it.
//!
//! [`Registry`]: crate::emit::dto::registry::Registry
//! [`debug_impl`]: crate::emit::dto::debug_impl
//! [`REDACTED_WIRE_NAMES`]: crate::emit::dto::registry::REDACTED_WIRE_NAMES

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use rustfs_gateway_model::ir::{Field, OperationIr};

use crate::emit::dto::registry::{Registry, is_redacted};
use crate::emit::dto::{debug_impl, derives, naming};

/// The SSE members whose value must never reach a log line, by the wire name the IR carries.
///
/// Headers first, then the XML body members that carry the same values inside a document.
const SENSITIVE_WIRE_NAMES: &[&str] = &[
    "x-amz-server-side-encryption-customer-key",
    "x-amz-copy-source-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-copy-source-server-side-encryption-customer-key-md5",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "KMSMasterKeyID",
    "ReplicaKmsKeyID",
    "KeyId",
    "KMSKeyId",
    "KMSContext",
    // The replication destination's account id. `q-repl-0010` classifies it beside the replica KMS
    // key id as a configuration secret the stored document echoes on the read and nothing else may
    // print; a derived `Debug` is one `{:?}` away from the log line that rule forbids.
    "Account",
];

fn operations() -> &'static [OperationIr] {
    static OPERATIONS: OnceLock<Vec<OperationIr>> = OnceLock::new();
    OPERATIONS.get_or_init(|| super::codegen_tests::artifacts().operations)
}

/// Every struct the emitter renders a `Debug` for, as `(type name, members)`.
///
/// Operation inputs and outputs come straight from the IR, nested shapes from the registry the
/// emitter itself builds — the same two sources `render::operation` and `shared::shapes` read.
fn rendered_structs() -> Vec<(String, Vec<Field>)> {
    let operations = operations();
    let ordered: Vec<&OperationIr> = operations.iter().collect();
    let registry = Registry::collect(&ordered).expect("the pinned model has one coherent vocabulary");
    let mut structs = Vec::new();
    for ir in operations {
        structs.push((format!("{}Input", ir.operation), ir.input.clone()));
        structs.push((format!("{}Output", ir.operation), ir.output.clone()));
    }
    for (name, shape) in registry.shapes {
        structs.push((name, shape.fields));
    }
    structs
}

/// Every sensitive member the pinned model has, as `(struct, field, wire name)`, plus the `Debug`
/// the emitter renders for its struct.
fn sensitive_members() -> Vec<(String, Field, String)> {
    let mut found = Vec::new();
    for (owner, fields) in rendered_structs() {
        let rendered = debug_impl(&owner, &fields);
        for field in &fields {
            if field
                .wire_name
                .as_deref()
                .is_some_and(|wire| SENSITIVE_WIRE_NAMES.contains(&wire))
            {
                found.push((owner.clone(), field.clone(), rendered.clone()));
            }
        }
    }
    found
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

/// Negative — no sensitive member is printed by value in the `Debug` the emitter renders.
#[test]
fn no_sse_sensitive_member_is_printed_by_value_in_debug() {
    let mut leaks = Vec::new();
    for (owner, field, rendered) in sensitive_members() {
        let name = naming::field_name(&field.name);
        if rendered.contains(&format!(".field(\"{name}\", &self.{name})")) {
            leaks.push(format!("{owner}.{name} ({})", field.wire_name.as_deref().unwrap_or_default()));
        }
    }
    assert!(
        leaks.is_empty(),
        "these SSE members reach Debug output by value, one `{{:?}}` away from a log line: {leaks:#?}"
    );
}

/// Negative — every sensitive member is classified as redacted. That classification is the one
/// bit `render` and `shared` read to drop `Debug` from the derive list; a member outside it leaves
/// its struct with a derived `Debug` that prints every field by value.
#[test]
fn every_sse_sensitive_member_is_classified_as_secret() {
    let unclassified: Vec<String> = sensitive_members()
        .into_iter()
        .filter(|(_, field, _)| !is_redacted(field))
        .map(|(owner, field, _)| format!("{owner}.{}", naming::field_name(&field.name)))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these SSE members are not classified as secret: {unclassified:#?}"
    );
    assert!(
        !derives(true, true, true).contains("Debug"),
        "a struct with a secret member must not derive Debug"
    );
}

/// Negative — the walk is not vacuous: every listed wire name is found in the pinned model at
/// least once. A renamed member would otherwise make both tests above pass by matching nothing.
#[test]
fn every_listed_sensitive_wire_name_is_present_in_the_model() {
    let mut seen: BTreeMap<&str, usize> = SENSITIVE_WIRE_NAMES.iter().map(|name| (*name, 0)).collect();
    for (_, field, _) in sensitive_members() {
        if let Some(count) = field.wire_name.as_deref().and_then(|wire| seen.get_mut(wire)) {
            *count += 1;
        }
    }
    let missing: Vec<&str> = seen.iter().filter(|(_, count)| **count == 0).map(|(name, _)| *name).collect();
    assert!(missing.is_empty(), "no generated struct carries {missing:?}; the list is stale");
}

// ── positive ──────────────────────────────────────────────────────────────────────────────────

/// Positive — the KMS key id header on PutObject renders as a placeholder that still tells
/// "absent" from "present".
#[test]
fn the_put_object_kms_key_id_renders_through_redact() {
    let (_, _, rendered) = sensitive_members()
        .into_iter()
        .find(|(owner, field, _)| {
            owner == "PutObjectInput" && field.wire_name.as_deref() == Some("x-amz-server-side-encryption-aws-kms-key-id")
        })
        .expect("PutObject carries the KMS key id header");
    assert!(
        rendered.contains(".field(\"ssekms_key_id\", &redact(&self.ssekms_key_id))"),
        "PutObjectInput's Debug does not redact the KMS key id:\n{rendered}"
    );
}
