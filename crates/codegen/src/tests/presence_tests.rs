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

//! The list members whose presence is carried (rustfs/gateway#1078, ADR-0037).
//!
//! Responsible for: exactly the wrapped document lists the legacy stack holds as an `Option`
//! carrying their presence — typed `Option<Vec<_>>`, read into the member only when the wrapper is
//! there, and written under the RustFS layout only when set — and every other list staying the
//! bare container ADR-0004 P1 makes it.
//! NOT responsible for: what a present empty list means to a handler, or the bytes it is stored
//! as (`rustfs-gateway-types`' persistence bridge, and the differential in `rustfs-gateway-difftest`).
//! Upstream: `emit::dto::presence`, the pinned model and legacy facts. Downstream: nothing.

use std::collections::BTreeSet;

use rustfs_gateway_model::ir::{Binding, Field, Type};

use super::codegen_tests::{artifacts, body};
use crate::emit::dto::naming;
use crate::emit::dto::presence::carries_presence;
use crate::emit::dto::registry::Registry;

/// Every `owner.member` whose presence is carried, over every operation's input, output and shapes.
fn carried(artifacts: &crate::Artifacts) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for ir in &artifacts.operations {
        let marker = naming::type_name(&ir.operation);
        let mut owners: Vec<(String, &[Field])> = vec![
            (format!("{marker}Input"), ir.input.as_slice()),
            (format!("{marker}Output"), ir.output.as_slice()),
        ];
        for (name, shape) in &ir.shapes {
            owners.push((name.clone(), shape.fields.as_slice()));
        }
        for (owner, fields) in owners {
            for field in fields.iter().filter(|field| carries_presence(&owner, field)) {
                out.insert(format!("{owner}.{}", field.name));
            }
        }
    }
    out
}

/// Positive — the lists whose presence is carried are the wrapped document lists the legacy stack
/// holds as an `Option` and the model does not require: the ACL grants, the logging grants, the
/// website routing rules, a restore location's grants and user metadata, inventory's optional
/// fields, the directory-bucket listing and the annotation listing.
#[test]
fn the_carried_lists_are_the_optional_wrapped_lists_of_the_legacy_stack() {
    let artifacts = artifacts();
    assert_eq!(
        carried(&artifacts).into_iter().collect::<Vec<_>>(),
        [
            "AccessControlPolicy.Grants",
            "GetBucketAclOutput.Grants",
            "GetBucketWebsiteOutput.RoutingRules",
            "GetObjectAclOutput.Grants",
            "InventoryConfiguration.OptionalFields",
            "ListDirectoryBucketsOutput.Buckets",
            "ListObjectAnnotationsOutput.Annotations",
            "LoggingEnabled.TargetGrants",
            "S3Location.AccessControlList",
            "S3Location.UserMetadata",
            "WebsiteConfiguration.RoutingRules",
        ]
    );
}

/// Negative — a carried list is `Option<Vec<_>>`, and every other list, a required or flattened or
/// header list among them, stays the bare container: `ListBuckets`' required `Buckets`, a
/// flattened lifecycle rule list, the header list of optional object attributes.
#[test]
fn n_only_a_carried_list_is_an_option() {
    let artifacts = artifacts();
    let field = |operation: &str, output: bool, name: &str| {
        let ir = artifacts
            .operations
            .iter()
            .find(|ir| ir.operation == operation)
            .unwrap_or_else(|| panic!("{operation}"));
        let fields = if output { &ir.output } else { &ir.input };
        fields
            .iter()
            .find(|field| field.name == name)
            .cloned()
            .unwrap_or_else(|| panic!("{operation}.{name}"))
    };
    let buckets = field("ListBuckets", true, "Buckets");
    assert!(buckets.required && !carries_presence("ListBucketsOutput", &buckets));
    assert!(Registry::field_type("ListBucketsOutput", &buckets).starts_with("Vec<"));
    let rules = field("GetBucketLifecycleConfiguration", true, "Rules");
    assert!(!carries_presence("GetBucketLifecycleConfigurationOutput", &rules));
    let attributes = field("ListObjectsV2", false, "OptionalObjectAttributes");
    assert_eq!(attributes.binding, Binding::Header);
    assert!(!carries_presence("ListObjectsV2Input", &attributes));
    let grants = field("GetBucketAcl", true, "Grants");
    assert!(Registry::field_type("GetBucketAclOutput", &grants).starts_with("Option<Vec<"));
}

/// Negative — a carried list is read into the member only when its wrapper is there, and written
/// under the RustFS layout only when set: the decoder assigns the wrapper's presence, and the
/// encoder guards the wrapper with the layout.
#[test]
fn n_a_carried_list_is_read_and_written_by_its_presence() {
    let artifacts = artifacts();
    let logging = body(&artifacts, "generated/codec/ops/put_bucket_logging.rs");
    assert!(
        logging.contains("shape.target_grants = node.child(\"TargetGrants\").map(|_| target_grants);"),
        "{logging}"
    );
    let read_back = body(&artifacts, "generated/codec/ops/get_bucket_logging.rs");
    assert!(
        read_back.contains("if value.target_grants.is_some() || !writer.writes_legacy_layout() {"),
        "{read_back}"
    );
    assert!(read_back.contains("for item in value.target_grants.iter().flatten() {"), "{read_back}");
    let tagging = body(&artifacts, "generated/codec/ops/get_bucket_tagging.rs");
    assert!(!tagging.contains("writes_legacy_layout"), "a required list is always written");
}

/// Negative — every optional wrapped list a request document can hold carries its presence, which
/// is what lets the RustFS reading hand an empty wrapper over rather than refuse it
/// (`rustfs_gateway_xml::bound` no longer calls one uncarriable).
#[test]
fn n_every_optional_wrapped_list_in_a_request_document_carries_its_presence() {
    let artifacts = artifacts();
    let mut checked = 0;
    let documents = |ir: &&rustfs_gateway_model::ir::OperationIr| {
        ir.input.iter().any(|field| {
            field.binding == Binding::BodyXml
                || (field.binding == Binding::Payload && matches!(field.ty, Type::Structure(_) | Type::Union(_)))
        })
    };
    for ir in artifacts.operations.iter().filter(documents) {
        for (name, shape) in &ir.shapes {
            for field in &shape.fields {
                if field.required || !matches!(field.ty, Type::List { flattened: false, .. }) {
                    continue;
                }
                assert!(carries_presence(name, field), "{}: {name}.{}", ir.operation, field.name);
                checked += 1;
            }
        }
    }
    assert!(checked >= 5, "only {checked} optional wrapped lists");
}
