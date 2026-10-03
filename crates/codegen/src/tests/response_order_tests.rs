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

//! The legacy RustFS response layout the encoder generator renders (rustfs/gateway#1078, row 5).
//!
//! Responsible for: each rendered order being the legacy structure's declaration order, alphabetical
//! or not; the lifecycle rule's order as the issue observed it on legacy RustFS; the layout switch
//! and the payload root's namespace reaching every response encoder; no order rendered where the
//! model's already is legacy RustFS's; the attributes answer's legacy root; and every entity tag
//! written with the call that keeps legacy RustFS's quotes under the layout.
//! NOT responsible for: writing a document in that order (`rustfs-gateway-xml`), or the bytes the
//! legacy stack answers (`rustfs-gateway-goldens`, `response_order`).
//! Upstream: `emit::codec::encode`, the pinned model. Downstream: nothing.

use super::codegen_tests::{artifacts, body};
use crate::emit::codec::encode::layout::LEGACY_ROOTS;
use crate::emit::dto::naming;

/// Every order a codec file renders, as `(constant, element names)`.
fn orders(file: &str) -> Vec<(String, Vec<String>)> {
    let Some(module) = file.split("mod rustfs_order {").nth(1) else {
        return Vec::new();
    };
    module
        .lines()
        .take_while(|line| *line != "}")
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub(super) const ")?;
            let (name, list) = rest.split_once(": &[&str] = &[")?;
            let list = list.strip_suffix("];")?;
            let names = list.split(", ").map(|quoted| quoted.trim_matches('"').to_owned()).collect();
            Some((name.to_owned(), names))
        })
        .collect()
}

fn codec_file(artifacts: &crate::Artifacts, operation: &str) -> String {
    body(artifacts, &format!("generated/codec/ops/{}.rs", naming::module_name(operation)))
}

fn rendered(artifacts: &crate::Artifacts, operation: &str, constant: &str) -> Vec<String> {
    orders(&codec_file(artifacts, operation))
        .into_iter()
        .find(|(name, _)| name == constant)
        .map(|(_, order)| order)
        .unwrap_or_else(|| panic!("{operation} renders no {constant}"))
}

/// Positive — an order is the legacy structure's declaration order even where that is not
/// alphabetical: the legacy stack declares a ListObjects answer in AWS's documented order, and a
/// completed upload's result alphabetically, `ChecksumXXHASH128` before `ChecksumXXHASH3`.
#[test]
fn an_order_is_the_legacy_declaration_order_alphabetical_or_not() {
    let artifacts = artifacts();
    assert_eq!(
        rendered(&artifacts, "ListObjects", "RESPONSE"),
        [
            "Name",
            "Prefix",
            "Marker",
            "MaxKeys",
            "IsTruncated",
            "Contents",
            "CommonPrefixes",
            "Delimiter",
            "NextMarker",
            "EncodingType",
        ]
    );
    let completed = rendered(&artifacts, "CompleteMultipartUpload", "RESPONSE");
    let position = |name: &str| {
        completed
            .iter()
            .position(|held| held == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    assert!(position("Bucket") < position("ChecksumCRC32") && position("ChecksumType") < position("ChecksumXXHASH128"));
    assert!(
        position("ChecksumXXHASH128") < position("ChecksumXXHASH3") && position("ChecksumXXHASH3") < position("ChecksumXXHASH64")
    );
    assert!(
        position("ETag") < position("Key") && position("Key") < position("Location"),
        "{completed:?}"
    );
}

/// Positive — the lifecycle rule is rendered in the order the issue observed legacy RustFS write
/// it (`DelMarkerExpiration`, `Expiration`, `Filter`, `ID`, `Status`), every member included.
#[test]
fn the_lifecycle_rule_is_rendered_in_legacy_rustfs_order() {
    let artifacts = artifacts();
    assert_eq!(
        rendered(&artifacts, "GetBucketLifecycleConfiguration", "LIFECYCLE_RULE"),
        [
            "AbortIncompleteMultipartUpload",
            "DelMarkerExpiration",
            "Expiration",
            "Filter",
            "ID",
            "NoncurrentVersionExpiration",
            "NoncurrentVersionTransition",
            "Prefix",
            "Status",
            "Transition",
        ]
    );
}

/// Negative — every encoder that writes an XML document turns the layout on from the view, a
/// payload root drops the namespace only under it, and a structure whose model order already is
/// legacy RustFS's gets no rendered order.
#[test]
fn n_the_layout_reaches_every_document_and_only_differing_orders_are_rendered() {
    let artifacts = artifacts();
    let mut documents = 0;
    for (path, text) in &artifacts.files {
        if !path.to_string_lossy().contains("generated/codec/ops/") {
            continue;
        }
        let writers = text.matches("rustfs_gateway_xml::XmlWriter::document();").count();
        let layouts = text
            .matches("writer.legacy_layout(request.rustfs_response_layout());")
            .count();
        assert_eq!(writers, layouts, "{}", path.display());
        documents += writers;
        for (name, order) in orders(text) {
            assert!(
                text.contains(&format!("writer.order_children(rustfs_order::{name});")),
                "{name} is never used"
            );
            let mut sorted = order.clone();
            sorted.dedup();
            assert_eq!(sorted.len(), order.len(), "{name} names an element twice");
        }
    }
    assert!(documents >= 40, "only {documents} response documents");

    let replication = codec_file(&artifacts, "GetBucketReplication");
    assert!(replication.contains("let xmlns = if request.rustfs_response_layout() {"), "{replication}");
    let lifecycle = codec_file(&artifacts, "GetBucketLifecycleConfiguration");
    assert!(!lifecycle.contains("let xmlns = if"), "an operation's own root keeps its namespace");

    let accelerate = orders(&codec_file(&artifacts, "GetBucketAccelerateConfiguration"));
    assert!(accelerate.is_empty(), "{accelerate:?}");
}

/// Positive — under the layout the attributes answer is rooted where the legacy stack roots it, and
/// elsewhere where AWS documents it; every legacy root named is one the gateway's root differs from.
#[test]
fn the_attributes_answer_is_rooted_as_the_legacy_stack_roots_it_under_the_layout() {
    let artifacts = artifacts();
    let attributes = codec_file(&artifacts, "GetObjectAttributes");
    assert!(
        attributes.contains(
            "let root = if request.rustfs_response_layout() {\n            \"GetObjectAttributesResponse\"\n        } else {\n            \"GetObjectAttributesOutput\"\n        };"
        ),
        "{attributes}"
    );
    for (operation, legacy) in LEGACY_ROOTS {
        let ir = artifacts
            .operations
            .iter()
            .find(|ir| ir.operation == *operation)
            .unwrap_or_else(|| panic!("{operation} is generated"));
        assert_ne!(ir.xml.response_root.as_deref(), Some(*legacy), "{operation}: a stale legacy root");
    }
}

/// Negative — no response document writes an entity tag with the plain element call, which would
/// escape its quotes under the RustFS layout where legacy RustFS writes them as they are; every
/// other root keeps the one the IR names.
#[test]
fn n_every_entity_tag_is_written_with_the_entity_tag_call() {
    let artifacts = artifacts();
    let mut tags = 0;
    for (path, text) in &artifacts.files {
        if !path.to_string_lossy().contains("generated/codec/ops/") {
            continue;
        }
        for line in text
            .lines()
            .filter(|line| line.contains("value::render_etag(") && line.contains("writer."))
        {
            assert!(line.contains("writer.entity_tag_element"), "{}: {line}", path.display());
            tags += 1;
        }
        if !path.to_string_lossy().ends_with("get_object_attributes.rs") {
            assert!(!text.contains("let root = if request.rustfs_response_layout()"), "{}", path.display());
        }
    }
    assert!(tags >= 8, "only {tags} entity tags written");
}
