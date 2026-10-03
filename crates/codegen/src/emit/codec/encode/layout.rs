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

//! The rest of the legacy RustFS response layout the encoders render (rustfs/gateway#1078): the
//! element an answer is rooted at, and the call an entity tag is written with.
//!
//! Responsible for: [`LEGACY_ROOTS`], and the `XmlWriter` call a scalar member is written with.
//! NOT responsible for: the member order (`super::order`), or honouring any of it at run time
//! (`rustfs_gateway_xml::XmlWriter` under its legacy layout).
//! Upstream: the IR. Downstream: the parent's encoders and shape writers, and
//! `super::order::open_root`.

use rustfs_gateway_model::ir::{EmptyValue, OperationIr, Type};

/// The operations whose answer the legacy stack roots at another element than the gateway's
/// `xml.response_root`, with that element: the legacy writer roots every output at its model
/// `xmlName`, and the gateway roots the attributes answer at the element AWS documents instead
/// (`q-attributes-root-0087`).
pub const LEGACY_ROOTS: &[(&str, &str)] = &[("GetObjectAttributes", "GetObjectAttributesResponse")];

/// The element the legacy stack roots `ir`'s answer at, when it is not the gateway's.
#[must_use]
pub fn legacy_root_name(ir: &OperationIr) -> Option<&'static str> {
    LEGACY_ROOTS
        .iter()
        .find(|(operation, _)| *operation == ir.operation)
        .map(|(_, root)| *root)
        .filter(|root| ir.xml.response_root.as_deref() != Some(*root))
}

/// The `XmlWriter` method one scalar body member is written with.
///
/// `empty_value_policy` chooses between writing an empty value as a paired element and dropping
/// it. Escaping is one rule, S3's, which escapes both quotes in every text node (rustfs/gateway#13)
/// — with one exception the type decides: an entity tag is written with `entity_tag_element`,
/// which under the RustFS response layout writes the tag's quotes as they are, as legacy RustFS
/// writes them, and outside it escapes them as every other text node.
#[must_use]
pub fn element_call(ty: &Type, policy: EmptyValue) -> &'static str {
    match (ty, policy) {
        (Type::ETag(_), EmptyValue::Emit) => "entity_tag_element",
        (Type::ETag(_), EmptyValue::Omit) => "entity_tag_element_if_present",
        (_, EmptyValue::Emit) => "element",
        (_, EmptyValue::Omit) => "element_if_present",
    }
}
