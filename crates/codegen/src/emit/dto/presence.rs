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

//! The list members whose presence is a fact of their own (rustfs/gateway#1078).
//!
//! Responsible for: [`carries_presence`] — a wrapped list the legacy stack holds as an `Option`,
//! whose empty wrapper and whose absence are two different documents on the legacy wire, so its
//! DTO member is `Option<Vec<_>>` rather than the bare container every other list is (the
//! exception to ADR-0004 P1 that ADR-0037 records).
//! NOT responsible for: how a present or absent list is read, written or converted (the codec and
//! seam emitters, which consult this).
//! Upstream: the IR, the seam generator's checked-in legacy facts. Downstream: every emitter that
//! spells or fills such a member.

use rustfs_gateway_model::ir::{Binding, Field, Type};

use super::naming;

/// Whether `owner`'s member `field` is a list whose presence is carried: a wrapped list in an XML
/// document — one with an element of its own around its entries — that the legacy structure named
/// `owner` holds as an `Option`. A flattened list has no element of its own, so its absence and
/// its emptiness are the same document; a list the legacy stack does not have, or holds bare,
/// stays a bare container.
#[must_use]
pub fn carries_presence(owner: &str, field: &Field) -> bool {
    let in_document = matches!(field.binding, Binding::BodyXml | Binding::Payload);
    if field.required || !in_document || !matches!(field.ty, Type::List { flattened: false, .. }) {
        return false;
    }
    let Ok(facts) = crate::emit::seam::legacy_facts() else {
        return false;
    };
    let name = naming::field_name(&field.name);
    facts
        .structs
        .get(owner)
        .and_then(|members| members.iter().find(|(member, _)| *member == name))
        .is_some_and(|(_, ty)| ty.unwrap_option().1)
}
