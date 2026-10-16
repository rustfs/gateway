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

//! Public Access Block persistence scalar checks.
//!
//! Responsible for: legacy text decoding and nested-element checks for stored boolean fields.
//! NOT responsible for: HTTP policy or scalar rules in other configuration families.
//! Upstream: stored XML bytes. Downstream: the Public Access Block persistence reader.

use rustfs_gateway_xml::{XmlLimits, XmlNode, parse_legacy_persistence_with_limits};

use super::{PersistenceCodecError, optional_child};

/// Keeps the historical text interpretation local to persisted Public Access Block.
pub(super) fn parse_root(input: &[u8]) -> Result<XmlNode, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_legacy_persistence_with_limits(input, limits)?;
    if root.name != "PublicAccessBlockConfiguration" {
        return Err(PersistenceCodecError::WrongRoot);
    }
    Ok(root)
}

pub(super) fn optional_bool_child(parent: &XmlNode, name: &str) -> Result<Option<bool>, PersistenceCodecError> {
    let Some(child) = optional_child(parent, name)? else {
        return Ok(None);
    };
    if !child.children.is_empty() {
        return Err(PersistenceCodecError::UnexpectedScalarElement);
    }
    match child.text.as_str() {
        "true" | "TRUE" => Ok(Some(true)),
        "false" | "FALSE" => Ok(Some(false)),
        _ => Err(PersistenceCodecError::InvalidBoolean),
    }
}
