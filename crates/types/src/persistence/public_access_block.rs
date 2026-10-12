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
//! Responsible for: rejecting nested elements in the four stored boolean fields.
//! NOT responsible for: HTTP policy or scalar rules in other configuration families.
//! Upstream: bounded XML nodes. Downstream: the Public Access Block persistence reader.

use rustfs_gateway_xml::XmlNode;

use super::{PersistenceCodecError, optional_child};

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
