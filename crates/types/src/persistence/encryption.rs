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

//! Responsible for: legacy XML text and scalar readers for persisted Bucket Encryption.
//! NOT responsible for: wire XML or other persistence configuration families.
//! Upstream: stored XML bytes. Downstream: the Bucket Encryption persistence reader.

use rustfs_gateway_xml::{XmlLimits, XmlNode, parse_legacy_persistence_with_limits};

use super::{PersistenceCodecError, optional_child};

pub(super) fn parse_root(input: &[u8]) -> Result<XmlNode, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_legacy_persistence_with_limits(input, limits)?;
    if root.name != "ServerSideEncryptionConfiguration" {
        return Err(PersistenceCodecError::WrongRoot);
    }
    Ok(root)
}

pub(super) fn optional_text(parent: &XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
    optional_child(parent, name)?
        .map(|child| {
            if !child.children.is_empty() {
                return Err(PersistenceCodecError::UnexpectedScalarElement);
            }
            Ok(child.text.clone())
        })
        .transpose()
}
