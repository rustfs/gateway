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

//! Closed carrier annotations for nested shape fields.
//!
//! Responsible for: parsing the closed carrier vocabulary.
//! NOT responsible for: checking resolved wire bindings.
//! Upstream: overlay loader. Downstream: code generation.

use crate::{Error, Result};

/// Dedicated representations for XML members whose wire text alone cannot express their states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCarrier {
    /// A DeleteObjects request Key that can carry a specific entry rejection.
    DeleteObjectKey,
    /// A DeleteObjects request ETag that can carry the strong-empty condition.
    DeleteObjectETag,
    /// A DeleteObjects error Key carrying the exact response echo.
    DeleteKeyEcho,
}

impl FieldCarrier {
    pub(super) fn parse(value: Option<&str>, operation_field: bool, context: &str) -> Result<Option<Self>> {
        let carrier = match value {
            None => return Ok(None),
            Some(_) if operation_field => {
                return Err(Error::Overlay(format!("{context}: carriers require a nested shape member")));
            }
            Some("delete_object_key") => Self::DeleteObjectKey,
            Some("delete_object_etag") => Self::DeleteObjectETag,
            Some("delete_key_echo") => Self::DeleteKeyEcho,
            Some(other) => return Err(Error::Overlay(format!("{context}: unknown carrier `{other}`"))),
        };
        Ok(Some(carrier))
    }
}
