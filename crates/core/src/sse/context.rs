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

//! Responsible for: the bounded JSON string-pair shape required by ADR-0019.
//! NOT responsible for: base64, the decoded byte ceiling, KMS meaning or error rendering.
//! Upstream: the shared SSE managed-channel validator after its byte and UTF-8 guards.
//! Downstream: a boolean verdict; parsed context data and diagnostics never leave this module.

use std::collections::BTreeSet;

use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};

struct StringPairs;

impl<'de> Deserialize<'de> for StringPairs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(Self)
    }
}

impl<'de> Visitor<'de> for StringPairs {
    type Value = Self;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an object with unique string keys and string values")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self, M::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(M::Error::custom("duplicate context key"));
            }
            // Reject a container at its opening token instead of traversing nested values.
            let _value = map.next_value::<String>()?;
        }
        Ok(Self)
    }
}

pub(super) fn is_valid(bytes: &[u8]) -> bool {
    // from_slice also requires end of input after optional JSON whitespace.
    serde_json::from_slice::<StringPairs>(bytes).is_ok()
}
