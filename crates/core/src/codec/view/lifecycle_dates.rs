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

//! Lifecycle date facts read from one validated request document.
//!
//! Responsible for: preserving normalized source date strings beside the decoded DTO.
//! NOT responsible for: lifecycle validation or timestamp representation.
//! Upstream: the bounded document codec. Downstream: typed dispatch and the handler context.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustfs_gateway_xml::XmlNode;

use super::MetaView;
use crate::CodecError;

/// The dates supplied in a RustFS-profile lifecycle request.
///
/// The strings retain the source offset and nanosecond precision. Rule and transition indices
/// match the decoded lists, including entries without a date.
pub struct LifecycleRequestDates {
    expiry_updated_at: Option<String>,
    rules: Vec<RuleDates>,
}

struct RuleDates {
    expiration: Option<String>,
    transitions: Vec<Option<String>>,
}

impl LifecycleRequestDates {
    /// The normalized `ExpiryUpdatedAt` date, if supplied.
    #[must_use]
    pub fn expiry_updated_at(&self) -> Option<&str> {
        self.expiry_updated_at.as_deref()
    }

    /// The normalized expiration date for the zero-based rule index, if supplied.
    #[must_use]
    pub fn expiration(&self, rule_index: usize) -> Option<&str> {
        self.rules.get(rule_index)?.expiration.as_deref()
    }

    /// The normalized date for the zero-based rule and transition indices, if supplied.
    #[must_use]
    pub fn transition(&self, rule_index: usize, transition_index: usize) -> Option<&str> {
        self.rules.get(rule_index)?.transitions.get(transition_index)?.as_deref()
    }

    fn from_document(root: &XmlNode) -> Self {
        let rules = root
            .children_named("Rule")
            .map(|rule| RuleDates {
                expiration: rule
                    .child("Expiration")
                    .and_then(|expiration| expiration.child_text("Date"))
                    .map(str::to_owned),
                transitions: rule
                    .children_named("Transition")
                    .map(|transition| transition.child_text("Date").map(str::to_owned))
                    .collect(),
            })
            .collect();
        Self {
            expiry_updated_at: root.child_text("ExpiryUpdatedAt").map(str::to_owned),
            rules,
        }
    }
}

impl fmt::Debug for LifecycleRequestDates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LifecycleRequestDates").finish_non_exhaustive()
    }
}

pub(super) type LifecycleDateCapture = Option<Mutex<Option<Arc<LifecycleRequestDates>>>>;

const CAPTURE_FAILED: CodecError = CodecError::internal("lifecycle request date capture failed");

impl MetaView<'_> {
    pub(crate) fn with_lifecycle_date_capture(&self) -> Self {
        let mut scoped = self.derive_with_framed_length(self.framed_content_length);
        scoped.lifecycle_date_capture = Some(Mutex::new(None));
        scoped
    }

    pub(crate) const fn captures_lifecycle_dates(&self) -> bool {
        self.lifecycle_date_capture.is_some()
    }

    pub(crate) fn capture_lifecycle_dates(&self, root: &XmlNode) -> Result<(), CodecError> {
        if let Some(slot) = &self.lifecycle_date_capture {
            let dates = Arc::new(LifecycleRequestDates::from_document(root));
            *slot.lock().map_err(|_| CAPTURE_FAILED)? = Some(dates);
        }
        Ok(())
    }

    pub(crate) fn into_lifecycle_request_dates(self) -> Result<Option<Arc<LifecycleRequestDates>>, CodecError> {
        self.lifecycle_date_capture
            .map(Mutex::into_inner)
            .transpose()
            .map(Option::flatten)
            .map_err(|_| CAPTURE_FAILED)
    }
}
