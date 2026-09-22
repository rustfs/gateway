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

//! Responsible for: retaining transport-installed values behind an owned, read-only view.
//! NOT responsible for: authentication, header decoding, or the values' internal synchronization.
//! Upstream: the accepted HTTP request. Downstream: handler request context and typed adapters.

use core::fmt;
use std::sync::Arc;

/// Transport-installed values retained without exposing a mutable extension bag.
///
/// Clones share the original values, including their identity; they never clone an individual
/// extension. Empty bags require no allocation. Only typed shared lookup is exposed: a caller
/// cannot insert, remove, or replace entries through this view. A stored value may itself provide
/// interior mutability, whose synchronization and semantics remain that value's responsibility.
#[derive(Clone, Default)]
pub struct TransportExtensions(Option<Arc<http::Extensions>>);

impl TransportExtensions {
    pub(crate) fn from_extensions(extensions: http::Extensions) -> Self {
        if extensions.is_empty() {
            Self(None)
        } else {
            Self(Some(Arc::new(extensions)))
        }
    }

    /// Borrows the transport value of type `T`, when that type was installed before acceptance.
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0.as_ref().and_then(|extensions| extensions.get::<T>())
    }
}

impl fmt::Debug for TransportExtensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportExtensions(<redacted>)")
    }
}
