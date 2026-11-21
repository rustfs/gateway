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

//! Construction of default and explicit signing-service scopes.
//!
//! Responsible for: selecting the core router's immutable signing-service scope.
//! NOT responsible for: listener dispatch, authentication, or protocol codecs.
//! Upstream: embedding hosts. Downstream: the ordinary service assembly and request pipeline.

use rustfs_gateway_core::RouterBuilder;
use rustfs_gateway_sig::SigService;

use super::ServiceBuilder;

impl Default for ServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceBuilder {
    /// Starts an independent signing service with no generated S3 route table.
    ///
    /// Only explicit dialect registrations assembled with
    /// [`rustfs_gateway_core::Dialect::assemble_for_service`] for `service` are accepted. Every
    /// registered operation must use this service and require SigV4 under every policy. Its
    /// authentication, authorization, body verification, and handler stages use the normal pipeline.
    ///
    /// A host serving several signing services chooses their instances before calling them and
    /// preserves the original request URI, query, headers, and body. The default [`Self::new`]
    /// keeps its ordinary S3 routes. Live registry and assembly updates must retain this scope.
    #[must_use]
    pub fn for_service(service: SigService) -> Self {
        Self {
            router: RouterBuilder::for_service(service),
            ..Self::new()
        }
    }
}
