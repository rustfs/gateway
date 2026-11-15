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

//! Responsible for: registering the PostObject adapter and rejecting incompatible assemblies.
//! NOT responsible for: authorizing requests or running handlers.
//! Upstream: ServiceBuilder. Downstream: router and operation dispatch.

use std::sync::Arc;

use super::ServiceBuilder;
use crate::dispatch::OperationDispatch;
use crate::dispatch::post_object_handler::PostObjectAdapter;
use crate::dto::PostObject;
use crate::routing::RoutingSnapshot;
use crate::{AssemblyError, Operation, PostObjectHandler, RuleRef};

impl ServiceBuilder {
    /// Register PostObject with host authorization before success-control validation and storage.
    ///
    /// Assembly requires the legacy form profile. A PostObject operation layer, monomorphic
    /// dispatch, or another registration for PostObject is refused.
    #[must_use]
    pub fn register_post_object_after_authorization<H: PostObjectHandler>(mut self, handler: Arc<H>) -> Self {
        let adapter = Arc::new(PostObjectAdapter(handler));
        self.router = self.router.handle::<PostObject, _>(Arc::clone(&adapter));
        self.pending.entry(PostObject::NAME).or_insert_with(|| {
            Box::new(move |layers| {
                if !layers.is_empty() {
                    return Err(refusal("PostObject authorization cannot have a PostObject operation layer"));
                }
                Ok(OperationDispatch::post_object_after_authorization(adapter))
            })
        });
        self
    }
}

pub(super) fn validate_staged_post(
    routing: &RoutingSnapshot,
    legacy_forms: bool,
    monomorphic: bool,
) -> Result<(), AssemblyError> {
    let staged = routing
        .dispatch
        .get(PostObject::NAME)
        .is_some_and(OperationDispatch::defers_post_object_success_check);
    if staged && monomorphic {
        return Err(refusal("PostObject authorization requires dynamic dispatch"));
    }
    if staged && !legacy_forms {
        return Err(refusal("PostObject authorization requires the legacy form profile"));
    }
    Ok(())
}

fn refusal(reason: &'static str) -> AssemblyError {
    AssemblyError::PostObjectAuthorization {
        reason,
        rule: RuleRef::POST_OBJECT_AUTHORIZATION,
    }
}
