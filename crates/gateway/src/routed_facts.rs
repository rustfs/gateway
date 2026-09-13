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

//! What routing decided about a request beyond its operation (ADR-0024): whether it is
//! service-level, the target every later stage addresses, whether its handler may hold the
//! caller's secret, and a claimed row's typed path values.
//!
//! Responsible for: [`RoutedFacts::of`], one pure function over the dispatch and the raw path.
//! NOT responsible for: routing (`rustfs-gateway-core`'s router), dropping the secret
//! (`crate::service`, on the line that reads the verdict), or rendering a refusal.
//! Upstream: `rustfs_gateway_core::Dispatch`, `crate::dispatch::target_of`. Downstream:
//! `crate::service`.
//!
//! # Why a claimed or service-level request has no bucket
//!
//! Inside a claim the path is not S3 addressing, and a `ResourceShape::Service` operation names no
//! resource a path could supply. Addressing either as `TargetKind::Service` is what keeps a
//! path-style `/rustfs/admin/…` from reaching the governor, both authorizer stages, the audit
//! event and the handler context as bucket `rustfs`. The raw path is untouched, so the signature
//! and the context still read it exactly as it arrived.

use rustfs_gateway_core::{CodecError, Dispatch, PathParams, ResourceShape, TargetKind};

use crate::dispatch::target_of;

/// What the pipeline reads from the routed row and the operation's own spec, once.
pub(crate) struct RoutedFacts {
    /// No bucket and no key reach any later stage.
    pub(crate) service_level: bool,
    /// The target every later stage addresses: `Service` for a service-level request.
    pub(crate) target: TargetKind,
    /// Whether the routed operation opted in to the caller's secret.
    pub(crate) hands_caller_secret: bool,
    /// The claimed row's decoded values; none outside a claim.
    pub(crate) path_params: PathParams,
}

impl RoutedFacts {
    /// The facts of one dispatched request.
    ///
    /// # Errors
    ///
    /// A `400 InvalidArgument` naming the path parameter whose value no handler may be handed. The
    /// message is a constant and never carries the value.
    pub(crate) fn of(dispatched: &Dispatch<'_>, raw_path: &str) -> Result<Self, CodecError> {
        let service_level = dispatched.claimed.is_some()
            || dispatched
                .spec
                .auth
                .is_some_and(|auth| auth.resource == ResourceShape::Service);
        let path_params = match dispatched.claimed {
            Some(claimed) => claimed.template().extract(raw_path).map_err(|error| {
                let refusal = CodecError::invalid_argument(error.message());
                match error.name() {
                    Some(name) => refusal.about(name),
                    None => refusal,
                }
            })?,
            None => PathParams::none(),
        };
        Ok(Self {
            service_level,
            target: if service_level {
                TargetKind::Service
            } else {
                target_of(dispatched.entry)
            },
            hands_caller_secret: dispatched.spec.receives_caller_secret(),
            path_params,
        })
    }
}
