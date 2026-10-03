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

//! The assembly's CORS settings: where bucket documents come from, the cache in front of them, and
//! the deployment's credential posture.
//!
//! Responsible for: [`ServiceBuilder::cors_source`], [`ServiceBuilder::cors_cache`],
//! [`ServiceBuilder::cors_policy`] and [`ServiceBuilder::answer_cors_as_legacy_rustfs`].
//! NOT responsible for: answering a preflight or decorating a response (`crate::service`'s CORS
//! stage), or caching (`crate::ext::cors`).
//! Upstream: `super::ServiceBuilder`. Downstream: `super::ServiceBuilder::build`, which wraps the
//! source in its cache.

use std::sync::Arc;

use rustfs_gateway_core::cors::CorsPolicy;

use super::ServiceBuilder;
use crate::ext::{CorsCacheConfig, CorsSource};

impl ServiceBuilder {
    /// Installs the source of bucket CORS documents. Defaults to [`NoCors`](crate::ext::NoCors),
    /// under which no preflight is ever allowed.
    ///
    /// The source is wrapped in [`CachedCorsSource`](crate::ext::CachedCorsSource) here and stored
    /// wrapped, which is the whole of the "no un-cached call path" property: this is the only
    /// setter, it takes a bare source, and nothing hands the inner one back. See `crate::ext::cors`
    /// for why an unauthenticated read that reaches storage once per request is an amplifier.
    #[must_use]
    pub fn cors_source(mut self, source: impl CorsSource) -> Self {
        self.cors_source = Arc::new(source);
        self
    }

    /// Tunes the mandatory CORS cache. Defaults to [`CorsCacheConfig::default`].
    #[must_use]
    pub const fn cors_cache(mut self, config: CorsCacheConfig) -> Self {
        self.cors_cache = config;
        self
    }

    /// Installs the deployment's credential posture for CORS.
    ///
    /// Defaults to "any origin the bucket's rules admit, no credentials". A policy that would
    /// pair a reflected origin with credentials cannot be constructed at all, so there is nothing
    /// for this setter to refuse — see `rustfs_gateway_core::cors::CorsPolicy::new`.
    #[must_use]
    pub fn cors_policy(mut self, policy: CorsPolicy) -> Self {
        self.cors_policy = policy;
        self
    }

    /// Answers CORS as legacy RustFS does, in place of this crate's own runtime
    /// (rustfs/gateway#1120).
    ///
    /// Every `OPTIONS` is answered before routing — `400` without `Origin` or
    /// `Access-Control-Request-Method` on `/` and on an S3 path, the bucket's rules or the
    /// deployment-wide fallback headers otherwise, `403` with no body when a bucket's rules admit
    /// nothing — and every other request carrying `Origin` has its answer decorated, refusals
    /// before authentication included, from the bucket named by its first path segment. See
    /// `crate::cors_legacy` for the whole of what RustFS does. [`Self::cors_policy`] is not
    /// consulted; the source and its cache still are.
    ///
    /// Off by default: the gateway's own runtime answers, with its uniform refusal. This switch
    /// gives that up for RustFS's answers — every one of them but the credentials legacy RustFS
    /// allows, which these answers never allow (`crate::cors_legacy` says why).
    #[must_use]
    pub fn answer_cors_as_legacy_rustfs(mut self, cors: crate::LegacyRustfsCors) -> Self {
        self.legacy_cors = Some(cors);
        self
    }
}
