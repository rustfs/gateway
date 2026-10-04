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

//! The operation a request head is dispatched to, without serving it (rustfs/gateway#1141).
//!
//! Responsible for: [`S3Service::classify`] and its answer, [`Classification`]: every step
//! [`S3Service::call`] takes before it authenticates — the `GET //` reading, the stage filters'
//! wire seam, acceptance, host resolution, the CORS preflight split, the RustFS profile's
//! pre-routing judgement, routing and the routed facts — taken in the same order on a copy of the
//! head, so an embedding host, a proxy or a debugging tool learns what the service will do with a
//! request before it forwards it.
//! NOT responsible for: authentication, authorization, the body, or anything a handler decides:
//! a request classified as an operation can still be refused by any of them.
//! Upstream: `crate::service`'s stages. Downstream: embedding hosts.
//!
//! # Why it is kept beside the pipeline and not inside it
//!
//! `S3Service::call` interleaves these steps with the floors, the preflight answer and the
//! outcome record, and is the one file that knows where a stage ends. This walks the same steps
//! with the same functions and stops at the first answer; `tests/classification.rs` holds it to
//! `call` over every request shape the RustFS profile distinguishes, so a step added to one and
//! not the other fails there rather than in production.

use http::Request;
use http::request::Parts;
use rustfs_gateway_core::cors::{
    PreflightClass, classify as classify_preflight, invalid_target_is_uniform_refusal, preflight_bypasses_pipeline,
};
use rustfs_gateway_core::error::PreAuthError;
use rustfs_gateway_core::{ResponseKind, RouteRequestParts};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::ext::{HostQuery, WireHead};
use crate::render::{S3Error, from_codec, from_handler, from_pre_auth, from_wire_reject};
use crate::routed_facts::RoutedFacts;
use crate::service::S3Service;

/// What [`S3Service::classify`] found a request head to be.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Classification {
    /// The service dispatches the request to this operation, by its S3 or dialect name.
    Operation(&'static str),
    /// A CORS preflight, which the service answers itself before routing.
    Preflight,
    /// An object-path form without an operation under the RustFS selector. Its bounded
    /// multipart metadata and signature must be read before the service can choose its refusal.
    /// No handler is dispatched, whatever that refusal is.
    UnroutedPostForm,
    /// Refused before any operation is chosen, with the status and code the service answers.
    Refused {
        /// The status.
        status: http::StatusCode,
        /// The error code, when the answer carries one.
        code: Option<ErrorCode>,
    },
}

impl Classification {
    fn refused(error: &S3Error) -> Self {
        Self::Refused {
            status: error.status(),
            code: error.code().cloned(),
        }
    }
}

impl S3Service {
    /// The operation this service dispatches a request with `head` to, decided by every step
    /// [`S3Service::call`] takes before it authenticates, in the same order, on a copy of the head.
    ///
    /// Nothing is authenticated or authorized, no body is read, no handler runs and nothing is
    /// recorded: [`Classification::Operation`] names the operation the request is routed to, which
    /// can still refuse it — its bucket or key once decoded, authentication, authorization, the
    /// body. The assembly's stage filters see the copy as they would see the request.
    #[must_use]
    pub fn classify(&self, head: &Parts) -> Classification {
        let snapshot = self.inner.config.load_full();
        let runtime = snapshot.runtime();
        let router = &runtime.routing.router;
        let kind = if head.method == http::Method::HEAD {
            ResponseKind::Head
        } else {
            ResponseKind::Other
        };
        let mut parts = copy(head);
        crate::legacy_addressing::rewrite_double_slash_root(&self.inner.names, &mut parts);
        if !runtime.filters.is_empty() {
            let mut wire_head = WireHead::new(&mut parts);
            for filter in runtime.filters.iter() {
                if let Err(error) = filter.on_wire(&mut wire_head) {
                    return Classification::refused(&from_handler(error, kind, ConnectionIntent::MayKeepAlive));
                }
            }
        }
        let wire = match WireRequest::accept(Request::from_parts(parts, ()), &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => return Classification::refused(&from_wire_reject(reject)),
        };
        let resolved = self.inner.host_resolver.resolve(&HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        });
        match classify_preflight(wire.method(), &wire.headers()) {
            PreflightClass::NotPreflight => {}
            PreflightClass::HeaderlessOptions => {
                let refusal = PreAuthError::bad_request("An Origin header is required for this OPTIONS request");
                return Classification::refused(&from_pre_auth(refusal, kind));
            }
            PreflightClass::Malformed => return Classification::Preflight,
            PreflightClass::Preflight(_) => {
                let valid_target = crate::service::preflight_bucket(wire.raw_path().as_str(), &resolved).is_some();
                if preflight_bypasses_pipeline() && (invalid_target_is_uniform_refusal() || valid_target) {
                    return Classification::Preflight;
                }
            }
        }
        let resolver = &*self.inner.host_resolver;
        let resolved = match crate::legacy_addressing::classify(&self.inner.names, resolver, router, &wire, resolved) {
            Ok(resolved) => resolved,
            Err(refusal) => return Classification::refused(&from_codec(refusal, kind)),
        };
        let dispatched = match router.dispatch(&RouteRequestParts {
            method: wire.method(),
            path: wire.raw_path().as_str(),
            target: resolved.target,
            host_class: resolved.host_class,
            arn_form: resolved.arn_form,
            query: wire.query(),
            headers: wire.headers(),
            host_named_bucket: resolved.bucket().is_some(),
        }) {
            Ok(dispatched) => dispatched,
            Err(error) if crate::service::refused_post::applies_to(router, &wire, resolved.target, &error) => {
                return Classification::UnroutedPostForm;
            }
            Err(error) => return Classification::refused(&from_pre_auth(error, kind)),
        };
        match RoutedFacts::of(&dispatched, wire.raw_path().as_str(), wire.query().as_str(), &self.inner.names) {
            Ok(_) => Classification::Operation(dispatched.spec.name),
            Err(refusal) => Classification::refused(&from_codec(refusal, kind)),
        }
    }
}

/// A copy of a request head: `Parts` is not `Clone`, because its extensions are not.
fn copy(head: &Parts) -> Parts {
    let mut builder = Request::builder()
        .method(head.method.clone())
        .uri(head.uri.clone())
        .version(head.version);
    if let Some(headers) = builder.headers_mut() {
        *headers = head.headers.clone();
    }
    let (parts, ()) = builder.body(()).unwrap_or_default().into_parts();
    parts
}
