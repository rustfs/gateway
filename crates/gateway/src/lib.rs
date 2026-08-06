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

//! A protocol-exact, security-first S3 server framework for Rust.
//!
//! Responsible for: the public facade — [`ServiceBuilder`], the non-generic [`S3Service`], the
//! hyper and tower adapters, the extension points a deployment mounts, and the re-exports that let
//! a consumer depend on this crate alone.
//! NOT responsible for: storage semantics or IAM policy evaluation, which belong to the user; the
//! protocol kernel, which is `rustfs-gateway-core`, `-sig` and `-http`; or listening on a socket,
//! which is P7-02's.
//! Upstream: `rustfs-gateway-core`. Downstream: application code, the conformance suite, and
//! RustFS's HTTP boundary.
//!
//! # Assembling one
//!
//! ```no_run
//! use std::sync::Arc;
//! use rustfs_gateway::{Credentials, RegionSet, ServiceBuilder, SigV4Authenticator, StaticCredentials, allow_when};
//! # use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req};
//! # use rustfs_gateway::dto::{ListBuckets, ListBucketsOutput};
//! # struct Fs;
//! # impl Handler<ListBuckets> for Fs {
//! #     fn call(&self, _: Req<ListBuckets>) -> impl core::future::Future<Output = HandlerResult<ListBuckets>> + Send {
//! #         async { Err(HandlerError::not_implemented("example")) }
//! #     }
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret")?));
//! let service = ServiceBuilder::new()
//!     .register::<ListBuckets, _>(Arc::new(Fs))
//!     .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"])?))
//!     .authorizer(allow_when(|request| !request.is_anonymous()))
//!     .build()?;
//! # let _ = service;
//! # Ok(())
//! # }
//! ```
//!
//! # What this crate re-exports, and why it re-exports so much
//!
//! A backend implements [`Handler`] for operation types declared in `rustfs-gateway-types`, using
//! request and response types declared in the same place, and returns errors declared in
//! `rustfs-gateway-core`. Making it depend on four crates to write one handler would mean four
//! version constraints for one API, so the facade publishes the whole surface a consumer needs.
//! The conformance suite depends on this crate and on nothing else internal, and
//! `scripts/check_layer_dependencies.sh` enforces that — so anything the suite needs has to be
//! here.
//!
//! # The two async policies, in one sentence each
//!
//! Every extension point held as `Arc<dyn _>` writes its async methods as hand-written
//! [`BoxFuture`], because RPITIT is measurably not dyn compatible. [`Handler`] and `Operation` are
//! the only exceptions, because registration erases them behind a closure and neither is ever
//! reached through `dyn`. ADR-0002 is the full statement, and this crate re-exports the
//! [`BoxFuture`] alias so that no downstream crate takes a dependency on `futures` to name it.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod adapt;
mod assembly;
mod builder;
mod clock;
mod dispatch;
mod ext;
mod render;
mod service;
mod stamp;
mod trace;
mod transport;
mod wire;

pub mod sig;

pub use crate::adapt::ServiceFuture;
pub use crate::assembly::{AssemblyError, RuleRef};
pub use crate::builder::{DEFAULT_MAX_BUFFERED_BODY_BYTES, ServiceBuilder};
pub use crate::clock::{Clock, FixedClock, system_clock};
pub use crate::ext::{
    Authentication, Authenticator, Authorizer, AuthzRequest, CredentialProvider, Credentials, CredentialsError, Denial, Governor,
    GovernorRequest, HostQuery, HostResolver, Lease, NoObserver, Observer, PathStyleOnly, RequestEvent, ResolvedHost,
    SigV4Authenticator, StaticCredentials, Unavailable, Unlimited,
};
pub use crate::render::{S3Error, declaration, document, render};
pub use crate::service::S3Service;
pub use crate::trace::{
    FixedTrace, HOST_ID_HEADER, HostId, MintedTraces, REQUEST_ID_HEADER, RequestId, RequestTrace, TraceSource,
};
pub use crate::transport::Transport;
pub use crate::wire::{OrderedHeaders, WireResponse, collect};

/// The generated request and response types, and the operation markers they belong to.
///
/// Re-exported as a module rather than item by item: there are seventy-three operations and three
/// types each, and a facade that listed them would be a list to keep in sync with a generator.
pub use rustfs_gateway_types::dto;

// The kernel surface a backend and a test harness have to name. Re-exported rather than reached
// for directly, because `scripts/check_layer_dependencies.sh` allows the conformance suite to
// depend on this crate and on nothing else internal.
pub use rustfs_gateway_core::{
    ArnForm, AuthRequirement, BoxFuture, CodecError, ELEMENT_ORDER, EncodedResponse, ErrorDetail, ErrorHeader, Handler,
    HandlerError, HandlerResult, HostClass, MetaView, MissingHandlers, Operation, OperationCodec, OperationSet, OperationSpec,
    PRECONDITION_FAILED_MESSAGE, ParamKind, PreAuthError, Predicate, RANGE_NOT_SATISFIABLE_MESSAGE, Req, RequestBody,
    RequiredParam, ResourceShape, Resp, ResponseBody, ResponseOverride, RouteEntry, RouteSelector, TargetKind,
};
// The pagination contract. Found unreachable by check_shared_reachable.sh the moment that
// guard existed — the fourth contract in a row written for backends and left where no
// backend could see it. key_count is the KeyCount = Contents + CommonPrefixes rule that
// made OpenDAL page forever when a listing got it wrong.
pub use rustfs_gateway_core::ops::shared::pagination::{CursorKind, CursorSpec, MAX_CURSOR_BYTES, key_count};

// The conditional-request and entity-tag contracts, exported for the same reason as
// copy_source below: the conformance fixture had written its own `evaluate_conditions`
// by hand, because it could not reach this one. That mirror got strong/weak comparison
// wrong, evaluated existence before the condition, and missed the If-Match suppression
// of If-Modified-Since — four RFC 9110 rules re-derived and re-broken, while a correct
// implementation sat one crate away and unreachable.
//
// The evaluation cannot live in `ops/*.rs`: those hold a static OperationSpec settled
// before the request is read, and evaluate() needs the representation the handler
// resolved. So the backend is the only place it can run, and the backend can only run
// what the facade exports.
pub use rustfs_gateway_core::ops::shared::etag::{ConditionalHeader, EtagComparison, etag_matches, parse_conditional_etag};
pub use rustfs_gateway_core::ops::shared::precondition::{
    ConditionalOutcome, IfRange, ObjectValidators, PreconditionRejection, Preconditions, RangeDecision, RangeSelectors,
    RequestKind, evaluate, evaluate_range,
};

// The copy-source contract. Exported because a backend cannot honour it otherwise: the
// conformance fixture had to mirror `CopySource`, `authorize_source` and `classify_self_copy`
// by hand, and every backend outside this workspace would have done the same. A type state
// that only this workspace can reach is a type state that does not prevent the defect it was
// written for — GHSA-mx42 and GHSA-wfxj were both a second implementation forgetting the
// check the first one made.
pub use rustfs_gateway_core::ops::shared::copy_source::{
    CopyRange, CopySource, CopySourceForm, CopySourceRejection, ResolvedCopySource, SelfCopy, SourceAccess, SourceAuthorized,
    SourceResource, authorize_source, classify_self_copy, resolve_copy_range,
};
pub use rustfs_gateway_http::{EffectiveHost, Limits, WireReject, WireRequest};
pub use rustfs_gateway_sig::{Identity, OperationFloor, RegionSet, SecurityFloor, SigService, SkewWindow, Verdict};
pub use rustfs_gateway_stream::{Body, ByteStream, Payload, TrailingHeaders};
// `ETag`, `Timestamp` and the checksum types are here because a backend cannot answer without
// them: `Object`, `ObjectVersion`, `Part` and `Bucket` all require one, so without these a
// listing entry is unbuildable and `PutObject` cannot return an etag from outside this
// workspace. The conformance suite found this — 58 cases were failing behind two missing lines
// while `REQUIRED_FACADE_EXPORTS` was satisfied to the letter. A facade that exports the
// service but not the values the service returns is not a facade.
pub use rustfs_gateway_types::{
    BucketName, ChecksumAlgorithm, ChecksumDigest, ChecksumSpec, ChecksumType, ETag, ErrorCode, ObjectKey, Timestamp,
};

pub use crate::ext::allow_when;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;

    /// A backend that answers exactly one operation, and answers it with a refusal.
    ///
    /// Enough to assemble a service, which is all the tests in this crate need: what they assert
    /// is the assembly and the pipeline, never a storage behaviour.
    pub(crate) struct NoBackend;

    impl Handler<dto::ListBuckets> for NoBackend {
        async fn call(&self, _request: Req<dto::ListBuckets>) -> HandlerResult<dto::ListBuckets> {
            Err(HandlerError::not_implemented("this backend stores nothing"))
        }
    }

    /// The smallest service this crate can build.
    pub(crate) fn minimal_service() -> S3Service {
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
        ServiceBuilder::new()
            .register::<dto::ListBuckets, _>(Arc::new(NoBackend))
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
            .authorizer(allow_when(|_| true))
            .build()
            .expect("a complete assembly")
    }
}
