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

//! Operations, routing, the typed pipeline, and the extension points.
//!
//! Responsible for: `Operation`/`OperationSpec`, the ordered route table, the type-state
//! pipeline, and every extension trait (`Authorizer`, `HostResolver`, `Governor`, ...).
//! NOT responsible for: HTTP transport assembly (that is the `rustfs-gateway` facade).
//! Upstream: `rustfs-gateway-sig`. Downstream: `rustfs-gateway`.
//!
//! # What P4-01 to P4-03 and P4-06 landed
//!
//! ```text
//!   route      which operation a request names — decided before anything is authenticated
//!   registry   what that operation requires of the request, and whether this backend handles it
//!   error      what may be said about a request from a caller nobody has identified yet
//!   fault      what a refusal may add to itself: two closed sets, headers and document elements
//!   dispatch   the three questions in order, each with its own failure
//!   op         what an operation is as a type: name, origin, input, output, authorisation
//!   ops        one AWS operation per file
//!   handler    what a backend implements for one operation
//! ```
//!
//! # Registering a backend
//!
//! The hand-written form, which always works and which the macro produces verbatim:
//!
//! ```ignore
//! impl Handler<GetBucketLocation> for Fs {
//!     fn call(&self, req: Req<GetBucketLocation>) -> impl Future<Output = HandlerResult<GetBucketLocation>> + Send {
//!         self.get_bucket_location(req)
//!     }
//! }
//!
//! let router = RouterBuilder::new()
//!     .handle::<GetBucketLocation, _>(Arc::clone(&fs))
//!     .handle::<PutObject, _>(Arc::clone(&fs))
//!     .require(&OperationSet::of(["GetBucketLocation", "PutObject"]))?
//!     .build()?;
//! ```
//!
//! An operation with no handler is answered with `501`, so a backend implementing two of the
//! seventy-three compiles and runs. Nothing has 73 default methods, and nothing needs a bundle
//! trait: completeness is asserted where a deployment wants it, by `require`.
//!
//! Each `handle` call also installs the operation's wire codec, because it is the only place that
//! holds the operation type and its name at once. Everything above the registry then works from a
//! name: `Registry::wire("GetObject")` yields the spec, the decoder, the handler and the encoder,
//! all four from the same registration. An operation whose wire form this crate does not define —
//! a dialect or an admin call — registers through `handle_without_codec`, which says so at the
//! call site and is reported afterwards by `HandlerTable::names_without_codec`.
//!
//! A whole surface of them — an admin API, an STS endpoint, a vendor query key — arrives as a
//! `dialect::Dialect`: a value carrying one route row per operation it adds, checked against a
//! hand-written overlay that records the same facts where a reviewer reads them. Installing one is
//! `RouterBuilder::dialect`. What a dialect may and may not do is `docs/dialects.md`; the short
//! version is that it may only *add*, its names must be `vendor:Name`, and a row that stands in
//! front of an AWS one needs a declaration with a reason and a source.
//!
//! Three properties hold this together. Everything else here exists to serve them.
//!
//! 1. **Routing is ordered, not disjoint.** `GET /bucket?acl&tagging` names two subresources and
//!    AWS answers it, picking one by a fixed internal order. A table that refuses to start unless
//!    no two selectors overlap either rejects that request or needs quadratically many `Absent`
//!    predicates, which AWS invalidates every time it adds a subresource. So entries carry a
//!    `precedence` and the first match wins. What stays forbidden is an overlap *within* one
//!    precedence, where the winner would be decided by sort order — an accident nobody reviewed.
//! 2. **Overlap is decided, not compared.** `GET /b?acl` and `GET /b` are not equal, share no
//!    query key, and one of them is dead. The build normalises each selector into constraints over
//!    independent dimensions, meets them, and — when the meet is non-empty — materialises a
//!    concrete request and runs it back through the ordinary matcher. The decision procedure is
//!    checked by the thing it is about, so a bug in it cannot quietly report "no conflict".
//! 3. **Routing decides which operation, and nothing else.** A missing required parameter is a
//!    `400` from the operation that was already selected, never a `501`. Encoding requiredness as
//!    a routing predicate turns a client's parameter mistake into "this service does not support
//!    that operation", and clients act on that by disabling the feature rather than fixing the
//!    request.
//!
//! Everything on the pre-authentication path is non-`async`, holds no store handle, allocates
//! nothing per request, and can say nothing about the request beyond a compile-time constant.
//! `tests/purity_guard.rs` asserts each of those over the source.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

pub mod authz;
pub mod cancellation;
pub mod codec;
mod committed;
mod contracts;
pub mod cors;
pub mod dialect;
pub mod dispatch;
pub mod error;
mod error_resolution;
pub mod fault;
pub mod handler;
pub mod op;
pub mod ops;
pub mod registry;
mod request_context;
pub mod route;
pub mod sse;
mod static_dispatch;

pub use crate::authz::{
    Authorized, AuthorizedRead, Decision, Denied, DerivedResourceError, DerivedResourceSet, NoDerived, OwnedResource,
    ResourceIdentity, ResourceRef,
};
pub use crate::cancellation::{HandlerCancellation, HandlerCancellationSource, HandlerContext};
pub use crate::codec::{
    BodyAllowance, CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody,
    ResponseOverride, body_allowance, override_header_value, response_body_allowed, response_framing_allowed,
};
pub use crate::committed::{CommitOutcome, CommitWork, CommittedResponse, DeferredOperation, HeadPart, HeadPartError};
pub use crate::contracts::{copy_source_guards_before_target_write, copy_source_if_match_miss_proceeds, error_root_namespace};
pub use crate::dialect::{
    ClaimedOperation, ClaimedRoute, ClaimedRow, Dialect, DialectBuilder, DialectError, DialectOperation, DialectOverlay,
    DialectRoute, OverlayRow,
};
pub use crate::dispatch::{Dispatch, Router, RouterBuildError};
pub use crate::error::{DisallowedPreAuthCode, PRE_AUTH_STATUSES, PreAuthError};
pub use crate::error_resolution::{
    BodyPolicy, ErrorContext, ErrorResolution, HandlerErrorContext, InvalidErrorContext, MissingObject, ResourceVisibility,
    ResponseKind, resolve,
};
pub use crate::fault::{
    ELEMENT_ORDER, ErrorDetail, ErrorHeader, HttpDate, InvalidWireLabel, PRECONDITION_FAILED_MESSAGE,
    RANGE_NOT_SATISFIABLE_MESSAGE, RedirectTarget, RegionLabel,
};
pub use crate::handler::{Answer, BoxFuture, Handler, HandlerError, HandlerResult, Req, Resp};
pub use crate::op::{
    AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation, is_standard_operation_name,
    standard_operation_names,
};
pub use crate::registry::{
    BuildError, ErasedAuthorize, ErasedCodec, ErasedDecode, ErasedDecoded, ErasedEncode, ErasedHandler, ErasedRequest,
    ErasedResources, ErasedResponse, HandlerDeadlineClass, HandlerTable, Invocation, MissingHandlers, OperationSet,
    OperationSpec, ParamKind, Registry, RegistryError, RequiredParam, RouterBuilder, WireEntry, check_required,
    erase_authorized_handler,
};
pub use crate::request_context::{
    Addressed, AddressingStyle, AuthenticatedScheme, CallerSecretKey, RequestContextView, RequestPrincipal,
};
pub use crate::route::{
    ArnForm, ClaimedEntry, ClaimedTable, CompileError, CompiledRouter, Explanation, HostClass, InstalledClaim, OpId, PathClaim,
    PathParamError, PathParams, PathTemplate, Predicate, RequestShape, RouteBuildError, RouteEntry, RouteRequestParts,
    RouteSelector, RouteTable, ShadowingDecl, ShadowingDecls, ShadowingPolicy, TargetKind,
};
pub use crate::sse::{
    KeyFingerprint, KeySide, PartRejection, PlaintextCustomerKeyAck, SseConfig, SseEnforced, SseRejection, TransportSecurity,
};
pub use crate::static_dispatch::{
    StaticCommittedError, StaticCommittedResponse, StaticDispatchError, StaticDispatchOutcome, StaticOperation,
};
