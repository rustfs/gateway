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
mod chunked;
mod clock;
pub mod close;
pub mod commit;
mod dispatch;
mod ext;
mod gate;
mod invariants;
mod probe;
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
pub use crate::close::ConnectionIntent;
pub use crate::ext::{
    Authentication, Authenticator, Authorizer, AuthzRequest, ChunkSink, ChunkVerification, CredentialProvider, Credentials,
    CredentialsError, Denial, Governor, GovernorRequest, HostQuery, HostResolver, Lease, NoObserver, Observer, PathStyleOnly,
    RequestEvent, ResolvedHost, SigV4Authenticator, StaticCredentials, Unavailable, Unlimited,
};
pub use crate::probe::{BodyProgress, ObservedBody};
pub use crate::render::{S3Error, connection_intent_of, declaration, document, document_body, render};
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
// `Answer`, `CommitOutcome` and `CommitWork` are here for the reason `ETag` and `Timestamp` were:
// `Resp::commit` is exported, so a backend outside this workspace can build a committed response —
// and then cannot name the type of the work it just handed over, cannot write a function returning
// one, and cannot match on what `into_parts` gives back. An exported constructor whose argument
// type is unnameable is the same defect as an unexported contract, one step further along.
pub use rustfs_gateway_core::{
    Answer, ArnForm, AuthRequirement, BoxFuture, CodecError, CommitOutcome, CommitWork, ELEMENT_ORDER, EncodedResponse,
    ErrorDetail, ErrorHeader, Handler, HandlerError, HandlerResult, HostClass, MetaView, MissingHandlers, Operation,
    OperationCodec, OperationSet, OperationSpec, PRECONDITION_FAILED_MESSAGE, ParamKind, PreAuthError, Predicate,
    RANGE_NOT_SATISFIABLE_MESSAGE, Req, RequestBody, RequiredParam, ResourceShape, Resp, ResponseBody, ResponseOverride,
    RouteEntry, RouteSelector, TargetKind,
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
// The CORS document contract. A backend stores what `PutBucketCors` hands it and the preflight
// runtime later answers browsers out of that store, so the rules for what may be stored — the
// closed method set, the wildcard budget, the hundred-rule cap — must be one implementation
// every backend calls, not a description every backend re-derives. The conformance fixture is
// the first caller; a backend that skipped validation would store a document whose rules the
// matcher can never satisfy, and the only symptom would be browser-side.
pub use rustfs_gateway_core::ops::shared::cors::{
    CORS_ALLOWED_METHODS, CorsRejection, MAX_CORS_ID_CHARS, MAX_CORS_RULES, validate_cors,
};

// The tagging contract. The tag set has two request channels — the `<Tagging>` document of the
// `?tagging` subresource and the packed `x-amz-tagging` header on PutObject, CopyObject and
// CreateMultipartUpload — and the count, length, character-set and duplicate-key rules must be
// one rule for both. The XML channel's syntax is the generated decoder's; everything semantic,
// and the whole of the header channel, is here, because a backend parses that header itself and
// an unexported parser is one every backend rewrites.
pub use rustfs_gateway_core::ops::shared::tagging::{
    MAX_BUCKET_TAGS, MAX_OBJECT_TAGS, MAX_TAG_KEY_CHARS, MAX_TAG_VALUE_CHARS, TagScope, TaggingRejection, parse_tagging_header,
    validate_tag_set,
};

// The lifecycle document contract, exported for the same reason as the CORS one above:
// what `PutBucketLifecycleConfiguration` may store — the filter's one-child grammar, the
// expiration mutex, the midnight rule, the thousand-rule cap, the id bounds — must be one
// implementation every backend calls. The stakes are higher here than for CORS: the scanner that
// reads this document deletes data, and validation deliberately stops at AWS's documented
// refusals so that a stored document is never refused by a later release (`q-lc-0014`).
pub use rustfs_gateway_core::ops::shared::lifecycle::{
    LifecycleRejection, MAX_LIFECYCLE_ID_CHARS, MAX_LIFECYCLE_RULES, validate_lifecycle,
};

// The default-encryption document contract, exported for the same reason as the two above: what
// `PutBucketEncryption` may store — the closed SSEAlgorithm set and the KMS-key-id/algorithm
// agreement — must be one implementation every backend calls. The rejection reasons are
// constant on purpose: `KMSMasterKeyID` is a sensitive member, and a backend that composed its
// own refusal from the document's bytes would copy a key identifier into an error body
// (`q-enc-0009`).
pub use rustfs_gateway_core::ops::shared::encryption::{EncryptionRejection, validate_encryption};

// The object-lock document contracts, exported for the same reason as the three above — with
// the sharpest stakes in the table: what the lock, retention and legal-hold writes may store is
// a WORM compliance answer, so the closed value sets, the Days/Years mutex and the future-only
// RetainUntilDate must be one implementation every backend calls. `validate_retention` takes
// the caller's clock rather than reading one, which is what makes the future-only rule
// testable — and what the conformance fixture pins per case. Enforcement — refusing deletes and
// overwrites of protected objects, the governance bypass — is deliberately not exported,
// because it is deliberately not implemented here.
pub use rustfs_gateway_core::ops::shared::object_lock::{
    ObjectLockRejection, validate_legal_hold, validate_lock_configuration, validate_retention,
};

// The replication document contract, exported for the same reason as the three above: what
// `PutBucketReplication` may store — the V1/V2 schema couplings, the filter grammar, the rule
// cap and the id bounds — must be one implementation every backend calls, and its leniencies
// matter even more than its refusals: this is the one configuration RustFS parses fail-closed,
// so a backend that re-derived a stricter rule would make buckets unusable on the next
// re-parse. The rejection reasons are constant on purpose: `ReplicaKmsKeyID` and `Account` are
// configuration secrets, and a backend that composed its own refusal from the document's bytes
// would copy them into an error body (`q-repl-0010`).
pub use rustfs_gateway_core::ops::shared::replication::{
    MAX_REPLICATION_ID_CHARS, MAX_REPLICATION_RULES, ReplicationRejection, RuleShape, classify_rule, validate_replication,
};

// The select request contract, exported for the same reason and with one addition of its own:
// the expression is user-authored SQL, so no rejection here carries a byte of it and a backend
// that composed its own refusal would be the second place that rule has to hold. The same four
// members appear twice on the wire — in a `SelectObjectContentRequest` and in a
// `RestoreRequest`'s `SelectParameters` — which is why the validator takes them as arguments
// rather than as a request.
pub use rustfs_gateway_core::ops::shared::select::{
    MAX_EXPRESSION_BYTES, SelectRejection, validate_input_serialization, validate_output_serialization, validate_scan_range,
    validate_select,
};

// The restore contract, and the one thing on this list a backend cannot afford to re-derive:
// `RestoreState::status` is where the 202/200 difference lives. A client polls on it, both
// numbers are successes, and a backend that picked its own would break the poll loop while
// answering something no status assertion would flag. `format_restore_status` is exported
// beside it because `x-amz-restore` is a structured header the read and head encoders will also
// have to write, and two `format!`s spell a comma-and-a-space differently sooner or later.
pub use rustfs_gateway_core::ops::shared::restore::{
    MAX_RESTORE_HEADER_BYTES, MIN_RESTORE_DAYS, RestoreRejection, RestoreState, RestoreStatus, format_restore_status,
    parse_restore_status, validate_restore,
};

// The event-stream framing. Exported although nothing in this workspace sends a frame yet: the
// response shape a select answer needs is a third variant of `Resp<O>` and is not this family's
// to add, but the framing is the half an implementation gets wrong invisibly — a CRC over the
// wrong range encodes, decodes against its own author, and is refused by every SDK. Exporting
// it is what stops the eventual caller from writing a second one.
pub use rustfs_gateway_core::ops::shared::event_stream::{
    EVENT_STREAM_CONTENT_TYPE, EventKind, EventSequence, EventStreamError, MAX_PAYLOAD_BYTES, encode_event, encode_exception,
    progress_document, stats_document,
};

// The ACL contract, exported for the same reason as the five above, plus one this family has to
// itself: an ACL arrives on **two** wire channels — the `<AccessControlPolicy>` body and the
// `x-amz-acl` / `x-amz-grant-*` headers — and a backend that parsed the grant-header grammar for
// itself would end up with two parsers for one grammar. The two would then disagree about what a
// client asked for while both answered 200, which on an authorization input is the failure mode
// worth an export on its own. `resolve_grantee_type` is exported beside them because the
// `<Grantee>` discriminator is an XML attribute this project's reader cannot see (`q-acl-0004`),
// so every backend has to derive it the same way or a read answers a document no SDK can parse.
pub use rustfs_gateway_core::ops::shared::acl::{
    ALL_USERS_GROUP, AUTHENTICATED_USERS_GROUP, AclHeaders, AclInput, AclRejection, AclTarget, BUCKET_CANNED_ACLS, GranteeType,
    LOG_DELIVERY_GROUP, MAX_GRANT_HEADER_BYTES, MAX_GRANTEES_PER_HEADER, OBJECT_CANNED_ACLS, PERMISSIONS, XSI_NAMESPACE,
    canonicalize_policy, parse_canned, parse_grant_header, resolve_grantee_type, resolve_input,
};

// The bucket lifecycle contracts, exported the day they are written rather than found
// unreachable later. A backend answering CreateBucket needs `resolve` — the us-east-1
// omission rule, the EU alias and the strict region match — and a backend answering any
// of the three needs `permanent_redirect`, because a 301 built by hand is a 301 that will
// eventually be built without `x-amz-bucket-region`, which is the redirect SDKs cannot
// complete. `RegionLabel` and `RedirectTarget` ride along or the constructors' argument
// types are unnameable outside the workspace.
pub use rustfs_gateway_core::ops::shared::bucket_region::{
    PERMANENT_REDIRECT_MESSAGE, RegionHeaderDuty, TEMPORARY_REDIRECT_MESSAGE, permanent_redirect, permanent_redirect_for,
    temporary_redirect,
};
pub use rustfs_gateway_core::ops::shared::location_constraint::{
    EU_ALIAS, MAX_CONSTRAINT_LEN, RegionMatchPolicy, US_EAST_1, invalid_location_constraint,
    normalize as normalize_location_constraint, resolve as resolve_location_constraint,
};
pub use rustfs_gateway_core::{InvalidWireLabel, RedirectTarget, RegionLabel};
// The policy itself, not just its type. A backend that reaches for `RegionMatchPolicy::Strict`
// directly has written the deployment's region posture down a second time, and the second copy is
// the one that will not move when the first does — which is the whole failure mode `ops/shared/`
// exists to prevent. This is the value `CreateBucket` declares, and it is what a backend reads.
pub use rustfs_gateway_core::ops::create_bucket::REGION_MATCH_POLICY;
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
    TimestampFormat,
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
