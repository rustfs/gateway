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
//!
//! # The three middleware levels
//!
//! A tower [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) wraps the whole service
//! and needs nothing from this crate. [`StageFilter`] intercepts between the pipeline's stages and
//! may rewrite the head or the response. [`OpLayer`] wraps one operation with its input and output
//! types intact. [`Observer`] only watches, and always will. `docs/middleware.md` is the decision
//! tree and the table of which of RustFS's nine tower patch layers lands where.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
// No stdout, no stderr, no `dbg!` outside tests: a diagnostic is a `tracing` event (docs/observability.md).
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro))]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod adapt;
mod assembly;
mod builder;
mod chunked;
mod classify;
mod clock;
pub mod close;
pub mod commit;
mod commit_task;
pub use crate::commit_task::DetachedWork;
mod config;
#[cfg(feature = "server")]
mod conn;
mod cors_legacy;
mod dialect_posture;
mod dispatch;
mod ext;
mod file_fallback;
mod gate;
mod integrity;
mod invariants;
mod legacy_addressing;
mod logging;
mod monomorphic;
mod naming_posture;
mod operation_mode;
mod panic_boundary;
mod payload_header;
mod post_object;
mod posture;
mod presigned_expiry_posture;
mod probe;
mod render;
mod request_body;
mod request_config;
mod request_deadline;
mod request_end;
mod response;
mod routed_facts;
mod routing;
mod select_frames;
mod service;
mod stamp;
mod trace;
mod transport;
mod unread_body;
mod wire;
mod wire_read;

pub mod sig;

pub use crate::adapt::ServiceFuture;
pub use crate::assembly::{AssemblyError, RuleRef};
pub use crate::builder::version_actions::LEGACY_UNVERSIONED_OPERATIONS;
pub use crate::builder::view_policy::{
    BODY_LITERAL_OPERATIONS, CLAMPED_MAX_KEYS_OPERATIONS, EMPTY_UPLOAD_OPERATIONS, RUSTFS_LISTING_ENCODINGS,
    RUSTFS_MAX_KEYS_CEILING, STRICT_DATE_CONDITION_HEADERS,
};
pub use crate::builder::{
    AssemblyUpdate, CHECKSUM_REQUIRED_OPERATIONS, DEFAULT_MAX_BUFFERED_BODY_BYTES, MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS,
    S3CMD_CHECKSUM_OPTIONAL_OPERATIONS, ServiceBuilder,
};
pub use crate::classify::Classification;
pub use crate::clock::{
    Clock, ClockPosture, ClockSkewAck, FixedClock, ManualMonotonic, MonotonicClock, MonotonicNow, SystemMonotonic, system_clock,
};
pub use crate::close::ConnectionIntent;
pub use crate::config::{
    ConfigHandle, ConfigSnapshot, DEFAULT_COMMIT_PROGRESS_DEADLINE, DEFAULT_EXTENDED_HANDLER_DEADLINE,
    DEFAULT_STANDARD_HANDLER_DEADLINE, HandlerDeadlineConfig, HandlerDeadlineConfigError, KEEPALIVE_INTERVALS_WITHOUT_PROGRESS,
    NO_DEADLINE, RequestBodyDeadlineConfig, ServiceConfig,
};
#[cfg(feature = "server")]
pub use crate::conn::{
    MeasuredSelfHeldHttp1Driver, ResponseFallbackReason, ResponseTransportMetrics, SelfHeldHttp1Driver, SelfHeldRequestBody,
};
pub use crate::cors_legacy::{DEFAULT_RUSTFS_CONSOLE_PREFIX, LegacyRustfsCors};
pub use crate::ext::{
    Addressing, AuthSchemeRef, Authentication, AuthenticationOutcome, Authenticator, Authorizer, AuthzAuditEvent, AuthzAuditSink,
    AuthzRequest, AuthzStage, BaseDomain, BodyQuota, BodyQuotaExceeded, BucketOwnerError, BucketOwnerSource, CORS_PREFLIGHT,
    CachedCorsSource, ChunkSink, ChunkVerification, ClassKind, ClientAddr, CorsCacheConfig, CorsSource, CorsSourceError,
    Credential, CredentialGuardConfig, CredentialLookup, CredentialProvider, CredentialRefusal, Credentials, CredentialsError,
    DEFAULT_POLICY_SNAPSHOT_TIMEOUT, Decision, DefaultGovernor, Denial, DenyAllAuthorizer, DomainError, FROZEN_WIRE_HEADERS,
    FrozenHeader, Governor, GovernorRates, GovernorRequest, GuardedCredentialProvider, HostQuery, HostRefusal, HostResolver,
    InputAuthzRequest, InputDecisions, LayeredGovernor, Lease, LegacyDomainError, LegacyRustfsVirtualHosts,
    MAX_BASE_DOMAIN_BYTES, MAX_POLICY_SNAPSHOT_TIMEOUT, Next, NoAuthzAudit, NoBucketOwner, NoCors, NoObserver, NoPolicy,
    Observer, OpLayer, PathStyleOnly, PolicyError, PolicySnapshot, PolicySource, PolicyTimeout, PolicyTimeoutError,
    ProviderError, ProviderMetrics, Rate, RequestContext, RequestEvent, ResolvedHost, ResponseView, RoutedView, ServerExtensions,
    SessionBinding, SessionBindingError, SigV2Authentication, SigV4Authenticator, SnapshotId, StageFilter, StaticCredentials,
    TargetOrigin, Unavailable, Unlimited, VerifiedBodyProgress, VhostHint, VirtualHostStyle, WireHead, allow_when, decide_with,
    fn_credential_provider, op_layer, policy_from, response_filter, routed_filter, wire_filter,
};
#[cfg(feature = "dangerous-allow-all-authorizer")]
pub use crate::ext::{AllowAllAuthorizer, DangerAck};
pub use crate::monomorphic::{MonomorphicOperationSet, MonomorphicService, OperationSetEnd, OperationSetNode};
pub use crate::probe::{BodyProgress, ObservedBody};
pub use crate::render::{S3Error, connection_intent_of, declaration, document, document_body, render};
pub use crate::request_config::HandlerDeadlineReport;
pub use crate::service::{S3Service, SecurityPosture};
pub use crate::trace::{
    FixedTrace, HOST_ID_HEADER, HostId, HostRequestId, InvalidRequestId, MintedTraces, REQUEST_ID_HEADER, RequestId,
    RequestTrace, TraceSource, X_REQUEST_ID_HEADER,
};
pub use crate::transport::Transport;
pub use crate::unread_body::UnreadBodyDrain;
pub use crate::wire::{OrderedHeaders, WireResponse, collect};
pub use rustfs_gateway_http::MAX_LINGER_DRAIN_BYTES;
pub use rustfs_gateway_macros::handlers;
#[cfg(feature = "server")]
pub use rustfs_gateway_server::{DEFAULT_ALPN_PROTOCOLS, RunningServer, Server, ServerConfig, TlsHandle, TlsMaterial};

/// The generated request and response types, and the operation markers they belong to.
///
/// Re-exported as a module rather than item by item: there are seventy-three operations and three
/// types each, and a facade that listed them would be a list to keep in sync with a generator.
pub use rustfs_gateway_types::dto;

/// Historical persisted-configuration codecs and representations for facade-only backends.
pub use rustfs_gateway_types::persistence;

// The kernel surface a backend and a test harness have to name. Re-exported rather than reached
// for directly, because `scripts/check_layer_dependencies.sh` allows the conformance suite to
// depend on this crate and on nothing else internal.
// `Answer`, `CommitOutcome` and `CommitWork` are here for the reason `ETag` and `Timestamp` were:
// `Resp::commit` is exported, so a backend outside this workspace can build a committed response —
// and then cannot name the type of the work it just handed over, cannot write a function returning
// one, and cannot match on what `into_parts` gives back. An exported constructor whose argument
// type is unnameable is the same defect as an unexported contract, one step further along.
pub use rustfs_gateway_core::{
    ActionRule, Addressed, AddressingStyle, AuthenticatedScheme, CallerSecretKey, PathParamError, PathParams, RequestContextView,
    RequestPrincipal, Subject, SubjectName, SubjectRule, WhenAbsent,
};
pub use rustfs_gateway_core::{
    Answer, ArnForm, AuthRequirement, Authorized, BodyPolicy, BoxFuture, CodecError, CommitOutcome, CommitWork,
    CommittedResponse, DeferredOperation, DerivedResourceError, ELEMENT_ORDER, EncodedResponse, ErrorContext, ErrorDetail,
    ErrorHeader, ErrorResolution, Handler, HandlerCancellation, HandlerContext, HandlerDeadlineClass, HandlerError,
    HandlerErrorContext, HandlerResult, HasOperation, HeadPart, HeadPartError, HttpDate, InvalidErrorContext, LegacyRustfsFacts,
    LegacyRustfsRefusal, MetaView, MissingHandlers, MissingObject, NoDerived, OWNED_RESPONSE_HEADERS, Operation, OperationCodec,
    OperationSet, OperationSpec, PRECONDITION_FAILED_MESSAGE, ParamKind, PreAuthError, Predicate, RANGE_NOT_SATISFIABLE_MESSAGE,
    Req, RequestBody, RequestBodyMode, RequiredParam, ResourceIdentity, ResourceShape, ResourceVisibility, Resp, ResponseBody,
    ResponseKind, ResponseOverride, RouteEntry, RouteSelector, RouterBuilder, TargetKind, resolve,
};
pub use rustfs_gateway_core::{Everyone, MAX_SUBJECTS, Subjects};

/// Input-parameterized compatibility name for an operation request.
///
/// This is the same type as [`Req`] for the operation selected by [`HasOperation`].
pub type S3Request<I> = Req<<I as HasOperation>::Op>;

/// Compatibility result using the facade's protocol error type.
pub type S3Result<T> = std::result::Result<T, S3Error>;
// The pagination contract. Found unreachable by check_shared_reachable.sh the moment that
// guard existed — the fourth contract in a row written for backends and left where no
// backend could see it. key_count is the KeyCount = Contents + CommonPrefixes rule that
// made OpenDAL page forever when a listing got it wrong.
pub use rustfs_gateway_core::ops::delete_objects::DeleteObjectResources;
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
    ConditionalOutcome, FailedCondition, IfRange, ObjectValidators, PreconditionRejection, Preconditions, RangeDecision,
    RangeSelectors, RequestKind, completion_failure_retains_upload, conditional_write_guards_before_mutation,
    copy_target_uses_source_validators, evaluate, evaluate_range,
};
// The other half of the range contract. `evaluate_range` stops at a part *selector* because the
// part table is a fact only the handler has; this is what a backend resolves it with.
pub use rustfs_gateway_core::ops::shared::part_table::{PartWindow, resolve_part};
// The checksum a streaming body claimed. A trailer exists only once the body has ended, so only the
// backend that drained it can ask; this is where it asks, with the header decoder's field rule and
// the wire layer's refusal of a claim made in both places (rustfs/gateway#929).
pub use rustfs_gateway_core::ops::shared::trailer_checksum::request_checksum;
// The upload-id capability. Five multipart operations are handed an id the caller chose to send,
// and the rule that separates a genuine id from a genuine id *belonging to somebody else* is one
// comparison that every one of them must make identically — including the part that makes all its
// refusals indistinguishable. Like the part table it can only run in the backend, because only the
// backend can look an upload up, so `resolve_upload` takes the lookup as a closure and owns the
// order: shape, then lookup, then ownership. `ResolvedUploadId` is the only value carrying an id a
// handler can act on, and this exchange is its only producer.
pub use rustfs_gateway_core::ops::shared::upload_id::{
    RecordedUpload, ResolvedUploadId, UploadIdClaim, UploadRejection, resolve_upload,
};
pub use rustfs_gateway_core::{copy_source_guards_before_target_write, copy_source_if_match_miss_proceeds};

/// The `CopyObject` metadata-directive authority used by backend handlers.
///
/// `CopyObject` owns this directive rather than the shared source parser, but a backend needs both
/// in the same handler. Re-exporting it here keeps out-of-workspace adapters on the public facade.
pub use rustfs_gateway_core::ops::copy_object::MetadataSource;
// The copy-source contract. A backend receives `CopySourceResources` through `Req::resources`
// and can reveal the normalized source only with the proof on that same request. It never needs
// to parse the raw header again.
pub use rustfs_gateway_core::ops::shared::copy_source::{
    CopyRange, CopySource, CopySourceForm, CopySourceRejection, CopySourceResources, ResolvedCopySource, SelfCopy,
    classify_self_copy, resolve_copy_range,
};
// The CORS document contract. A backend stores what `PutBucketCors` hands it and the preflight
// runtime later answers browsers out of that store, so the rules for what may be stored — the
// closed method set, the wildcard budget, the hundred-rule cap — must be one implementation
// every backend calls, not a description every backend re-derives. The conformance fixture is
// the first caller; a backend that skipped validation would store a document whose rules the
// matcher can never satisfy, and the only symptom would be browser-side.
pub use rustfs_gateway_core::ops::shared::cors::{
    CORS_ALLOWED_METHODS, CorsRejection, MAX_CORS_ID_CHARS, MAX_CORS_RULES, cors_delete_absent_succeeds, validate_cors,
};
// The CORS **runtime**, exported for the reason the document contract above is: a deployment
// installs a `CorsSource` and a `CorsPolicy`, and neither is nameable without these. `CorsOrigins`
// and `CorsPolicyError` ride along or `CorsPolicy::new`'s argument and error types are
// unnameable outside the workspace — the same defect as an unexported contract, one step on. The
// matcher itself is exported too, because a deployment answering `OPTIONS` on a second protocol
// face (a website endpoint, a console) must reach the one evaluator rather than write a second.
pub use rustfs_gateway_core::cors::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
    AllowOrigin, CorsHeaders, CorsOrigins, CorsPolicy, CorsPolicyError, ORIGIN, PREFLIGHT_REFUSAL_MESSAGE,
    PREFLIGHT_SUCCESS_STATUS, PreflightClass, PreflightOutcome, PreflightRequest, RequestedHeaders, RuleMatch, UnrenderableRule,
    VARY, VARY_ORIGIN, actual_headers, answer_actual, answer_preflight, classify, match_actual, match_preflight,
    preflight_headers, preflight_refusal,
};

// The tagging contract. The tag set has two request channels — the `<Tagging>` document of the
// `?tagging` subresource and the packed `x-amz-tagging` header on PutObject, CopyObject and
// CreateMultipartUpload — and the count, length, character-set and duplicate-key rules must be
// one rule for both. The XML channel's syntax is the generated decoder's; everything semantic,
// and the whole of the header channel, is here, because a backend parses that header itself and
// an unexported parser is one every backend rewrites.
pub use rustfs_gateway_core::ops::shared::tagging::{
    MAX_BUCKET_TAGS, MAX_OBJECT_TAGS, MAX_TAG_KEY_UNITS, MAX_TAG_VALUE_UNITS, TagHeaderGrammar, TagScope, TaggingRejection,
    parse_tagging_header, parse_tagging_header_with, validate_tag_set,
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
//
// `refuse_blocked_encryption_type` is the stored document's one run-time rule, and it is the
// backend's to call: the framework holds no bucket state, so only the backend that stored a
// `BlockedEncryptionTypes` can refuse the write it blocks. It takes the framework's `SseEnforced`
// proof rather than the decoded headers, so a backend cannot answer from a field the gate did not
// validate.
pub use rustfs_gateway_core::ops::shared::encryption::{
    EncryptionRejection, blocks_customer_keys, encryption_delete_absent_succeeds, refuse_blocked_encryption_type,
    validate_encryption,
};

// The **run-time** half of server-side encryption, which the document contract above deliberately
// does not answer. Three of these are named by a deployment: `TransportSecurity` is what a
// transport puts into a request's extensions to say the socket was encrypted, `SseConfig` and
// `PlaintextCustomerKeyAck` are how a deployment says it will serve customer-provided keys over
// cleartext anyway. The rest are what a **backend** needs: `KeyFingerprint` is the sixteen bytes
// an upload is bound to, `check_part` is the cross-request comparison the framework cannot make
// for it because it holds no upload state, and `enforce` is how a handler obtains a fingerprint
// the framework has already validated. `SseEnforced` carries digests and an algorithm — never a
// key; there is no accessor for one, on purpose.
pub use rustfs_gateway_core::sse::{
    KeyFingerprint, KeySide, ManagedRejection, PartRejection, PlaintextCustomerKeyAck, SseConfig, SseEnforced, SseRejection,
    TransportSecurity, check_part, enforce as enforce_sse, presented_customer_key,
};

// The object-lock document contracts, exported for the same reason as the three above — with
// the sharpest stakes in the table: what the lock, retention and legal-hold writes may store is
// a WORM compliance answer, so the closed value sets, the Days/Years mutex and the future-only
// RetainUntilDate must be one implementation every backend calls. `validate_retention` takes
// the caller's clock rather than reading one, which is what makes the future-only rule
// testable — and what the conformance fixture pins per case. Enforcement — refusing deletes and
// overwrites of protected objects, the governance bypass — is deliberately not exported,
// because it is deliberately not implemented here. `validate_object_write_lock` holds the
// `x-amz-object-lock-*` headers of an object write to the same rules as the two documents.
pub use rustfs_gateway_core::ops::shared::object_lock::{
    ObjectLockRejection, object_lock_requires_enabled_bucket, validate_legal_hold, validate_lock_configuration,
    validate_object_write_lock, validate_retention,
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
    MAX_EXPRESSION_BYTES, SelectRejection, select_scan_bytes, select_uses_event_stream, validate_input_serialization,
    validate_output_serialization, validate_scan_range, validate_select,
};

// The restore contract, and the one thing on this list a backend cannot afford to re-derive:
// `RestoreState::status` is where the 202/200 difference lives. A client polls on it, both
// numbers are successes, and a backend that picked its own would break the poll loop while
// answering something no status assertion would flag. `format_restore_status` is exported
// beside it because `x-amz-restore` is a structured header the read and head encoders will also
// have to write, and two `format!`s spell a comma-and-a-space differently sooner or later.
pub use rustfs_gateway_core::ops::shared::restore::{
    MAX_RESTORE_HEADER_BYTES, MIN_RESTORE_DAYS, RestoreRejection, RestoreState, RestoreStatus, format_optional_restore_status,
    format_restore_status, parse_restore_status, validate_restore,
};

// The event-stream framing used with `Resp::event_stream`. A CRC over the wrong range encodes,
// decodes against its own author, and is refused by every SDK, so the encoder is exported beside
// the response constructor rather than leaving each backend to write another one.
pub use rustfs_gateway_core::ops::shared::event_stream::{
    EVENT_STREAM_CONTENT_TYPE, EventKind, EventSequence, EventStreamError, MAX_PAYLOAD_BYTES, encode_event, encode_exception,
    progress_document, stats_document,
};
// The bounded way to answer a select from a record source: one frame per read, never the answer.
pub use select_frames::frame_records;

// The ACL contract, exported for the same reason as the five above, plus one this family has to
// itself: an ACL arrives on **two** wire channels — the `<AccessControlPolicy>` body and the
// `x-amz-acl` / `x-amz-grant-*` headers — and a backend that parsed the grant-header grammar for
// itself would end up with two parsers for one grammar. The two would then disagree about what a
// client asked for while both answered 200, which on an authorization input is the failure mode
// worth an export on its own. `canonicalize_grantee` is exported beside them because a `<Grantee>`
// reaches a backend from more than one document — an ACL body and a logging document's
// `<TargetGrants>` — and both owe it the same two answers: an `xsi:type` outside the closed set is
// refused (`q-acl-0003`), and the stored discriminator comes from the identifying member
// (`q-acl-0004`). A backend that did one of the two would echo back a document no SDK can classify.
pub use rustfs_gateway_core::ops::shared::acl::{
    ALL_USERS_GROUP, AUTHENTICATED_USERS_GROUP, AclHeaders, AclInput, AclRejection, AclTarget, BUCKET_CANNED_ACLS, GRANTEE_TYPES,
    GranteeType, LOG_DELIVERY_GROUP, MAX_GRANT_HEADER_BYTES, MAX_GRANTEES_PER_HEADER, OBJECT_CANNED_ACLS, PERMISSIONS,
    XSI_NAMESPACE, canonicalize_grantee, canonicalize_policy, check_grantee_type, parse_canned, parse_grant_header,
    resolve_grantee_type, resolve_input,
};

// The bucket-configuration band's four contracts, exported for the same reason as the families
// above. The stakes are lowest here and the leniency is widest: RustFS parses these documents
// fail-open, so a backend that re-derived a stricter rule would not refuse a write — it would
// switch a feature off on the next re-parse, and for `?versioning` that means version retention.
// What is refused is the short list AWS documents as a refusal, once, here.
pub use rustfs_gateway_core::ops::shared::bucket_config::{
    BucketConfigRejection, mfa_delete_states, payers, switch_statuses, validate_accelerate, validate_logging,
    validate_request_payment, validate_versioning,
};

// The notification document contract. Its leniency is the load-bearing part: AWS adds event
// types continuously, so a backend that refused a name it did not know would reject
// configurations AWS accepts until it was rebuilt.
pub use rustfs_gateway_core::ops::shared::bucket_notification::{NotificationRejection, validate_notification};

// The bucket policy contract — and the fence around it. What is exported is the size ceiling, the
// depth ceiling and the syntax check; what is deliberately **not** exported, because it is
// deliberately not implemented, is any evaluation of what a policy grants. The rejection reasons
// are constant with no offset and no excerpt: a policy names principals and account identifiers,
// and an error that said where the syntax broke would let a caller who cannot read the policy
// back reconstruct it one probe at a time.
pub use rustfs_gateway_core::ops::shared::bucket_policy::{
    MAX_POLICY_BYTES, MAX_POLICY_DEPTH, PolicyRejection, validate_policy, validate_public_access_block,
};

// The website document contract: the exclusion between a whole-site redirect and a
// document-serving site, and the one-rewrite-per-redirect rule. Serving anything from the
// document is a second protocol face this workspace does not implement, so nothing about the
// runtime is exported — there is nothing to export.
pub use rustfs_gateway_core::ops::shared::bucket_website::{WebsiteRejection, validate_website};

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
pub use rustfs_gateway_core::{InvalidWireLabel, RedirectTarget, RegionLabel, VersionIdLabel};
// The policy itself, not just its type. A backend that reaches for `RegionMatchPolicy::Strict`
// directly has written the deployment's region posture down a second time, and the second copy is
// the one that will not move when the first does — which is the whole failure mode `ops/shared/`
// exists to prevent. This is the value `CreateBucket` declares, and it is what a backend reads.
/// The wire ceiling an upload-object ceiling implies for an aws-chunked body; see
/// [`ServiceConfig::with_upload_object_ceiling`].
pub use crate::gate::max_framed_upload_bytes;
pub use rustfs_gateway_core::ops::create_bucket::REGION_MATCH_POLICY;
pub use rustfs_gateway_http::{EffectiveHost, Limits, TransportExtensions, WireReject, WireRequest};
pub use rustfs_gateway_sig::{
    Identity, OperationFloor, PresignedExpiryRule, RegionSet, RequestNow, SecurityFloor, SigService, SkewWindow, Verdict,
};
pub use rustfs_gateway_stream::{Body, ByteStream, Payload, TrailingHeaders};
/// Tower's service trait, exposed so facade-only consumers can wrap [`S3Service`].
pub use tower::Service as TowerService;
// `ETag`, `Timestamp` and the checksum types are here because a backend cannot answer without
// them: `Object`, `ObjectVersion`, `Part` and `Bucket` all require one, so without these a
// listing entry is unbuildable and `PutObject` cannot return an etag from outside this
// workspace. The conformance suite found this — 58 cases were failing behind two missing lines
// while `REQUIRED_FACADE_EXPORTS` was satisfied to the letter. A facade that exports the
// service but not the values the service returns is not a facade.
pub use rustfs_gateway_types::{
    AwsNameValidator, BucketName, ChecksumAlgorithm, ChecksumDigest, ChecksumSpec, ChecksumType, Checksummer, ETag, ErrorCode,
    KeyFloor, LegacyRustfsNameValidator, NamePolicy, NameRejection, NameValidator, ObjectKey, PathSplit, SlashPolicy,
    SseCustomerKey, Stricter, Timestamp, TimestampFormat, decode_once, floor_check_bucket, floor_check_key,
};

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

        async fn call_with_context(
            &self,
            _request: Req<dto::ListBuckets>,
            _context: HandlerContext,
        ) -> HandlerResult<dto::ListBuckets> {
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
