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

//! The in-process target: a service assembled from the facade, driven without a socket.
//!
//! Responsible for: turning one `[request]` block into signed bytes, handing them to
//! [`rustfs_gateway::S3Service::call_bytes`], and turning what comes back into an
//! [`Observation`] — the response head in wire order, the body, and the trailers.
//! NOT responsible for: judging anything (`crate::expect`), or storing anything
//! (`crate::fixture`).
//! Upstream: `rustfs-gateway`, `crate::fixture`, `crate::exec`. Downstream: `crate::cli`.
//!
//! # What this transport can see, and what it cannot
//!
//! There is no connection here, so three families of assertion have no honest answer and this
//! module reports what is true of an in-process call rather than guessing what a socket would have
//! done. Each is stated once, here, so a red case can be read against it:
//!
//! * **`connection_after`** — the service is a value, not a peer. A completed exchange leaves it
//!   reusable, which is reported as `open`. A case asserting `closed`, `reset` or `half_closed`
//!   cannot be judged by this transport and will be red for that reason alone. The tempting
//!   shortcut — report `closed` when the response carries `Connection: close` — is deliberately not
//!   taken: that header is the server's *intention*, and reporting an intention as an observation is
//!   the same class of defect as the unconditional `Outcome::Response` this module used to report.
//! * **`request_progress`** — measured, with one caveat, and no longer assumed. The body is handed
//!   over as a [`rustfs_gateway::ObservedBody`] that counts what the service pulls out of it, so
//!   `body_bytes_sent_at_response` is the number of payload bytes the server had asked for when the
//!   response existed and `body_fully_sent` is whether it read on to the end. On a socket those are
//!   two different numbers — a client can be a receive window ahead of the server — and what is
//!   reported here is the server-side one, which is the tighter of the two and the one a case about
//!   early refusal is asking about. This used to be reported as "the whole body, fully sent"
//!   unconditionally, which made every such assertion unfailable.
//! * **`timing`** — `elapsed_ms` and `ttfb_ms` are real but meaningless: an in-memory call takes
//!   microseconds, so an upper bound always holds and a lower bound never does.
//!
//! Everything else — status, error code, header set, header order, body bytes, trailers, capture —
//! is measured exactly.
//!
//! # What `kind` is, and what it is not allowed to be
//!
//! `expect.kind` was reported as `response` unconditionally, and `body_bytes_before_error` was never
//! recorded at all. That is a worse defect than a missing feature: the four cases that assert a late
//! failure could not have failed those assertions no matter what the server did, so the assertions
//! read as satisfied while measuring nothing. A blind spot in the instrument is invisible in the
//! report, which is the one place a conformance suite has to be trusted.
//!
//! Two things are reported now, and each is read off the exchange rather than assumed:
//!
//! * A response that arrived intact but whose status line and body **disagree** — a success status
//!   over an `<Error>` document — is a `stream_error` terminating in an `error_document`, and
//!   `body_bytes_before_error` is where that document begins. The classification is
//!   [`crate::observation::late_error_offset`]'s, so a socket transport will make it identically.
//! * A body that could not be drained is a `stream_error` terminating in an `abrupt_close`, and no
//!   longer an environment failure that *skips* the case.
//!
//! What is still out of reach is the byte count on that second path: `collect` discards what it had
//! read when the stream failed, so `body_bytes_before_error` is left unrecorded there rather than
//! guessed, and a case pinning it stays red. `stream_termination = "reset"` and `"trailer_error"`
//! need a connection and are likewise never reported.
//!
//! # Why a request is built twice
//!
//! Signing needs the host in the byte-exact form the canonical request uses, and the only way to
//! obtain one through the facade is [`rustfs_gateway::WireRequest::accept`], which consumes the
//! request. So the head is assembled once to be accepted and read, and again to be sent. The two
//! are built from the same description, so they cannot disagree.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustfs_gateway::sig::{
    AmzDate, LookupBudget, PayloadMode, SessionToken, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
    Tamper, TamperComponent,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, BucketName, ClassKind, CorsSource, CorsSourceError, CredentialGuardConfig,
    CredentialLookup, CredentialProvider, Credentials, DEFAULT_MAX_BUFFERED_BODY_BYTES, Decision, ErrorCode, FixedClock,
    Governor, GovernorRequest, GuardedCredentialProvider, HandlerDeadlineConfig, HandlerResult, InputAuthzRequest,
    InputDecisions, Lease, Limits, Next, ObservedBody, PolicyError, PolicySnapshot, ProviderError, RegionSet, Req,
    RequestContext, S3Service, ServiceBuilder, ServiceConfig, SessionBinding, SigV4Authenticator, SnapshotId, StaticCredentials,
    VirtualHostStyle, WireRequest, allow_when, collect, dto, fn_credential_provider, op_layer, policy_from,
};
mod sigv2;
use crate::exec::block_on;
use crate::fixture::{Fixture, StoredObject, Stub};
use crate::interpolate::Captures;
use crate::observation::{
    ConnectionState, Observation, Outcome, StreamTermination, decode_event_stream, has_event_stream_content_type,
    late_error_offset,
};
use crate::sut::{ExchangePlan, Sut, SutError};
use crate::time;
use crate::value::Value;
/// The access key id every case names as `valid`.
pub const VALID_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
/// Its secret. The AWS documentation example key, which is what makes a hand-checked signature
/// comparable against the worked examples in the SigV4 documentation.
pub const VALID_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
/// The access key id the target has never heard of.
pub const UNKNOWN_ACCESS_KEY: &str = "AKIAI44QH8DHBEXAMPLE";
/// The secret used when a case asks to sign with the wrong one.
pub const WRONG_SECRET: &[u8] = b"this-is-not-the-secret-the-target-knows--";
/// The access key id of a temporary STS issuance whose lifetime has already ended.
///
/// A distinct identity rather than the valid one under another name, and its secret is
/// [`VALID_SECRET`], so a request signed for it verifies. The only thing wrong with it is the
/// expiry — which is what makes the case measure the expiry and nothing else.
pub const EXPIRED_SESSION_ACCESS_KEY: &str = "ASIAI44QH8DHBEXAMPLE";
/// The token that issuance was handed out with. Presented on the request, and held by the
/// provider, so the access-key-to-token binding holds and only the lifetime fails.
pub const EXPIRED_SESSION_TOKEN: &str = "FQoGZXIvYXdzEExpiredSessionTokenForConformance";
/// A live temporary credential used by header and presigned-query cases.
pub const LIVE_SESSION_ACCESS_KEY: &str = "ASIAIOSFODNN7EXAMPLE";
/// The token issued with [`LIVE_SESSION_ACCESS_KEY`].
pub const LIVE_SESSION_TOKEN: &str = "FQoGZXIvYXdzELiveSessionTokenForConformance";
/// A different token, signed with the same key pair, used to prove issuance binding.
pub const OTHER_SESSION_TOKEN: &str = "FQoGZXIvYXdzEOtherSessionTokenForConformance";
/// A known credential switched off in the fixture provider.
pub const DISABLED_ACCESS_KEY: &str = "AKIADISABLED00EXAMPLE";
/// The issuer recorded on the expired session. Opaque to the framework.
const SESSION_ISSUER: &str = "sts.conformance.invalid";
/// How far in the past the expired session's lifetime ended, relative to the case's own clock.
///
/// Relative rather than absolute, so a case may fix its clock wherever it likes and the session is
/// expired for all of them. An absolute instant would make the fixture silently *live* for any
/// case whose clock predates it.
const EXPIRED_SESSION_AGE_SECONDS: i64 = 3_600;
/// The host every request addresses unless a case overrides it with `request.host`.
///
/// Also the first entry of [`BASE_DOMAINS`], which is what lets the `host/` family address a
/// bucket virtual-hosted without disturbing the rest of the corpus: the bare base domain has no
/// prefix, so `Host: s3.example.com` with a `/bucket/key` target is path-style exactly as it was
/// before the resolver was installed.
pub const HOST: &str = "s3.example.com";
/// The virtual-hosted base domains the target is assembled with.
///
/// Two of them, and the second is the region-bearing form, because a resolver that only ever holds
/// one domain cannot show that the *longest* match wins or that a second domain matches at all.
pub const BASE_DOMAINS: [&str; 2] = [HOST, "s3.us-east-1.example.com"];
/// The region every case signs for.
pub const REGION: &str = "us-east-1";

struct FixedDecision(Decision);

impl Authorizer for FixedDecision {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async move { self.0 })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(self.0, |_| self.0);
        Box::pin(async move { decisions })
    }
}

struct SameSnapshot {
    first: Mutex<Option<(SnapshotId, i64)>>,
}

impl SameSnapshot {
    fn decide(&self, context: &RequestContext<'_>) -> Decision {
        let observed = (context.policy().id(), context.now().unix_seconds());
        match self.first.lock() {
            Ok(mut first) => match *first {
                None => {
                    *first = Some(observed);
                    Decision::Allow
                }
                Some(expected) if expected == observed => Decision::Allow,
                Some(_) => Decision::Deny,
            },
            Err(_) => Decision::Indeterminate,
        }
    }
}

impl Authorizer for SameSnapshot {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide(context);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide(context);
        let decisions = request.decide_all(stage, |_| self.decide(context));
        Box::pin(async move { decisions })
    }
}

struct HotUpdate {
    current: Arc<AtomicUsize>,
}

struct CountedCredentials {
    inner: Arc<dyn CredentialProvider>,
    calls: Arc<AtomicUsize>,
}

impl CredentialProvider for CountedCredentials {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup(access_key_id)
    }
}

struct DeletedAfterFirstLookup {
    credentials: Mutex<Option<Credentials>>,
    calls: Arc<AtomicUsize>,
}

struct CredentialClassProbe {
    calls: Arc<AtomicUsize>,
}

impl Governor for CredentialClassProbe {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        if request.kind() == ClassKind::CredentialLookup {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(async { Ok(Lease::admit()) })
    }
}

impl CredentialProvider for DeletedAfterFirstLookup {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let lookup = self
            .credentials
            .lock()
            .ok()
            .and_then(|mut credentials| credentials.take())
            .map_or(CredentialLookup::NotFound, CredentialLookup::Found);
        Box::pin(async move { Ok(lookup) })
    }
}

impl HotUpdate {
    fn decide(&self, context: &RequestContext<'_>, request: &AuthzRequest<'_>) -> Decision {
        match context.policy().get::<usize>().copied() {
            Some(1) => {
                if request.action == "s3:PutObject" {
                    self.current.store(2, Ordering::SeqCst);
                }
                Decision::Allow
            }
            Some(2) => Decision::Deny,
            _ => Decision::Indeterminate,
        }
    }
}

impl Authorizer for HotUpdate {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide(context, request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide(context, request.route());
        let decisions = request.decide_all(stage, |resource| self.decide(context, resource));
        Box::pin(async move { decisions })
    }
}

/// A service assembled from the facade, plus the fixtures the current case established.
pub struct InProcess {
    root: PathBuf,
    state: Arc<Mutex<Fixture>>,
    limits: Limits,
    case_id: String,
    authz_policy_version: Arc<AtomicUsize>,
    authz_backend_calls: Arc<AtomicUsize>,
    credential_backend_calls: Arc<AtomicUsize>,
    credential_exchanges: AtomicUsize,
    credential_governor_calls: Arc<AtomicUsize>,
    persistent_credentials: Mutex<Option<Arc<dyn CredentialProvider>>>,
}

impl InProcess {
    /// Builds a target rooted at a corpus directory, which is where `body.file` payloads are read
    /// from.
    #[must_use]
    pub fn new(root: PathBuf) -> InProcess {
        InProcess {
            root,
            state: Arc::new(Mutex::new(Fixture::at(0))),
            limits: Limits::default(),
            case_id: String::new(),
            authz_policy_version: Arc::new(AtomicUsize::new(1)),
            authz_backend_calls: Arc::new(AtomicUsize::new(0)),
            credential_backend_calls: Arc::new(AtomicUsize::new(0)),
            credential_exchanges: AtomicUsize::new(0),
            credential_governor_calls: Arc::new(AtomicUsize::new(0)),
            persistent_credentials: Mutex::new(None),
        }
    }

    /// Assembles the service for one exchange.
    ///
    /// Rebuilt per exchange rather than once, because the clock is fixed at assembly time and is a
    /// per-case declaration. Assembly is a few table inserts; a stale clock would be a wrong answer.
    pub(crate) fn assemble(&self, at_unix_seconds: i64, skew_ms: i64) -> Result<S3Service, SutError> {
        let backend = Arc::new(Stub::new(Arc::clone(&self.state)));
        let credentials = Credentials::new(VALID_ACCESS_KEY, VALID_SECRET)
            .map_err(|error| SutError::Environment(format!("the fixture credentials are not valid: {error}")))?;
        // The second identity exists so that `sign.credential = "expired_session"` measures an
        // expiry rather than being skipped. Its lifetime is pinned to this exchange's own clock,
        // so it is expired whatever instant the case fixed.
        let expired_binding = SessionBinding::new(SESSION_ISSUER, at_unix_seconds.saturating_sub(EXPIRED_SESSION_AGE_SECONDS))
            .map_err(|error| SutError::Environment(format!("the fixture session binding is not valid: {error}")))?;
        let expired = Credentials::new(EXPIRED_SESSION_ACCESS_KEY, VALID_SECRET)
            .and_then(|credentials| credentials.with_session(EXPIRED_SESSION_TOKEN, expired_binding))
            .map_err(|error| SutError::Environment(format!("the fixture session credentials are not valid: {error}")))?;
        let live_binding = SessionBinding::new(SESSION_ISSUER, at_unix_seconds.saturating_add(EXPIRED_SESSION_AGE_SECONDS))
            .map_err(|error| SutError::Environment(format!("the live fixture session binding is not valid: {error}")))?;
        let live = Credentials::new(LIVE_SESSION_ACCESS_KEY, VALID_SECRET)
            .and_then(|credentials| credentials.with_session(LIVE_SESSION_TOKEN, live_binding))
            .map_err(|error| SutError::Environment(format!("the live fixture session is not valid: {error}")))?;
        let disabled = Credentials::new(DISABLED_ACCESS_KEY, VALID_SECRET)
            .map_err(|error| SutError::Environment(format!("the disabled fixture credential is not valid: {error}")))?
            .disable();
        let fixture_provider: Arc<dyn CredentialProvider> = Arc::new(
            StaticCredentials::new()
                .with(credentials)
                .with(expired)
                .with(live)
                .with(disabled),
        );
        let provider = match self.case_id.as_str() {
            "c-cred-0005" => {
                let fixture = Arc::clone(&fixture_provider);
                Arc::new(fn_credential_provider(move |access_key_id: &str| {
                    let fixture = Arc::clone(&fixture);
                    let access_key_id = access_key_id.to_owned();
                    Box::pin(async move { fixture.lookup(&access_key_id).await })
                        as BoxFuture<'_, Result<CredentialLookup, ProviderError>>
                })) as Arc<dyn CredentialProvider>
            }
            "c-cred-0011" => Arc::new(fn_credential_provider(|_| {
                Box::pin(async { Err(ProviderError::Backend) }) as BoxFuture<'_, Result<CredentialLookup, ProviderError>>
            })) as Arc<dyn CredentialProvider>,
            "c-cred-0012" => Arc::new(fn_credential_provider(|_| {
                Box::pin(std::future::pending()) as BoxFuture<'_, Result<CredentialLookup, ProviderError>>
            })) as Arc<dyn CredentialProvider>,
            "c-cred-0028" => Arc::new(fn_credential_provider(|_| {
                Box::pin(async {
                    panic!("credential provider panic fixture");
                    #[allow(unreachable_code)]
                    Ok(CredentialLookup::NotFound)
                }) as BoxFuture<'_, Result<CredentialLookup, ProviderError>>
            })) as Arc<dyn CredentialProvider>,
            "c-cred-0006" | "c-cred-0023" => self
                .persistent_credentials
                .lock()
                .ok()
                .and_then(|provider| provider.clone())
                .ok_or_else(|| SutError::Environment("the persistent credential fixture was not prepared".to_owned()))?,
            _ => Arc::new(CountedCredentials {
                inner: fixture_provider,
                calls: Arc::clone(&self.credential_backend_calls),
            }) as Arc<dyn CredentialProvider>,
        };
        let regions =
            RegionSet::new([REGION]).map_err(|error| SutError::Environment(format!("`{REGION}` is not a region: {error}")))?;
        let clock = FixedClock::at_unix_seconds(at_unix_seconds).skewed_by_millis(skew_ms);
        // The fallback is unreachable: `COMMIT_PROGRESS_DEADLINE` is a non-zero constant.
        let deadlines = HandlerDeadlineConfig::default()
            .try_with_commit_progress(crate::sut::COMMIT_PROGRESS_DEADLINE)
            .unwrap_or_default();
        let builder = ServiceBuilder::new()
            .register::<dto::AbortMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::CopyObject, _>(Arc::clone(&backend))
            .register::<dto::CreateBucket, _>(Arc::clone(&backend))
            .register::<dto::CreateMultipartUpload, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucket, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketCors, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketEncryption, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketLifecycle, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketPolicy, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketReplication, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketTagging, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucketWebsite, _>(Arc::clone(&backend))
            .register::<dto::DeleteObject, _>(Arc::clone(&backend))
            .register::<dto::DeleteObjectTagging, _>(Arc::clone(&backend))
            .register::<dto::DeleteObjects, _>(Arc::clone(&backend))
            .register::<dto::DeletePublicAccessBlock, _>(Arc::clone(&backend))
            .register::<dto::GetBucketAccelerateConfiguration, _>(Arc::clone(&backend))
            .register::<dto::GetBucketAcl, _>(Arc::clone(&backend))
            .register::<dto::GetBucketCors, _>(Arc::clone(&backend))
            .register::<dto::GetBucketEncryption, _>(Arc::clone(&backend))
            .register::<dto::GetBucketLifecycleConfiguration, _>(Arc::clone(&backend))
            .register::<dto::GetBucketLocation, _>(Arc::clone(&backend))
            .register::<dto::GetBucketLogging, _>(Arc::clone(&backend))
            .register::<dto::GetBucketNotificationConfiguration, _>(Arc::clone(&backend))
            .register::<dto::GetBucketPolicy, _>(Arc::clone(&backend))
            .register::<dto::GetBucketPolicyStatus, _>(Arc::clone(&backend))
            .register::<dto::GetBucketReplication, _>(Arc::clone(&backend))
            .register::<dto::GetBucketRequestPayment, _>(Arc::clone(&backend))
            .register::<dto::GetBucketTagging, _>(Arc::clone(&backend))
            .register::<dto::GetBucketVersioning, _>(Arc::clone(&backend))
            .register::<dto::GetBucketWebsite, _>(Arc::clone(&backend))
            .register::<dto::GetPublicAccessBlock, _>(Arc::clone(&backend))
            .register::<dto::HeadBucket, _>(Arc::clone(&backend))
            .register::<dto::GetObject, _>(Arc::clone(&backend))
            .register::<dto::GetObjectAcl, _>(Arc::clone(&backend))
            .register::<dto::GetObjectLegalHold, _>(Arc::clone(&backend))
            .register::<dto::GetObjectLockConfiguration, _>(Arc::clone(&backend))
            .register::<dto::GetObjectRetention, _>(Arc::clone(&backend))
            .register::<dto::GetObjectTagging, _>(Arc::clone(&backend))
            .register::<dto::HeadObject, _>(Arc::clone(&backend))
            .register::<dto::ListBuckets, _>(Arc::clone(&backend))
            .register::<dto::ListMultipartUploads, _>(Arc::clone(&backend))
            .register::<dto::ListObjectVersions, _>(Arc::clone(&backend))
            .register::<dto::ListObjects, _>(Arc::clone(&backend))
            .register::<dto::ListObjectsV2, _>(Arc::clone(&backend))
            .register::<dto::ListParts, _>(Arc::clone(&backend))
            .register::<dto::PutBucketAcl, _>(Arc::clone(&backend))
            .register::<dto::PutBucketCors, _>(Arc::clone(&backend))
            .register::<dto::PutBucketAccelerateConfiguration, _>(Arc::clone(&backend))
            .register::<dto::PutBucketEncryption, _>(Arc::clone(&backend))
            .register::<dto::PutBucketLifecycleConfiguration, _>(Arc::clone(&backend))
            .register::<dto::PutBucketLogging, _>(Arc::clone(&backend))
            .register::<dto::PutBucketNotificationConfiguration, _>(Arc::clone(&backend))
            .register::<dto::PutBucketPolicy, _>(Arc::clone(&backend))
            .register::<dto::PutBucketReplication, _>(Arc::clone(&backend))
            .register::<dto::PutBucketRequestPayment, _>(Arc::clone(&backend))
            .register::<dto::PutBucketTagging, _>(Arc::clone(&backend))
            .register::<dto::PutBucketVersioning, _>(Arc::clone(&backend))
            .register::<dto::PutBucketWebsite, _>(Arc::clone(&backend))
            .register::<dto::PutPublicAccessBlock, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .register::<dto::PutObjectAcl, _>(Arc::clone(&backend))
            .register::<dto::PutObjectLegalHold, _>(Arc::clone(&backend))
            .register::<dto::PutObjectLockConfiguration, _>(Arc::clone(&backend))
            .register::<dto::PutObjectRetention, _>(Arc::clone(&backend))
            .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
            .register::<dto::RestoreObject, _>(Arc::clone(&backend))
            .register::<dto::SelectObjectContent, _>(Arc::clone(&backend))
            .register::<dto::UploadPart, _>(Arc::clone(&backend))
            .register::<dto::UploadPartCopy, _>(Arc::clone(&backend))
            .cors_source(FixtureCors {
                state: Arc::clone(&self.state),
            })
            .authenticator(if self.case_id == "c-cred-0012" {
                SigV4Authenticator::with_guard_config(
                    provider,
                    regions,
                    CredentialGuardConfig {
                        budget: LookupBudget::new(
                            std::time::Duration::from_millis(5),
                            std::time::Duration::from_secs(30),
                            std::time::Duration::from_secs(30),
                        ),
                        ..CredentialGuardConfig::default()
                    },
                )
            } else {
                SigV4Authenticator::new(provider, regions)
            });
        let builder = if self.case_id == "c-cred-0024" {
            builder.governor(CredentialClassProbe {
                calls: Arc::clone(&self.credential_governor_calls),
            })
        } else {
            builder
        };
        let builder = match self.case_id.as_str() {
            "c-authz-0005" => builder.authorizer(SameSnapshot { first: Mutex::new(None) }),
            "c-authz-1009" => builder
                .policy_source(policy_from(|_| Err(PolicyError::unavailable())))
                .authorizer(allow_when(|_| true)),
            "c-authz-1010" => builder.authorizer(FixedDecision(Decision::Indeterminate)),
            "c-authz-1014" => {
                let source = Arc::clone(&self.authz_policy_version);
                builder
                    .policy_source(policy_from(move |_| Ok(PolicySnapshot::of(Arc::new(source.load(Ordering::SeqCst))))))
                    .authorizer(HotUpdate {
                        current: Arc::clone(&self.authz_policy_version),
                    })
            }
            _ => builder.authorizer(allow_when(|request| {
                !request.is_anonymous()
                    && !(request.action == "s3:GetObject"
                        && request.bucket.is_some_and(|bucket| bucket.as_str() == "authz-denied-source"))
            })),
        };
        let builder = sigv2::configure_case(builder, &self.case_id);
        let backend_calls = Arc::clone(&self.authz_backend_calls);
        let copy_backend_calls = Arc::clone(&self.authz_backend_calls);
        builder
            .op_layer::<dto::CopyObject, _>(op_layer(move |request: Req<dto::CopyObject>, next: Next<'_, dto::CopyObject>| {
                let backend_calls = Arc::clone(&copy_backend_calls);
                Box::pin(async move {
                    backend_calls.fetch_add(1, Ordering::SeqCst);
                    next.run(request).await
                }) as BoxFuture<'_, HandlerResult<dto::CopyObject>>
            }))
            .op_layer::<dto::UploadPartCopy, _>(op_layer(
                move |request: Req<dto::UploadPartCopy>, next: Next<'_, dto::UploadPartCopy>| {
                    let backend_calls = Arc::clone(&backend_calls);
                    Box::pin(async move {
                        backend_calls.fetch_add(1, Ordering::SeqCst);
                        next.run(request).await
                    }) as BoxFuture<'_, HandlerResult<dto::UploadPartCopy>>
                },
            ))
            // Installed rather than left at the default, because the default reads no host and a
            // `host/` case that could not be answered differently from a path-style one would be a
            // case that cannot fail. Every other family addresses the bare base domain, which has
            // no prefix and is therefore path-style — so this changes nothing for them.
            .host_resolver(
                VirtualHostStyle::new(BASE_DOMAINS)
                    .map_err(|error| SutError::Environment(format!("the base domains are not usable: {error}")))?,
            )
            .clock_with_skew_ack(
                clock,
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .limits(self.limits)
            .config(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES).with_handler_deadlines(deadlines))
            .0
            .build()
            .map_err(|error| SutError::Environment(format!("the service could not be assembled: {error}")))
    }

    /// The wire limits this target assembles its service with.
    pub(crate) const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Moves the fixture's clock, which is what a case's `[clock] fixed` pins.
    pub(crate) fn set_fixture_now(&self, unix_seconds: i64) {
        if let Ok(mut fixture) = self.state.lock() {
            fixture.now = unix_seconds;
        }
    }

    /// Reads a `payload` block into bytes.
    fn payload(&self, payload: &Value) -> Result<Vec<u8>, SutError> {
        // Every source is read before any of them is chosen. Returning from the first branch that
        // matched would leave the later fields unread on a corpus that happens not to use them, and
        // `crate::keys` would then be unable to tell "this harness reads `file`" from "no case
        // wrote `file` this time" — which is the whole distinction it exists to make.
        let utf8 = payload.read("payload.utf8").and_then(Value::as_str);
        let hex = payload.read("payload.hex").and_then(Value::as_str);
        let file = payload.read("payload.file").and_then(Value::as_str);
        let size = payload.read("payload.size").and_then(Value::as_integer);
        let fill = payload.read("payload.fill").and_then(Value::as_str);
        if let Some(text) = utf8 {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(text) = hex {
            return decode_hex(text).ok_or_else(|| SutError::Environment(format!("`{text}` is not valid hex")));
        }
        if let Some(relative) = file {
            let path = self.root.join(relative);
            return std::fs::read(&path)
                .map_err(|error| SutError::Environment(format!("cannot read {}: {error}", path.display())));
        }
        if let Some(size) = size {
            let size = usize::try_from(size).unwrap_or(0);
            return Ok(generate(size, fill));
        }
        Err(SutError::Environment("a payload names no source".to_owned()))
    }
}

/// The fixture's CORS store, read the way a deployment's would be.
///
/// `Ok(None)` covers both "this bucket has no document" and "this bucket does not exist", which is
/// what the trait asks for: a source that distinguished them would be handing the preflight branch
/// a fact it is required to discard.
struct FixtureCors {
    state: Arc<Mutex<Fixture>>,
}

impl CorsSource for FixtureCors {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<dto::CorsConfiguration>, CorsSourceError>> {
        let found = self
            .state
            .lock()
            .ok()
            .and_then(|fixture| fixture.cors(bucket.as_str()).cloned());
        Box::pin(async move { Ok(found) })
    }
}

/// Generates `size` bytes.
///
/// `fill` is read as hex when it is valid hex, because the corpus writes `fill = "ff"` meaning one
/// byte and not two. With no `fill` the pattern is `index % 251`, which is deterministic, has no
/// period that lines up with a power-of-two block size, and is therefore a payload whose corruption
/// a digest actually notices.
fn generate(size: usize, fill: Option<&str>) -> Vec<u8> {
    let pattern = fill
        .and_then(decode_hex)
        .or_else(|| fill.map(|text| text.as_bytes().to_vec()))
        .filter(|bytes| !bytes.is_empty());
    match pattern {
        Some(pattern) => (0..size)
            .map(|index| pattern.get(index % pattern.len()).copied().unwrap_or(0))
            .collect(),
        None => (0..size).map(|index| (index % 251) as u8).collect(),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (*pair.first()? as char).to_digit(16)?;
        let low = (*pair.get(1)? as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// The clock a case declared, or the pinned default.
///
/// An absent `[clock]` is read as an empty table rather than skipped, so that every key of the
/// block is looked at on every case. A read that only happens when some case happens to write the
/// enclosing block is a read the honesty ledger cannot vouch for on a corpus that later drops it.
pub(crate) fn clock_of(clock: Option<&Value>) -> Result<(time::Instant, time::Instant, i64), SutError> {
    let empty = Value::empty_table();
    let clock = clock.unwrap_or(&empty);
    if clock.read("clock.presign_expires_s").is_some() {
        return Err(SutError::Environment(
            "`clock.presign_expires_s` pins the lifetime of a presigned URL, and a presigned mode \
             needs the query-string signing a socket transport owns; the in-process target signs \
             the header form only"
                .to_owned(),
        ));
    }
    if clock.read("clock.advance_ms_between_exchanges").is_some() {
        return Err(SutError::Environment(
            "`clock.advance_ms_between_exchanges` asks for the clock the target observes to move \
             between exchanges; this target pins one instant for the whole case, and answering \
             from a clock that did not move would decide an expiry case on the wrong instant"
                .to_owned(),
        ));
    }
    let fixed = match clock.read("clock.fixed").and_then(Value::as_str) {
        Some(text) => time::parse_rfc3339(text).map_err(SutError::Environment)?,
        None => time::parse_rfc3339(time::DEFAULT_FIXED).map_err(SutError::Environment)?,
    };
    let request_time = match clock.read("clock.request_time").and_then(Value::as_str) {
        Some(text) => time::parse_rfc3339(text).map_err(SutError::Environment)?,
        None => fixed.clone(),
    };
    let skew_ms = clock.read("clock.skew_ms").and_then(Value::as_integer).unwrap_or(0);
    Ok((fixed, request_time, skew_ms))
}

/// Reads `[connection]`, refusing every instruction that needs a socket to mean anything.
///
/// `reuse = true` is the one instruction this target can carry out, and it carries it out by
/// construction: every exchange of a case runs against the same fixture state, which is what
/// "one connection for the whole case" buys a case here. `reuse = false` asks for the opposite and
/// is refused rather than quietly given the same treatment.
fn read_connection(connection: Option<&Value>) -> Result<(), SutError> {
    let empty = Value::empty_table();
    let connection = connection.unwrap_or(&empty);
    if connection.read("connection.pipeline").and_then(Value::as_bool) == Some(true) {
        return Err(SutError::Environment(
            "`connection.pipeline = true` asks for the next request to be written before the \
             previous response is read. There is no connection here: the in-process target performs \
             one `S3Service::call` at a time and the runner reads each response before it builds \
             the next request, so the two writes cannot race. A case whose assertion turns on the \
             race — one winner, and a distinct code telling the loser to retry — would be judged \
             against a strictly ordered pair, where the loser's answer is an ordinary precondition \
             failure. Pipelining needs a transport that owns the socket"
                .to_owned(),
        ));
    }
    if connection.read("connection.tls").is_some() {
        return Err(SutError::Environment(
            "`[connection.tls]` needs a socket to negotiate on; the in-process target hands a \
             parsed `http::Request` to the service and never speaks TLS"
                .to_owned(),
        ));
    }
    if connection.read("connection.read_window_bytes").is_some() {
        return Err(SutError::Environment(
            "`connection.read_window_bytes` induces backpressure by leaving response bytes unread; \
             the in-process target collects the whole body and has no flow-control window"
                .to_owned(),
        ));
    }
    if connection.read("connection.idle_timeout_ms").is_some() {
        return Err(SutError::Environment(
            "`connection.idle_timeout_ms` times out an idle connection, and there is no connection \
             here to leave idle"
                .to_owned(),
        ));
    }
    if connection.read("connection.reuse").and_then(Value::as_bool) == Some(false) {
        return Err(SutError::Environment(
            "`connection.reuse = false` asks for a fresh connection per exchange. There is no \
             connection, and the fixture state a case established is deliberately kept for all of \
             its exchanges, so this target cannot distinguish a fresh connection from a reused one"
                .to_owned(),
        ));
    }
    Ok(())
}

/// One step of a body, in the order the case wrote it.
///
/// A body is not always bytes: `conformance/case.schema.json` lets a chunk sequence carry a control
/// action, and "close the connection here" is as much a part of what a case sends as the payload
/// around it. Modelled as one sequence rather than as bytes plus a footnote, because the two are
/// ordered with respect to each other and a transport that flattened them would lose the ordering
/// that `c-mpu-0043` — bytes, then a half-close — exists to send.
#[derive(Debug, Clone)]
pub(crate) enum ChunkStep {
    /// Payload bytes, written and flushed as one frame.
    Data(Vec<u8>),
    /// A connection-level act.
    Control {
        /// The `controlChunk.action` spelling.
        action: String,
        /// The pause the case asks for before the act.
        delay_ms: u64,
        /// How long a `stall` or `stop_reading` holds.
        duration_ms: u64,
    },
}

/// One request, read out of the case and ready to be signed.
///
/// Deliberately transport-neutral: it records everything a case wrote, including the shapes an
/// in-process call cannot send, and each transport refuses what it cannot carry out **by name**.
/// Reading and refusing used to be the same function, which meant the socket transport could not
/// reuse the reader without also inheriting a refusal of the very cases it exists to run.
#[derive(Debug)]
pub(crate) struct Wire {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    /// The head verbatim, when the case wrote one instead of a structured request line.
    pub(crate) raw_head: Option<Vec<u8>>,
    /// Whether the case scripted HTTP/2 frames, which no transport here can send.
    pub(crate) h2_frames: bool,
    /// The wire version the case asked for.
    pub(crate) http_version: Option<String>,
    /// The whole body, which is what the signature and `Content-Length` are stated over.
    pub(crate) body: Vec<u8>,
    /// The same bytes, still in the pieces the case wrote them in.
    ///
    /// Kept apart from `body` because the pieces are what makes "the server stopped asking part
    /// way through" observable: a body handed over as one frame can only be all-or-nothing.
    pub(crate) frames: Vec<Vec<u8>>,
    /// The body as the case wrote it, control acts included.
    pub(crate) steps: Vec<ChunkStep>,
    pub(crate) sign: Option<Value>,
}

impl Wire {
    /// The control actions this body carries, in order.
    pub(crate) fn control_actions(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().filter_map(|step| match step {
            ChunkStep::Control { action, .. } => Some(action.as_str()),
            ChunkStep::Data(_) => None,
        })
    }
}

impl InProcess {
    /// Reads a `[request]` block, refusing every shape a socketless transport cannot send.
    fn read_request(&self, request: &Value) -> Result<Wire, SutError> {
        let wire = self.read_wire(request)?;
        if wire.raw_head.is_some() {
            return Err(needs_a_socket("raw_head_utf8"));
        }
        if wire.h2_frames {
            return Err(needs_a_socket("h2_frames"));
        }
        if wire.http_version.as_deref() == Some("h2") {
            return Err(SutError::Environment(
                "`request.http_version = \"h2\"` needs a real HTTP/2 framing layer".to_owned(),
            ));
        }
        // A control chunk is refused rather than dropped, because a case that half-closes the
        // connection is asserting something about a socket and answering it from a complete body
        // would be a false green.
        if let Some(action) = wire.control_actions().next() {
            return Err(SutError::Environment(format!(
                "a `{action}` control chunk needs a transport that owns the connection; the \
                 in-process target hands over a complete body"
            )));
        }
        Ok(wire)
    }

    /// Reads a `[request]` block into everything a case wrote, refusing nothing.
    pub(crate) fn read_wire(&self, request: &Value) -> Result<Wire, SutError> {
        // Written out rather than looped over a list of names: `crate::keys` allows one source
        // location to claim one schema key, so that a loop cannot report coverage of keys nothing
        // reads.
        let raw_head_utf8 = request
            .read("requestSpec.raw_head_utf8")
            .and_then(Value::as_str)
            .map(|text| text.as_bytes().to_vec());
        let raw_head_hex = request.read("requestSpec.raw_head_hex").and_then(Value::as_str);
        let raw_head = match (raw_head_utf8, raw_head_hex) {
            (Some(bytes), _) => Some(bytes),
            (None, Some(text)) => {
                Some(decode_hex(text).ok_or_else(|| SutError::Environment(format!("`{text}` is not valid hex")))?)
            }
            (None, None) => None,
        };
        let h2_frames = request.read("requestSpec.h2_frames").is_some();
        let http_version = request
            .read("requestSpec.http_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // A raw head carries its own request line, so the two fields the schema makes mandatory for
        // a structured request are absent by construction and their absence is not an error.
        let method = request
            .read("requestSpec.method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let target = request
            .read("requestSpec.target")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (method, target) = match (method, target, raw_head.is_some()) {
            (Some(method), Some(target), _) => (method, target),
            (_, _, true) => (String::new(), String::new()),
            (None, _, false) => return Err(SutError::Environment("a request has no method".to_owned())),
            (_, None, false) => return Err(SutError::Environment("a request has no target".to_owned())),
        };

        let mut headers = Vec::new();
        if let Some(Value::Table(entries)) = request.read("requestSpec.headers") {
            for (name, value) in entries {
                match value {
                    Value::String(text) => headers.push((name.clone(), text.clone())),
                    Value::Array(items) => {
                        for item in items.iter().filter_map(Value::as_str) {
                            headers.push((name.clone(), item.to_owned()));
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(Value::Array(rows)) = request.read("requestSpec.raw_headers") {
            for row in rows {
                let pair: Vec<&str> = row.as_array().unwrap_or_default().iter().filter_map(Value::as_str).collect();
                if let (Some(name), Some(value)) = (pair.first(), pair.get(1)) {
                    headers.push(((*name).to_owned(), (*value).to_owned()));
                }
            }
        }

        // `host` overrides `Host` / `:authority`, so it replaces whatever the header list said
        // rather than adding a second one. Applied after both header forms for that reason.
        if let Some(host) = request.read("requestSpec.host").and_then(Value::as_str) {
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("host"));
            headers.push(("host".to_owned(), host.to_owned()));
        }

        // One read per line: `crate::keys` allows one source location to claim one schema key.
        let declared_body = request.read("requestSpec.body");
        let declared_chunks = request.read("requestSpec.chunks");
        let steps = match (declared_body, declared_chunks) {
            (Some(payload), _) => vec![ChunkStep::Data(self.payload(payload)?)],
            (None, Some(Value::Array(chunks))) => self.chunks(chunks)?,
            _ => Vec::new(),
        };
        let frames: Vec<Vec<u8>> = steps
            .iter()
            .filter_map(|step| match step {
                ChunkStep::Data(bytes) => Some(bytes.clone()),
                ChunkStep::Control { .. } => None,
            })
            .collect();
        let body = frames.iter().flatten().copied().collect::<Vec<u8>>();

        Ok(Wire {
            method,
            target,
            headers,
            raw_head,
            h2_frames,
            http_version,
            body,
            frames,
            steps,
            sign: request.read("requestSpec.sign").cloned(),
        })
    }

    /// Reads a chunk sequence into the steps it was written as.
    ///
    /// `delay_ms` is not read here by either transport, and the reason has moved rather than gone
    /// away: the in-process target observes no arrival timing at all, and the socket target paces on
    /// the peer instead of on the clock — see `crate::socket`'s module documentation for why a sleep
    /// would make a case's own `terminate_within_ms` a function of the build machine.
    /// `crate::keys::DECLARED` carries the entry that says so.
    ///
    /// What survives here is the *shape* — one frame per chunk, and one per repetition — which is
    /// the half a socketless transport can still measure: a server that stops pulling at the third
    /// of fifty thousand frames is distinguishable from one that drains them all.
    fn chunks(&self, chunks: &[Value]) -> Result<Vec<ChunkStep>, SutError> {
        let mut steps = Vec::new();
        for chunk in chunks {
            if let Some(action) = chunk.read("controlChunk.action").and_then(Value::as_str) {
                steps.push(ChunkStep::Control {
                    action: action.to_owned(),
                    delay_ms: chunk
                        .read("controlChunk.delay_ms")
                        .and_then(Value::as_integer)
                        .unwrap_or(0)
                        .unsigned_abs(),
                    duration_ms: chunk
                        .read("controlChunk.duration_ms")
                        .and_then(Value::as_integer)
                        .unwrap_or(0)
                        .unsigned_abs(),
                });
                continue;
            }
            let repeat = usize::try_from(chunk.read("dataChunk.repeat").and_then(Value::as_integer).unwrap_or(1)).unwrap_or(1);
            let unit = self.chunk_bytes(chunk)?;
            for _ in 0..repeat {
                steps.push(ChunkStep::Data(unit.clone()));
            }
        }
        Ok(steps)
    }

    /// The bytes one data chunk carries.
    ///
    /// A data chunk's `utf8` is its own schema declaration, distinct from a payload's, so the
    /// fields are read one by one here instead of handing the table to [`InProcess::payload`] with
    /// the `raw_` prefixes stripped off. The two forms produce the same bytes in process, because
    /// the framing that `raw_*` exists to bypass is framing a socket transport would add.
    fn chunk_bytes(&self, chunk: &Value) -> Result<Vec<u8>, SutError> {
        // Read before chosen, for the reason given in `InProcess::payload`.
        let utf8 = chunk.read("dataChunk.utf8").and_then(Value::as_str);
        let raw_utf8 = chunk.read("dataChunk.raw_utf8").and_then(Value::as_str);
        let hex = chunk.read("dataChunk.hex").and_then(Value::as_str);
        let raw_hex = chunk.read("dataChunk.raw_hex").and_then(Value::as_str);
        let file = chunk.read("dataChunk.file").and_then(Value::as_str);
        if let Some(text) = utf8.or(raw_utf8) {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(text) = hex.or(raw_hex) {
            return decode_hex(text).ok_or_else(|| SutError::Environment(format!("`{text}` is not valid hex")));
        }
        if let Some(relative) = file {
            let path = self.root.join(relative);
            return std::fs::read(&path)
                .map_err(|error| SutError::Environment(format!("cannot read {}: {error}", path.display())));
        }
        Err(SutError::Environment("a chunk names no source".to_owned()))
    }
}

/// The refusal every request shape that needs a socket shares.
fn needs_a_socket(field: &str) -> SutError {
    SutError::Environment(format!(
        "`request.{field}` needs a transport that writes bytes on a socket; the in-process target \
         hands a parsed `http::Request` to the service and cannot express a malformed head"
    ))
}

/// Splits a request target into its path and its query, neither decoded.
pub(crate) fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// Builds the `http::Request` the service is called with.
fn assemble_request<B>(method: &str, target: &str, headers: &[(String, String)], body: B) -> Result<http::Request<B>, SutError> {
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(body)
        .map_err(|error| SutError::Environment(format!("the request could not be built: {error}")))
}

/// Reads `sign.tamper` into the signer's own description.
fn read_tamper(spec: &Value) -> Result<Tamper, SutError> {
    let component = spec
        .read("signSpec.tamper.component")
        .and_then(Value::as_str)
        .ok_or_else(|| SutError::Environment("a tamper names no component".to_owned()))?;
    let component = match component {
        "signature" => TamperComponent::Signature,
        "access_key" => TamperComponent::AccessKey,
        "scope_date" => TamperComponent::ScopeDate,
        "scope_region" => TamperComponent::ScopeRegion,
        "scope_service" => TamperComponent::ScopeService,
        "signed_headers_list" => TamperComponent::SignedHeadersList,
        "canonical_query" => TamperComponent::CanonicalQuery,
        "canonical_path" => TamperComponent::CanonicalPath,
        "canonical_header_value" => TamperComponent::CanonicalHeaderValue,
        "payload_hash" => TamperComponent::PayloadHash,
        "date_header" => TamperComponent::DateHeader,
        other => return Err(SutError::Environment(format!("unknown tamper component `{other}`"))),
    };
    let mut tamper = Tamper::new(component);
    if let Some(target) = spec.read("signSpec.tamper.target").and_then(Value::as_str) {
        tamper = tamper.with_target(target);
    }
    if let Some(value) = spec.read("signSpec.tamper.new_value").and_then(Value::as_str) {
        tamper = tamper.with_new_value(value);
    }
    if let Some(index) = spec.read("signSpec.tamper.flip_byte_at").and_then(Value::as_integer) {
        tamper = tamper.flip_byte_at(usize::try_from(index).unwrap_or(0));
    }
    Ok(tamper)
}

impl Sut for InProcess {
    fn describe(&self) -> String {
        "rustfs-gateway assembled in process from the facade, over a fixture backend".to_owned()
    }

    fn prepare(&mut self, case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        self.case_id.clear();
        self.case_id.push_str(case_id);
        self.authz_policy_version.store(1, Ordering::SeqCst);
        self.authz_backend_calls.store(0, Ordering::SeqCst);
        self.credential_backend_calls.store(0, Ordering::SeqCst);
        self.credential_exchanges.store(0, Ordering::SeqCst);
        self.credential_governor_calls.store(0, Ordering::SeqCst);
        if let Ok(mut provider) = self.persistent_credentials.lock() {
            *provider = None;
            match case_id {
                "c-cred-0006" => {
                    let counted = Arc::new(CountedCredentials {
                        inner: Arc::new(StaticCredentials::new()),
                        calls: Arc::clone(&self.credential_backend_calls),
                    });
                    *provider = Some(Arc::new(GuardedCredentialProvider::new(counted)));
                }
                "c-cred-0023" => {
                    let credentials = Credentials::new(VALID_ACCESS_KEY, VALID_SECRET)
                        .map_err(|error| SutError::Environment(format!("the deletion fixture is not valid: {error}")))?;
                    *provider = Some(Arc::new(GuardedCredentialProvider::new(Arc::new(DeletedAfterFirstLookup {
                        credentials: Mutex::new(Some(credentials)),
                        calls: Arc::clone(&self.credential_backend_calls),
                    }))));
                }
                _ => {}
            }
        }
        let mut captures = Captures::new();
        let mut fixture = Fixture::at(
            time::parse_rfc3339(time::DEFAULT_FIXED)
                .map_err(SutError::Environment)?
                .unix_seconds,
        );
        let empty = Value::empty_table();
        let setup = setup.unwrap_or(&empty);

        if let Some(cleanup) = setup.read("setup.cleanup").and_then(Value::as_str)
            && cleanup != "auto"
        {
            return Err(SutError::Environment(format!(
                "`setup.cleanup = \"{cleanup}\"` asks for what this case established to survive it; \
                 this target rebuilds the fixture from `[setup]` before every case, so nothing \
                 would be carried over and a case relying on it would run against state it never \
                 declared"
            )));
        }

        if let Some(fault) = setup.read("setup.fault") {
            let operation = fault
                .read("setup.fault.operation")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let at = fault.read("setup.fault.at").and_then(Value::as_str).unwrap_or_default();
            let code = fault.read("setup.fault.code").and_then(Value::as_str).unwrap_or_default();
            // Neither arm restates the operation set; both measure the name against the one list the
            // handlers read. `UploadPartCopy` is why: able to fail after a `200` in the model, and
            // answered here without committing anything for it to fail after.
            let armed = match (at, ErrorCode::known(code)) {
                ("no_progress_after_commit", _) => fixture.arm_committed_stall(operation),
                ("after_commit", Some(code)) => fixture.arm_committed_fault(operation, code),
                ("after_commit", None) => {
                    return Err(SutError::Environment(format!(
                        "`setup.fault.code = \"{code}\"` is not a declared error code, so it has no status and no row; \
                     a fault reporting it would put a code on the wire this workspace does not admit exists"
                    )));
                }
                (other, _) => {
                    return Err(SutError::Environment(format!(
                        "`setup.fault.at = \"{other}\"` is not a point this target can fail at; it arranges \
                     `after_commit` and `no_progress_after_commit`, and nothing else"
                    )));
                }
            };
            if let Err(unreportable) = armed {
                return Err(SutError::Environment(format!(
                    "`setup.fault.operation = \"{}\"` names an operation this target does not commit a head for, \
                     so a fault armed against it would never be reported",
                    unreportable.operation()
                )));
            }
        }

        for bucket in setup.read("setup.buckets").and_then(Value::as_array).unwrap_or_default() {
            let Some(name) = bucket.read("setup.buckets[].name").and_then(Value::as_str) else { continue };
            // A bucket placed outside `REGION` exists but is not served here: the lifecycle
            // handlers answer requests for it with the 301 carrying `x-amz-bucket-region`, which
            // is exactly what the redirect cases exist to observe. Recorded before the declaring
            // insert so the two reads of the key stay one branch apart.
            let foreign_region = bucket
                .read("setup.buckets[].region")
                .and_then(Value::as_str)
                .filter(|region| *region != REGION);
            if bucket
                .read("setup.buckets[].absent")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                fixture.remove_bucket(name);
                continue;
            }
            let versioned = match bucket.read("setup.buckets[].versioning").and_then(Value::as_str) {
                None | Some("disabled") => false,
                Some("enabled") => true,
                Some(other) => {
                    return Err(SutError::Environment(format!(
                        "`setup.buckets[].versioning = \"{other}\"` is not modelled: the fixture has \
                         versioning on or off, and a suspended bucket — which keeps its history but \
                         writes `null` — is a third state whose listings differ from both"
                    )));
                }
            };
            fixture.declare_bucket(name, versioned);
            if let Some(region) = foreign_region {
                fixture.set_bucket_region(name, region);
            }
            // Object lock is what makes a version delete an authorisation decision rather than a
            // lookup; `fixture::Stub::delete_objects` is where it becomes observable.
            let locked = bucket
                .read("setup.buckets[].object_lock")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            fixture.set_object_lock(name, locked);
        }

        for object in setup.read("setup.objects").and_then(Value::as_array).unwrap_or_default() {
            let (Some(bucket), Some(key)) = (
                object.read("setup.objects[].bucket").and_then(Value::as_str),
                object.read("setup.objects[].key").and_then(Value::as_str),
            ) else {
                continue;
            };
            if object
                .read("setup.objects[].absent")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                fixture.remove_object(bucket, key);
                continue;
            }
            let body = match object.read("setup.objects[].body") {
                Some(payload) => self.payload(payload)?,
                None => Vec::new(),
            };
            let now = fixture.now;
            let content_type = object
                .read("setup.objects[].content_type")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let mut stored = StoredObject::new(body, content_type, now);
            if let Some(class) = object.read("setup.objects[].storage_class").and_then(Value::as_str) {
                stored.storage_class = class.to_owned();
            }
            if let Some(Value::Table(entries)) = object.read("setup.objects[].metadata") {
                stored.metadata = entries
                    .iter()
                    .filter_map(|(name, value)| value.as_str().map(|text| (name.clone(), text.to_owned())))
                    .collect::<BTreeMap<_, _>>();
            }
            fixture.put_object(bucket, key, stored);
        }

        for upload in setup
            .read("setup.multipart_uploads")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            let (Some(bucket), Some(key)) = (
                upload.read("setup.multipart_uploads[].bucket").and_then(Value::as_str),
                upload.read("setup.multipart_uploads[].key").and_then(Value::as_str),
            ) else {
                continue;
            };
            let id = fixture.create_upload(bucket, key);
            if let Some(name) = upload
                .read("setup.multipart_uploads[].capture_upload_id_as")
                .and_then(Value::as_str)
            {
                captures.insert(name.to_owned(), id.clone());
            }
            for part in upload
                .read("setup.multipart_uploads[].parts")
                .and_then(Value::as_array)
                .unwrap_or_default()
            {
                let Some(number) = part
                    .read("setup.multipart_uploads[].parts[].part_number")
                    .and_then(Value::as_integer)
                else {
                    continue;
                };
                let body = match part.read("setup.multipart_uploads[].parts[].body") {
                    Some(payload) => self.payload(payload)?,
                    None => Vec::new(),
                };
                let etag = fixture.put_part(&id, i32::try_from(number).unwrap_or(0), body);
                if let Some(name) = part
                    .read("setup.multipart_uploads[].parts[].capture_etag_as")
                    .and_then(Value::as_str)
                {
                    // Captured quoted, because that is the form a case interpolates into an XML
                    // `<ETag>` element and into an `If-Match` header alike.
                    captures.insert(name.to_owned(), format!("\"{etag}\""));
                }
            }
        }

        *self.state.lock().map_err(poisoned)? = fixture;
        Ok(captures)
    }

    fn finish(&mut self, case_id: &str) -> Result<(), SutError> {
        if matches!(case_id, "c-authz-1001" | "c-authz-1011" | "c-authz-1012")
            && self.authz_backend_calls.load(Ordering::SeqCst) != 0
        {
            return Err(SutError::Environment(format!(
                "{case_id} reached the copy backend after authorization refused the source"
            )));
        }
        match case_id {
            "c-cred-0002" if self.credential_backend_calls.load(Ordering::SeqCst) != 0 => {
                return Err(SutError::Environment(
                    "c-cred-0002 called the credential provider for an anonymous request".to_owned(),
                ));
            }
            "c-cred-0006" if self.credential_backend_calls.load(Ordering::SeqCst) >= 100 => {
                return Err(SutError::Environment(
                    "c-cred-0006 sent all 100 misses to the credential backend".to_owned(),
                ));
            }
            "c-cred-0006" if self.credential_exchanges.load(Ordering::SeqCst) != 100 => {
                return Err(SutError::Environment(
                    "c-cred-0006 did not execute exactly 100 identical misses".to_owned(),
                ));
            }
            "c-cred-0024" if self.credential_governor_calls.load(Ordering::SeqCst) != 1 => {
                return Err(SutError::Environment(
                    "c-cred-0024 did not classify the forged key as a credential lookup".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        if self.case_id == "c-cred-0006" {
            self.credential_exchanges.fetch_add(1, Ordering::SeqCst);
        }
        let (fixed, request_time, skew_ms) = clock_of(plan.clock)?;
        read_connection(plan.connection)?;
        if let Ok(mut fixture) = self.state.lock() {
            fixture.now = fixed.unix_seconds;
        }
        let service = self.assemble(fixed.unix_seconds, skew_ms)?;
        let wire = self.read_request(&plan.request)?;

        let mut headers = wire.headers.clone();
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            headers.push(("host".to_owned(), HOST.to_owned()));
        }
        if !wire.body.is_empty() && !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            headers.push(("content-length".to_owned(), wire.body.len().to_string()));
        }

        // A tamper may rewrite the path or the query, and those live in the target rather than in a
        // header. Signing therefore hands back both halves: the head to send, and the target to send
        // it to. Keeping the case's original target here is how `sign.tamper.component =
        // "canonical_query"` used to be signed, rewritten, and then thrown away — the request went
        // out exactly as it had been signed and was answered `200`, so the case measured nothing.
        let (headers, target) = match &wire.sign {
            None => (headers, wire.target.clone()),
            Some(sign) => sign_request(sign, &wire, &headers, &request_time, &self.limits, wire.body.len() as u64)?,
        };

        let (body, progress) = ObservedBody::new(wire.frames.iter().map(|frame| bytes::Bytes::from(frame.clone())));
        let request = assemble_request(&wire.method, &target, &headers, body)?;
        let started = std::time::Instant::now();
        let response = block_on(service.call(request));
        // The head is kept before the body is drained, so that a body which fails halfway can still
        // be reported *as a response that failed halfway* rather than as an environment problem. A
        // drain that consumed the head first would leave the transport with nothing to report but
        // the exception.
        let (parts, payload) = response.into_parts();
        let status = parts.status;
        let head: Vec<(http::HeaderName, http::HeaderValue)> = parts
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let drained = block_on(collect(http::Response::from_parts(parts, payload)));
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

        let render = |pairs: Vec<(http::HeaderName, http::HeaderValue)>| -> Vec<(String, String)> {
            pairs
                .into_iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value
                            .to_str()
                            .map_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned(), ToOwned::to_owned),
                    )
                })
                .collect()
        };

        let rendered_head = render(head);
        let (body, trailers, outcome, termination, before_error, events, notes) = match drained {
            Ok(collected) => {
                let (_, _, body, trailers) = collected.into_parts();
                let body = body.to_vec();
                if has_event_stream_content_type(&rendered_head) {
                    match decode_event_stream(&body) {
                        Ok(events) => (body, trailers, Outcome::EventStream, None, None, events, Vec::new()),
                        Err(error) => (
                            body,
                            trailers,
                            Outcome::StreamError,
                            Some(StreamTermination::MalformedEventStream),
                            None,
                            Vec::new(),
                            vec![format!("the event stream could not be decoded: {error}")],
                        ),
                    }
                } else {
                    // The status line and the document can disagree, and when they do the disagreement
                    // *is* the observation. Everything else about the exchange is unchanged: the head
                    // arrived, the body arrived, and the connection is reusable — what differs is that
                    // the request failed and only the body says so.
                    match late_error_offset(status.as_u16(), &body) {
                        None => (body, trailers, Outcome::Response, None, None, Vec::new(), Vec::new()),
                        Some(offset) => (
                            body,
                            trailers,
                            Outcome::StreamError,
                            Some(StreamTermination::ErrorDocument),
                            Some(offset),
                            Vec::new(),
                            Vec::new(),
                        ),
                    }
                }
            }
            // A body that could not be read to its end is a stream that stopped, which is a fact
            // about the response and not about this harness — reporting it as an environment error
            // would *skip* the case, and a skipped case asserts nothing. The byte count is left
            // unrecorded rather than guessed: `collect` discards what it had read when it failed, so
            // a case pinning `body_bytes_before_error` stays red here and says why.
            Err(_) => (
                Vec::new(),
                Vec::new(),
                Outcome::StreamError,
                Some(StreamTermination::AbruptClose),
                None,
                Vec::new(),
                Vec::new(),
            ),
        };

        Ok(Observation {
            outcome,
            stream_termination: termination,
            status: Some(status.as_u16()),
            http_version: None,
            headers: rendered_head,
            trailers: render(trailers),
            body,
            body_bytes_before_error: before_error,
            // Measured, not assumed. `progress` counts what the service pulled out of the body, and
            // the head above was taken before the body was drained, so what is read here is the
            // state at the moment the response existed.
            request_body_bytes_sent_at_response: Some(progress.bytes_read()),
            request_body_fully_sent: Some(progress.is_exhausted()),
            ttfb_ms: Some(elapsed_ms),
            elapsed_ms,
            // Always `Open`, and never derived from the service's own verdict.
            //
            // `open` is a genuine fact about this transport: there is no connection, and the
            // service is a value that is still callable. `closed` never is. Deriving it from
            // `connection_intent_of` was tried and removed: until f803525 the intent was correct
            // and `render` dropped it, so nothing was ever closed — and a derived
            // `connection_after` would have reported green through that entire period, which is
            // the exact shape this suite has now produced seven times. A note admitting the
            // derivation does not change what the green line means to whoever reads the report.
            //
            // A case that asserts `closed` therefore cannot pass here. `--transport conn` watches
            // the socket and answers for itself.
            connection_after: Some(ConnectionState::Open),
            events,
            notes,
        })
    }
}

fn poisoned<T>(_: T) -> SutError {
    SutError::Environment("the fixture state was left poisoned by an earlier case".to_owned())
}

/// Signs the request the way `sign.mode` asks for.
///
/// Returns the header list **and the request target**, because two of the eleven tamper components
/// — `canonical_path` and `canonical_query` — live in the target rather than in a header. A signer
/// that handed back only the headers would sign a request, rewrite a component of it, and then send
/// the untouched original: a negative case that way round is answered `200`, and its assertions are
/// judged against a request nobody meant to send.
pub(crate) fn sign_request(
    sign: &Value,
    wire: &Wire,
    headers: &[(String, String)],
    request_time: &time::Instant,
    limits: &Limits,
    wire_content_length: u64,
) -> Result<(Vec<(String, String)>, String), SutError> {
    // Split here rather than at each call site: every caller was passing
    // `split_target(&wire.target)` of the very `wire` it also passed, so the two arguments were a
    // second spelling of one that was already present — and a second spelling is a place for the
    // two to disagree.
    let (path, query) = split_target(&wire.target);
    let mode = sign.read("signSpec.mode").and_then(Value::as_str).unwrap_or("sigv4_header");
    match mode {
        "anonymous" | "none" => return Ok((headers.to_vec(), wire.target.clone())),
        "sigv4_header" | "sigv4_unsigned_payload" | "presigned_v4" | "sigv2_header" | "presigned_v2" => {}
        other => {
            return Err(SutError::Environment(format!(
                "`sign.mode = \"{other}\"` is not wired: the in-process target signs SigV4 headers, \
                 unsigned payloads and presigned URLs, plus SigV2 headers and presigned URLs; \
                 streaming and POST-policy modes need their dedicated wire protocol"
            )));
        }
    }

    // The host has to reach the canonical request in the byte-exact form the acceptance layer
    // settled on, and `WireRequest` is the only way to obtain one through the facade. The probe
    // carries the host and nothing else on purpose: a probe built from the real head would be
    // refused for exactly the requests a negative case exists to send — a duplicate `Range`, an
    // oversized query — and the case would be skipped instead of measured.
    let host = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map_or(HOST, |(_, value)| value.as_str());
    let probe = assemble_request("GET", "/", &[("host".to_owned(), host.to_owned())], bytes::Bytes::new())?;
    let accepted = WireRequest::accept(probe, limits)
        .map_err(|error| SutError::Environment(format!("`{host}` is not an acceptable host: {error:?}")))?;

    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        let name: http::HeaderName = name
            .parse()
            .map_err(|_| SutError::Environment(format!("`{name}` is not a header name")))?;
        let value =
            http::HeaderValue::from_str(value).map_err(|_| SutError::Environment(format!("`{value}` is not a header value")))?;
        map.append(name, value);
    }
    let credential = sign.read("signSpec.credential").and_then(Value::as_str).unwrap_or("valid");
    // An expired session token is a distinct identity, not the valid one under another name.
    // Signing it with the fixture's own credentials answered `200` and the case then asserted
    // against a request that was never expired.
    let (access_key, secret, token) = match credential {
        "unknown_access_key" => (UNKNOWN_ACCESS_KEY, VALID_SECRET, None),
        "wrong_secret" => (VALID_ACCESS_KEY, WRONG_SECRET, None),
        "expired_session" => (EXPIRED_SESSION_ACCESS_KEY, VALID_SECRET, Some(EXPIRED_SESSION_TOKEN)),
        "live_session" => (LIVE_SESSION_ACCESS_KEY, VALID_SECRET, Some(LIVE_SESSION_TOKEN)),
        "session_without_token" => (LIVE_SESSION_ACCESS_KEY, VALID_SECRET, None),
        "long_term_with_token" => (VALID_ACCESS_KEY, VALID_SECRET, Some(LIVE_SESSION_TOKEN)),
        "swapped_session_token" => (LIVE_SESSION_ACCESS_KEY, VALID_SECRET, Some(OTHER_SESSION_TOKEN)),
        "disabled" => (DISABLED_ACCESS_KEY, VALID_SECRET, None),
        "empty_secret" => (VALID_ACCESS_KEY, b"" as &[u8], None),
        _ => (VALID_ACCESS_KEY, VALID_SECRET, None),
    };
    let method = http::Method::from_bytes(wire.method.as_bytes())
        .map_err(|_| SutError::Environment(format!("`{}` is not a method", wire.method)))?;
    if matches!(mode, "sigv2_header" | "presigned_v2") {
        let input = sigv2::SignInput::new(sign, &method, path, query, &mut map, accepted.host(), (access_key, secret, token));
        return sigv2::sign(mode, input, request_time, &wire.target);
    }
    let mut credentials = SigningCredentials::new(access_key, secret)
        .map_err(|error| SutError::Environment(format!("the signing credentials are not valid: {error}")))?;
    if let Some(token) = token {
        // The signer mints `x-amz-security-token` and it is an `x-amz-*` header, so it joins
        // `SignedHeaders` on its own. A token the signature did not cover would be refused for a
        // reason that has nothing to do with the expiry the case is measuring.
        let token = SessionToken::new(token)
            .map_err(|error| SutError::Environment(format!("the fixture session token is not valid: {error}")))?;
        credentials = credentials.with_session_token(token);
    }
    let stamp = AmzDate::parse(&request_time.amz_stamp)
        .map_err(|error| SutError::Environment(format!("`{}` is not a SigV4 stamp: {error}", request_time.amz_stamp)))?;
    let region = sign.read("signSpec.region").and_then(Value::as_str).unwrap_or(REGION);
    let service = match sign.read("signSpec.service").and_then(Value::as_str) {
        None | Some("s3") => SigService::S3,
        Some("sts") => SigService::Sts,
        Some(other) => {
            return Err(SutError::Environment(format!(
                "`sign.service = \"{other}\"` is not a service this scope can name"
            )));
        }
    };
    let scope = SigningScope::new(stamp.day(), region, service)
        .map_err(|error| SutError::Environment(format!("the credential scope is not well formed: {error}")))?;

    // Every spelling is decided here. A `payload_hash` this target cannot produce is refused rather
    // than falling through to the computed digest: a case that asked for a streaming or a literal
    // hash and was silently given the correct one asserts nothing about the hash it named.
    let payload = match (mode, sign.read("signSpec.payload_hash").and_then(Value::as_str)) {
        ("sigv4_unsigned_payload" | "presigned_v4", _) | (_, Some("unsigned")) => PayloadMode::Unsigned,
        (_, Some("empty")) => PayloadMode::Empty,
        (_, Some(other @ ("streaming" | "streaming_trailer" | "base64" | "literal"))) => {
            return Err(SutError::Environment(format!(
                "`sign.payload_hash = \"{other}\"` needs the aws-chunked framing a socket transport \
                 owns, or a literal the header signer has no way to substitute"
            )));
        }
        _ if wire.body.is_empty() => PayloadMode::Empty,
        _ => PayloadMode::ExactSha256(crate::sha256::digest(&wire.body)),
    };

    let mut signer = SigV4Signer::new(credentials, scope);
    let mut signing = SigningRequest::new(&method, path, query, &map, accepted.host().raw_for_signing(), payload, stamp);
    let signed_header_names = sign
        .read("signSpec.signed_headers")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(|name| {
                    name.parse::<http::HeaderName>()
                        .map_err(|_| SutError::Environment(format!("`{name}` is not a signed header name")))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    if let Some(names) = signed_header_names.as_deref() {
        signing = signing.with_signed_headers(names);
    }
    // Always declared, including for the empty body: the signed-header rules cross-check
    // `content-length` against the length the wire layer settled on, and omitting it makes a
    // request that declares `content-length: 0` unsignable. The value is the caller's rather than
    // `wire.body.len()`, because a case may *declare* a length it never intends to send —
    // `c-mpu-0027` announces five gigabytes and writes ten bytes — and the signature has to cover
    // the header that is going on the wire, not the payload that follows it.
    signing = signing.with_wire_content_length(wire_content_length);
    let signed = if mode == "presigned_v4" {
        let expires = sign.read("signSpec.expires_s").and_then(Value::as_integer).unwrap_or(900);
        signer.presign(&signing, expires.unsigned_abs())
    } else {
        signer.sign_headers(&signing)
    }
    .map_err(|error| SutError::Environment(format!("the request could not be signed: {error}")))?;
    let signed = match sign.read("signSpec.tamper") {
        None => signed,
        Some(spec) => signed
            .tampered(&read_tamper(spec)?)
            .map_err(|error| SutError::Environment(format!("the request could not be tampered with: {error}")))?,
    };

    let headers = signed
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or_default().to_owned()))
        .collect();
    Ok((headers, rebuild_target(signed.path(), signed.query())))
}

/// Reassembles a request target out of the path and query the signer holds.
///
/// An empty query means no `?` at all: `/b/k?` and `/b/k` are two different request targets and
/// only one of them is what the case wrote.
fn rebuild_target(path: &str, query: &str) -> String {
    if query.is_empty() {
        return path.to_owned();
    }
    let mut target = String::with_capacity(path.len().saturating_add(query.len()).saturating_add(1));
    target.push_str(path);
    target.push('?');
    target.push_str(query);
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_split_into_a_path_and_a_raw_query() {
        assert_eq!(split_target("/b/k?list-type=2&x=1"), ("/b/k", "list-type=2&x=1"));
        assert_eq!(split_target("/b/k"), ("/b/k", ""));
    }

    #[test]
    fn a_generated_payload_is_deterministic_and_honours_a_hex_fill() {
        assert_eq!(generate(4, Some("ff")), vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(generate(3, None), vec![0, 1, 2]);
        assert_eq!(generate(3, None), generate(3, None));
    }

    /// Negative — every request shape that needs a socket is refused by name, so the report says
    /// which capability was missing rather than reporting a wrong answer.
    #[test]
    fn a_raw_head_is_refused_rather_than_approximated() {
        let target = InProcess::new(PathBuf::from("."));
        let request = Value::Table(vec![("raw_head_utf8".to_owned(), Value::String("GET / HTTP/1.1".to_owned()))]);
        let error = target.read_request(&request).expect_err("must be refused");
        assert!(format!("{error}").contains("raw_head_utf8"), "{error}");
    }

    /// Negative — a control chunk is refused, because answering it from a complete body would turn
    /// an abnormal-termination case into a false green.
    ///
    /// Asserted on `read_request`, which is where a request becomes something this target agrees to
    /// send. `chunks` is the parser both transports share and now returns the control act rather
    /// than rejecting it — the socket target has to see it. A test left pointing at the parser
    /// would have gone on passing while measuring the wrong half.
    #[test]
    fn a_control_chunk_is_refused() {
        let target = InProcess::new(PathBuf::from("."));
        let request = Value::Table(vec![
            ("method".to_owned(), Value::String("PUT".to_owned())),
            ("target".to_owned(), Value::String("/b/k".to_owned())),
            (
                "chunks".to_owned(),
                Value::Array(vec![Value::Table(vec![(
                    "action".to_owned(),
                    Value::String("half_close".to_owned()),
                )])]),
            ),
        ]);
        let error = target.read_request(&request).expect_err("must be refused");
        assert!(format!("{error}").contains("half_close"), "{error}");
    }

    #[test]
    fn a_case_without_a_clock_still_runs_at_a_pinned_instant() {
        let (fixed, request_time, skew) = clock_of(None).expect("a default clock");
        assert_eq!(fixed.amz_stamp, "20260102T030405Z");
        assert_eq!(request_time.amz_stamp, fixed.amz_stamp);
        assert_eq!(skew, 0);
    }
}
