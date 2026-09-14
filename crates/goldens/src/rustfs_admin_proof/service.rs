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

//! The proof's assembled service: the facade's SigV4 authenticator, a recording authorizer,
//! governor and CORS source, and a backend that records what each handler was handed.
//!
//! Responsible for: [`assemble`] and what it returns — every question the authorizer was asked
//! ([`AuthzCall`]), every `(operation, bucket)` the governor admitted, every bucket whose CORS
//! document was read — and [`Backend`], the handlers of the four representative operations and of
//! `GetObject` / `ListObjects`, each recording a [`Seen`].
//! NOT responsible for: the operations, their rows or the overlay (`super`, `super::classes`,
//! `super::overlay`), the class operations' one generic handler (`super::classes`), or any
//! assertion (the `*_tests` modules).
//! Upstream: `rustfs-gateway`'s `ServiceBuilder`, the parent's operations and dialect, the shared
//! credential of `operation_diff::context`. Downstream: the proof's test modules.

use std::sync::{Arc, Mutex};

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, CorsSource, CorsSourceError, Credentials, Decision, ErrorCode, Governor,
    GovernorRequest, Handler, HandlerContext, HandlerError, HandlerResult, InputAuthzRequest, InputDecisions, Lease, Req,
    RequestContext, RequestContextView, Resp, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, dto,
};
use rustfs_gateway_sig::{RegionSet, SecurityFloor};
use rustfs_gateway_types::BucketName;

use super::{
    AddServiceAccount, AdminBody, GetBucketQuota, GetBucketQuotaByQuery, GetTier, GetUserInfo, ListAccessKeysBulk,
    ListAccessKeysLdapBulk, ListAccessKeysOpenidBulk, ListPools, OidcAuthorize, OidcCallback, OidcListProviders, OidcLogout,
    ReplicationMetricsV2, SelfAccountInfo, ServerInfo, ServiceRestart, admin_dialect, json, open, same_bytes, seal,
};
use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, REGIONS, SECRET_KEY};

// ── the authorizer ────────────────────────────────────────────────────────────────────────────

/// One question the authorizer was asked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthzCall {
    /// `route`, `input` or `resource`.
    pub(crate) stage: &'static str,
    pub(crate) operation: String,
    pub(crate) action: String,
    pub(crate) caller: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    /// The subject asked about (ADR-0025): `None` for none, `Some(None)` for the caller.
    pub(crate) subject: Option<Option<String>>,
}

type Policy = Box<dyn Fn(&AuthzRequest<'_>) -> bool + Send + Sync>;

/// Records every question and answers it with `policy`.
struct RecordingAuthorizer {
    policy: Policy,
    calls: Arc<Mutex<Vec<AuthzCall>>>,
}

impl RecordingAuthorizer {
    fn decide(&self, stage: &'static str, request: &AuthzRequest<'_>) -> Decision {
        self.calls.lock().expect("uncontended").push(AuthzCall {
            stage,
            operation: request.operation.to_owned(),
            action: request.action.to_owned(),
            caller: request.identity.map(|identity| identity.access_key_id().to_owned()),
            bucket: request.bucket.map(|bucket| bucket.as_str().to_owned()),
            key: request.key.map(|key| key.as_str().to_owned()),
            subject: request.subject.map(|subject| subject.name().map(str::to_owned)),
        });
        if (self.policy)(request) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide("route", request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide("input", request.route());
        let decisions = request.decide_all(stage, |resource| self.decide("resource", resource));
        Box::pin(async move { decisions })
    }
}

// ── the backend ───────────────────────────────────────────────────────────────────────────────

/// What one handler was handed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Seen {
    pub(crate) operation: &'static str,
    pub(crate) caller: Option<String>,
    pub(crate) holds_secret: bool,
    pub(crate) secret_is_the_callers: bool,
    pub(crate) context_debug_shows_secret: bool,
    pub(crate) raw_path: String,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) params: Vec<(String, String)>,
    /// The subject the context carried, as [`AuthzCall::subject`] renders one.
    pub(crate) subject: Option<Option<String>>,
}

/// A backend that records what each handler was handed, and every account it created.
#[derive(Default)]
pub(crate) struct Backend {
    seen: Mutex<Vec<Seen>>,
    created: Mutex<Vec<String>>,
}

impl Backend {
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("uncontended").clone()
    }

    pub(crate) fn created(&self) -> Vec<String> {
        self.created.lock().expect("uncontended").clone()
    }

    pub(crate) fn see(&self, context: &RequestContextView) {
        let principal = context.principal();
        let secret = principal.and_then(|principal| principal.secret_key_from_authenticator_lookup());
        self.seen.lock().expect("uncontended").push(Seen {
            operation: context.operation(),
            caller: principal.map(|principal| principal.access_key_id().to_owned()),
            holds_secret: secret.is_some(),
            secret_is_the_callers: secret.is_some_and(|secret| same_bytes(secret.expose_secret(), SECRET_KEY.as_bytes())),
            context_debug_shows_secret: format!("{context:?}").contains(SECRET_KEY),
            raw_path: context.raw_path().to_owned(),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
            params: context
                .path_params()
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            subject: context.subject().map(|subject| subject.name().map(str::to_owned)),
        });
    }

    fn server_info(&self, request: &Req<ServerInfo>) -> HandlerResult<ServerInfo> {
        self.see(request.context());
        Ok(Resp::new(json(&serde_json::json!({"mode": "online", "servers": 1}))))
    }

    fn add_service_account(&self, request: &Req<AddServiceAccount>) -> HandlerResult<AddServiceAccount> {
        self.see(request.context());
        // Fail closed: without the caller's secret the body cannot be opened, and nothing may be
        // created from a body nobody could read.
        let secret = request
            .context()
            .principal()
            .and_then(|principal| principal.secret_key_from_authenticator_lookup())
            .ok_or_else(|| HandlerError::internal_error("the caller's secret was not handed to this handler"))?;
        let plain = open(secret.expose_secret(), request.input()).ok_or_else(|| {
            HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload does not open under the caller's key")
        })?;
        let asked: serde_json::Value = serde_json::from_slice(&plain)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload is not JSON"))?;
        let access_key = asked["accessKey"]
            .as_str()
            .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload names no access key"))?
            .to_owned();
        self.created.lock().expect("uncontended").push(access_key.clone());
        let answer = serde_json::json!({"credentials": {"accessKey": access_key}}).to_string();
        Ok(Resp::new(AdminBody {
            content_type: "application/octet-stream",
            bytes: seal(secret.expose_secret(), answer.as_bytes()),
        }))
    }

    fn get_tier(&self, request: &Req<GetTier>) -> HandlerResult<GetTier> {
        self.see(request.context());
        // The typed value the template extracted, decoded once; never a second parse of the path.
        let tier: String = request
            .context()
            .path_params()
            .parse("tier")
            .map_err(|_| HandlerError::internal_error("the template bound no tier"))?;
        Ok(Resp::new(json(&serde_json::json!({"tier": tier, "status": "online"}))))
    }

    fn replication_metrics(&self, request: &Req<ReplicationMetricsV2>) -> HandlerResult<ReplicationMetricsV2> {
        self.see(request.context());
        Ok(Resp::new(json(&serde_json::json!({"bucket": request.input().as_str(), "version": 2}))))
    }

    fn get_object(&self, request: &Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        self.see(request.context());
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }

    fn list_objects(&self, request: &Req<dto::ListObjects>) -> HandlerResult<dto::ListObjects> {
        self.see(request.context());
        Ok(Resp::new(dto::ListObjectsOutput::default()))
    }
}

macro_rules! handler {
    ($operation:ty, $method:ident) => {
        impl Handler<$operation> for Backend {
            async fn call(&self, request: Req<$operation>) -> HandlerResult<$operation> {
                self.$method(&request)
            }

            async fn call_with_context(&self, request: Req<$operation>, _context: HandlerContext) -> HandlerResult<$operation> {
                self.$method(&request)
            }
        }
    };
}

handler!(ServerInfo, server_info);
handler!(AddServiceAccount, add_service_account);
handler!(GetTier, get_tier);
handler!(ReplicationMetricsV2, replication_metrics);
handler!(dto::GetObject, get_object);
handler!(dto::ListObjects, list_objects);

// ── the assembled service ─────────────────────────────────────────────────────────────────────

/// How one service is assembled.
#[derive(Clone, Copy)]
pub(crate) struct Options {
    /// Whether the authenticator hands the caller's secret over. The assembly keeps ADR-0024's
    /// default scope, so an operation receives it only when its spec opted in.
    pub(crate) secret_hand_off: bool,
    /// Whether anonymous admission is delegated to the authorizer (ADR-0021).
    pub(crate) delegate_anonymous: bool,
}

/// Every `(operation, bucket)` a governor was asked about.
type Governed = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Admits everything and records the operation and bucket it was asked about: the governor must
/// see a bound bucket exactly as the authorizer does (ADR-0025).
struct RecordingGovernor {
    governed: Governed,
}

impl Governor for RecordingGovernor {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        self.governed
            .lock()
            .expect("uncontended")
            .push((request.operation().to_owned(), request.bucket().map(|bucket| bucket.as_str().to_owned())));
        Box::pin(async { Ok(Lease::admit()) })
    }
}

/// Answers no document and records every bucket whose CORS document was read: a claimed row's
/// bound bucket must never be one of them (ADR-0025).
struct RecordingCors {
    loaded: Arc<Mutex<Vec<String>>>,
}

impl CorsSource for RecordingCors {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<dto::CorsConfiguration>, CorsSourceError>> {
        self.loaded.lock().expect("uncontended").push(bucket.as_str().to_owned());
        Box::pin(async { Ok(None) })
    }
}

/// A service with the admin dialect and two S3 neighbours, and what it records.
pub(crate) struct Assembled {
    pub(crate) service: S3Service,
    pub(crate) backend: Arc<Backend>,
    pub(crate) calls: Arc<Mutex<Vec<AuthzCall>>>,
    /// Every `(operation, bucket)` the governor was asked about.
    pub(crate) governed: Governed,
    /// Every bucket whose CORS document was read.
    pub(crate) cors_loaded: Arc<Mutex<Vec<String>>>,
}

impl Assembled {
    pub(crate) fn calls(&self) -> Vec<AuthzCall> {
        self.calls.lock().expect("uncontended").clone()
    }
}

/// The facade's own SigV4 authenticator over the shared credential, an authorizer that answers
/// with `policy`, the admin dialect, and `GetObject` / `ListObjects` beside it.
pub(crate) fn assemble(options: Options, policy: impl Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static) -> Assembled {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    let regions = RegionSet::new(REGIONS).expect("fixture regions");
    let mut authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
    if options.secret_hand_off {
        authenticator = authenticator.hand_caller_secret_to_handlers();
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let governed = Arc::new(Mutex::new(Vec::new()));
    let cors_loaded = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(Backend::default());
    let mut builder = ServiceBuilder::new()
        .authenticator(authenticator)
        .governor(RecordingGovernor {
            governed: Arc::clone(&governed),
        })
        .cors_source(RecordingCors {
            loaded: Arc::clone(&cors_loaded),
        })
        .authorizer(RecordingAuthorizer {
            policy: Box::new(policy),
            calls: Arc::clone(&calls),
        })
        .dialect(&admin_dialect())
        .register::<ServerInfo, _>(Arc::clone(&backend))
        .register::<AddServiceAccount, _>(Arc::clone(&backend))
        .register::<GetTier, _>(Arc::clone(&backend))
        .register::<ReplicationMetricsV2, _>(Arc::clone(&backend))
        .register::<ListPools, _>(Arc::clone(&backend))
        .register::<SelfAccountInfo, _>(Arc::clone(&backend))
        .register::<GetUserInfo, _>(Arc::clone(&backend))
        .register::<GetBucketQuota, _>(Arc::clone(&backend))
        .register::<ServiceRestart, _>(Arc::clone(&backend))
        .register::<ListAccessKeysBulk, _>(Arc::clone(&backend))
        .register::<ListAccessKeysLdapBulk, _>(Arc::clone(&backend))
        .register::<ListAccessKeysOpenidBulk, _>(Arc::clone(&backend))
        .register::<GetBucketQuotaByQuery, _>(Arc::clone(&backend))
        .register::<OidcListProviders, _>(Arc::clone(&backend))
        .register::<OidcAuthorize, _>(Arc::clone(&backend))
        .register::<OidcCallback, _>(Arc::clone(&backend))
        .register::<OidcLogout, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::ListObjects, _>(Arc::clone(&backend));
    if options.delegate_anonymous {
        builder =
            builder.security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report());
    }
    Assembled {
        service: builder.build().expect("a complete assembly"),
        backend,
        calls,
        governed,
        cors_loaded,
    }
}
