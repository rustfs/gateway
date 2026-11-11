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

//! RustFS's STS endpoint through both stacks (rustfs/gateway#1232, ADR-0041 and ADR-0044): the same signed or
//! unsigned `POST /` sent to the legacy stack, configured as RustFS configures it with RustFS's STS
//! route in front, and to an assembled gateway with the RustFS profile's authentication, routing and
//! answer switches and the `rustfs` dialect.
//!
//! Responsible for: the request matrix — every signature form legacy RustFS verifies, forged and
//! unknown credentials, no credentials at all, path-style and virtual-hosted, a bucket label RustFS
//! would refuse, S3 operation keys in the query, the media type's spellings, and a body past the
//! claimed-route ceiling — and the comparison of what each stack answered (status, error code,
//! message, identifiers) and what its STS handler was handed (whether it ran, the caller's access
//! key, the body).
//! NOT responsible for: what RustFS's STS handler does with the body (RustFS's own), routing
//! without a service (the dialect crate's `sts_form` tests), or the inventory binding
//! (`rustfs_admin_dialect::tests`).
//! Upstream: the pinned legacy stack, the facade, the signature crate's signers, the dialect.
//! Downstream: nothing.
//!
//! # The legacy side
//!
//! The pinned legacy stack with RustFS's configuration (`rustfs_s3_config`: SigV2 enabled, `s3tables`
//! added to the signing services, rustfs/rustfs `95268a3b9` `rustfs/src/server/http.rs:166-173`), its
//! virtual-host domain, one credential, and a route standing for RustFS's admin router on these
//! requests: `is_match` is RustFS's STS predicate (`rustfs/src/server/layer.rs:878-886`), and
//! `check_access` lets an unsigned STS request through, refuses a credentialed one signed with
//! SigV2, in the `Authorization` header or the query, `AccessDenied`, and lets every other signed
//! one through. The SigV2 refusal is the one RustFS's router applies to its custom routes, the STS
//! form included, because SigV2 covers neither their query arguments nor their body:
//! <https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/router.rs#L3391-L3421>
//! is the refusal, and `#L3560-L3620` the access check that applies it once credentials are
//! present (rustfs/gateway#1592, ADR-0052). Its third arm, a credentialed `multipart/form-data`
//! POST, is not restated: such a request is not the STS form and never reaches this route. RustFS's
//! unsigned `x-amz-*` guard in the same check is not restated either: no request here carries an
//! unsigned `x-amz-*` header, and the gateway's guard has its own parity proofs
//! (rustfs/gateway#1120).

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, Method, Request};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerResult, InputAuthzRequest, InputDecisions,
    LegacyRustfsVirtualHosts, PresignedExpiryRule, Req, RequestContext, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials,
};
use rustfs_gateway_dialect_rustfs_admin::AdminResponse;
use rustfs_gateway_dialect_rustfs_admin::ops::sts_form_post::StsFormPost;
use rustfs_gateway_dialect_rustfs_admin::rustfs_admin_dialect;
use rustfs_gateway_sig::{RegionSet, RequestNow, SecurityFloor, SigService};

use self::sent::{Sent, Signing};
use super::block_on;
use super::context::{ACCESS_KEY, BASE_DOMAIN, SECRET_KEY, verifying_at};
use super::s3s as legacy;

mod sec1;
mod secret;
mod sent;
mod sigv2;

const FORM: &str = "application/x-www-form-urlencoded";
const REGION: &str = "us-east-1";
/// The base domain itself: a path-style request on both stacks.
const PATH_HOST: &str = BASE_DOMAIN;
const FORGED: &str = "not-the-sts-secret";
const ANSWER: &[u8] = b"<AssumeRoleResponse/>";

// ── what each side recorded ─────────────────────────────────────────────────────────────────

/// What an STS handler was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Handed {
    /// The caller's access key, or `None` for an anonymous request.
    caller: Option<String>,
    /// The body, as handed.
    body: Vec<u8>,
}

/// What one stack answered.
#[derive(Debug, PartialEq, Eq)]
struct Answered {
    status: u16,
    /// The error document's `<Code>` and `<Message>`, for a refusal.
    code: Option<String>,
    message: Option<String>,
    /// Whether the answer names a request: `x-amz-request-id`, `x-request-id` or `x-amz-id-2`.
    identified: bool,
    handed: Option<Handed>,
}

fn element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    Some(body[start..end].to_owned())
}

/// The headers that name a request.
const IDENTIFIERS: [&str; 3] = ["x-amz-request-id", "x-request-id", "x-amz-id-2"];

fn answered(status: u16, identified: bool, body: &[u8], handed: Option<Handed>) -> Answered {
    let text = String::from_utf8_lossy(body);
    let refused = status >= 300;
    Answered {
        status,
        code: refused.then(|| element(&text, "Code")).flatten(),
        message: refused.then(|| element(&text, "Message")).flatten(),
        identified,
        handed,
    }
}

// ── the legacy side ─────────────────────────────────────────────────────────────────────────

/// RustFS's STS predicate, as `rustfs/src/server/layer.rs:878-886` writes it.
fn is_sts_query_request(method: &Method, uri: &http::Uri, headers: &HeaderMap) -> bool {
    method == Method::POST
        && uri.path() == "/"
        && headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(FORM))
}

/// Whether SigV2 signed `req`: an `Authorization` value in its scheme, or a `Signature` query key.
/// RustFS decodes the query key first; every fixture here spells it literally, so this does not.
fn signed_with_sigv2(req: &legacy::S3Request<legacy::Body>) -> bool {
    let header = req
        .headers
        .get_all(http::header::AUTHORIZATION)
        .iter()
        .any(|value| value.as_bytes().starts_with(b"AWS "));
    let query = req
        .uri
        .query()
        .unwrap_or_default()
        .split('&')
        .any(|pair| pair.split('=').next() == Some("Signature"));
    header || query
}

/// RustFS's admin router on these requests: the STS predicate, the STS branch of its access check,
/// and a handler that records what it was handed.
struct LegacyStsRoute {
    handed: Arc<Mutex<Option<Handed>>>,
}

type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl legacy::route::S3Route for LegacyStsRoute {
    fn is_match(&self, method: &Method, uri: &http::Uri, headers: &HeaderMap, _extensions: &mut http::Extensions) -> bool {
        is_sts_query_request(method, uri, headers)
    }

    // The pinned trait is declared with `#[async_trait]`; these are the signatures that attribute
    // expands a `&self` method to, spelled out as the sibling harnesses do.
    fn check_access<'life0, 'life1, 'future>(
        &'life0 self,
        req: &'life1 mut legacy::S3Request<legacy::Body>,
    ) -> Boxed<'future, legacy::S3Result<()>>
    where
        'life0: 'future,
        'life1: 'future,
        Self: 'future,
    {
        // An unsigned STS request is let through; a signed one is let through unless SigV2 signed
        // it, which RustFS refuses on its custom routes (see the module documentation).
        let sts = is_sts_query_request(&req.method, &req.uri, &req.headers);
        let result = match (&req.credentials, sts) {
            (None, true) => Ok(()),
            (None, false) => Err(legacy::S3Error::with_message(
                legacy::S3ErrorCode::AccessDenied,
                "Signature is required".to_owned(),
            )),
            (Some(_), _) if signed_with_sigv2(req) => Err(legacy::S3Error::with_message(
                legacy::S3ErrorCode::AccessDenied,
                "Header or query Signature Version 4 is required for this operation".to_owned(),
            )),
            (Some(_), _) => Ok(()),
        };
        Box::pin(async move { result })
    }

    fn call<'life0, 'future>(
        &'life0 self,
        mut req: legacy::S3Request<legacy::Body>,
    ) -> Boxed<'future, legacy::S3Result<legacy::S3Response<legacy::Body>>>
    where
        'life0: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let body = req
                .input
                .store_all_limited(1 << 20)
                .await
                .map_err(|_| legacy::S3Error::with_message(legacy::S3ErrorCode::InvalidRequest, "body".to_owned()))?;
            *self.handed.lock().expect("uncontended") = Some(Handed {
                caller: req.credentials.map(|credentials| credentials.access_key),
                body: body.to_vec(),
            });
            Ok(legacy::S3Response::new(legacy::Body::from(Bytes::from_static(ANSWER))))
        })
    }
}

/// A backend with no S3 operation: a request the route does not take is answered `501`.
struct NoOperations;

impl legacy::S3 for NoOperations {}

fn legacy_answer(request: &Request<Bytes>) -> Answered {
    let handed = Arc::new(Mutex::new(None));
    let mut builder = legacy::service::S3ServiceBuilder::new(NoOperations);
    builder.set_auth(legacy::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    builder.set_host(legacy::host::MultiDomain::new([BASE_DOMAIN]).expect("the base domain"));
    builder.set_route(LegacyStsRoute {
        handed: Arc::clone(&handed),
    });
    let mut config = legacy::config::S3Config::default();
    config.normalize_forward_slash_path = true;
    config.enable_sig_v2 = true;
    config.sig_v4_allowed_services.push("s3tables".to_owned());
    builder.set_config(Arc::new(legacy::config::StaticConfigProvider::new(Arc::new(config))));
    let service = builder.build();
    let (parts, body) = request.clone().into_parts();
    let body = if body.is_empty() {
        legacy::Body::empty()
    } else {
        legacy::Body::from(body)
    };
    let response = block_on(service.call(Request::from_parts(parts, body))).expect("the legacy stack answers");
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).expect("a bounded answer");
    let handed = handed.lock().expect("uncontended").take();
    let identified = IDENTIFIERS.iter().any(|name| parts.headers.contains_key(*name));
    answered(parts.status.as_u16(), identified, &body, handed)
}

// ── the gateway side ────────────────────────────────────────────────────────────────────────

/// Records what the STS handler was handed, and answers what the legacy route answers.
struct Sts {
    handed: Arc<Mutex<Option<Handed>>>,
}

impl Handler<StsFormPost> for Sts {
    async fn call(&self, request: Req<StsFormPost>) -> HandlerResult<StsFormPost> {
        let caller = request
            .context()
            .principal()
            .map(|principal| principal.access_key_id().to_owned());
        *self.handed.lock().expect("uncontended") = Some(Handed {
            caller,
            body: request.input().to_vec(),
        });
        Ok(Resp::new(AdminResponse::bytes("", ANSWER.to_vec())))
    }
}

/// Every question an authorizer was asked: the action, and the caller's access key or none.
type Asked = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Allows the STS label, as RustFS's adapter must: legacy RustFS asks no policy before its STS
/// handler. Records every question with its caller.
struct StsLabelOnly {
    asked: Asked,
}

impl StsLabelOnly {
    fn decide(&self, request: &AuthzRequest<'_>) -> Decision {
        self.asked.lock().expect("uncontended").push((
            request.action.to_owned(),
            request.identity.map(|identity| identity.access_key_id().to_owned()),
        ));
        if request.action == "rustfs:AssumeRoleHandle" {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl Authorizer for StsLabelOnly {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide(request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide(request.route());
        let decisions = request.decide_all(stage, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The RustFS profile's authentication, routing and answer switches, as `compat/sut` assembles
/// them, with the `rustfs` dialect and an STS handler.
fn gateway(now: RequestNow, handed: &Arc<Mutex<Option<Handed>>>, asked: &Asked) -> S3Service {
    gateway_builder(now, asked)
        .register::<StsFormPost, _>(Arc::new(Sts {
            handed: Arc::clone(handed),
        }))
        .build()
        .expect("a complete assembly")
}

/// The same assembly, before the test selects its recording or refusing handler.
fn gateway_builder(now: RequestNow, asked: &Asked) -> ServiceBuilder {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    gateway_builder_on(now, asked, rustfs_profile_floor(), Arc::new(StaticCredentials::new().with(credentials)))
}

/// The RustFS profile's security floor, as `compat/sut` assembles it.
fn rustfs_profile_floor() -> SecurityFloor {
    SecurityFloor::new()
        .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
        .enable_sigv2_presigned_compatibility()
        .with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs)
        .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
        .recognize_signatures_as_legacy_rustfs()
}

/// [`gateway_builder`] behind `floor`, resolving credentials through `provider`.
fn gateway_builder_on(
    now: RequestNow,
    asked: &Asked,
    floor: SecurityFloor,
    provider: Arc<dyn rustfs_gateway::CredentialProvider>,
) -> ServiceBuilder {
    gateway_builder_authenticating(now, asked, floor, authenticator_over(provider))
}

/// The RustFS profile's authenticator over the shared credential, handing no secret over.
fn authenticator() -> SigV4Authenticator {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    authenticator_over(Arc::new(StaticCredentials::new().with(credentials)))
}

/// The RustFS profile's authenticator, resolving credentials through `provider`.
fn authenticator_over(provider: Arc<dyn rustfs_gateway::CredentialProvider>) -> SigV4Authenticator {
    SigV4Authenticator::new(provider, RegionSet::new([REGION]).expect("a region"))
        .accept_any_signing_region()
        .accept_empty_signing_region()
        .refuse_unreadable_signing_regions_after_verification()
        .accept_signing_regions_of_any_length()
        .verify_paths_as_legacy_rustfs()
        .accept_legacy_rustfs_signing_services()
        .answer_credential_scope_refusals_as_legacy_rustfs()
        .read_signed_headers_as_legacy_rustfs()
}

/// [`gateway_builder`] with `authenticator`, behind the RustFS profile's floor.
fn gateway_builder_with(now: RequestNow, asked: &Asked, authenticator: SigV4Authenticator) -> ServiceBuilder {
    gateway_builder_authenticating(now, asked, rustfs_profile_floor(), authenticator)
}

/// The assembly behind `floor`, authenticating with `authenticator`.
fn gateway_builder_authenticating(
    now: RequestNow,
    asked: &Asked,
    floor: SecurityFloor,
    authenticator: SigV4Authenticator,
) -> ServiceBuilder {
    let dialect = rustfs_admin_dialect().expect("the generated record and declarations agree");
    verifying_at(ServiceBuilder::new(), now)
        .authenticator(authenticator)
        .security_floor(floor)
        .authorizer(StsLabelOnly {
            asked: Arc::clone(asked),
        })
        .framework_governor_rates(unlimited_rates())
        .sign_presigned_payloads_as_unsigned()
        .sign_base64_payload_digests_as_hex()
        .answer_header_signatures_as_legacy_rustfs()
        .answer_presigned_urls_as_legacy_rustfs()
        .refuse_unsized_buffered_bodies_as_legacy_rustfs()
        .bound_claimed_route_bodies_as_legacy_rustfs()
        .bound_buffered_bodies_as_legacy_rustfs()
        .refuse_unsigned_amz_headers_before_routing()
        .answer_body_refusals_with_legacy_rustfs_sentences()
        .answer_credential_refusals_with_legacy_rustfs_sentences()
        .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
        .address_paths_as_legacy_rustfs()
        .select_operations_as_legacy_rustfs()
        .host_resolver(LegacyRustfsVirtualHosts::new([BASE_DOMAIN]).expect("the base domain"))
        .identify_requests_as_legacy_rustfs()
        .dialect(&dialect)
}

fn unlimited_rates() -> rustfs_gateway::GovernorRates {
    let unlimited = rustfs_gateway::Rate::unlimited();
    rustfs_gateway::GovernorRates {
        aggregate: unlimited,
        per_ip: unlimited,
        credential_lookup: unlimited,
        cors_preflight: unlimited,
        unauthenticated: unlimited,
        tracked_clients: rustfs_gateway::GovernorRates::default().tracked_clients,
    }
}

/// What the gateway answered, and every question its authorizer was asked.
fn gateway_answer(request: &Request<Bytes>, now: RequestNow) -> (Answered, Vec<(String, Option<String>)>) {
    let handed = Arc::new(Mutex::new(None));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let service = gateway(now, &handed, &asked);
    let response = block_on(service.call_bytes(request.clone()));
    let collected = block_on(rustfs_gateway::collect(response)).expect("an in-memory answer");
    let handed = handed.lock().expect("uncontended").take();
    let asked = std::mem::take(&mut *asked.lock().expect("uncontended"));
    let identified = collected
        .headers()
        .iter()
        .any(|(name, _)| IDENTIFIERS.contains(&name.as_str()));
    (answered(collected.status().as_u16(), identified, collected.body(), handed), asked)
}

/// Sends `sent` through both stacks, signed once.
fn both(sent: &Sent) -> (Answered, Answered, Vec<(String, Option<String>)>) {
    let now = RequestNow::capture();
    let request = sent.request(now);
    let legacy = legacy_answer(&request);
    let (gateway, asked) = gateway_answer(&request, now);
    (legacy, gateway, asked)
}

fn same(sent: &Sent) -> Answered {
    let (legacy, gateway, _) = both(sent);
    assert_eq!(gateway, legacy, "{sent:?}");
    legacy
}

// ── the matrix ──────────────────────────────────────────────────────────────────────────────

const STS_SECRET: &str = SECRET_KEY;

fn handed(caller: Option<&str>, sent: &Sent) -> Option<Handed> {
    Some(Handed {
        caller: caller.map(str::to_owned),
        body: sent.body.to_vec(),
    })
}

/// SigV4 header signatures preserve legacy parity; ordinary AssumeRole SigV4 query credentials
/// are refused by the gateway under ADR-0044; SigV2, header or presigned, is refused by both
/// stacks under ADR-0052. The legacy observations remain explicit for every signing mode.
#[test]
fn ordinary_assume_role_preserves_header_modes_and_refuses_query_credentials() {
    for signing in [
        Signing::Header {
            service: "sts",
            send_digest: false,
            secret: STS_SECRET,
        },
        Signing::Header {
            service: "sts",
            send_digest: true,
            secret: STS_SECRET,
        },
        Signing::Header {
            service: "s3",
            send_digest: true,
            secret: STS_SECRET,
        },
        Signing::Header {
            service: "s3tables",
            send_digest: true,
            secret: STS_SECRET,
        },
        Signing::HeaderUnsigned { service: "s3" },
        Signing::Presigned {
            service: SigService::S3,
            secret: STS_SECRET,
        },
        Signing::Presigned {
            service: SigService::Sts,
            secret: STS_SECRET,
        },
        Signing::V2Header { secret: STS_SECRET },
        Signing::V2Presigned,
    ] {
        let sent = Sent::new(signing);
        let (legacy, gateway, _) = both(&sent);
        if refuses_sigv2(&sent, &legacy, &gateway) {
            continue;
        }
        assert_eq!(legacy.status, 200);
        assert!(legacy.handed == handed(Some(ACCESS_KEY), &sent));
        assert!(!legacy.identified);
        if matches!(signing, Signing::Presigned { .. }) {
            assert_eq!(gateway.status, 403);
            assert_eq!(gateway.code.as_deref(), Some("AccessDenied"));
            assert!(gateway.handed.is_none());
        } else {
            assert!(gateway == legacy, "header authentication retains the legacy result");
        }
    }
}

/// For a SigV2-signed `sent`, checks that both stacks refused it `403 AccessDenied` and ran no
/// handler (ADR-0052), and answers `true`; answers `false` for any other signing.
fn refuses_sigv2(sent: &Sent, legacy: &Answered, gateway: &Answered) -> bool {
    if !matches!(sent.signing(), Signing::V2Header { .. } | Signing::V2Presigned) {
        return false;
    }
    for (stack, answer) in [("legacy", legacy), ("gateway", gateway)] {
        assert_eq!(answer.status, 403, "{stack}: {sent:?}: {answer:?}");
        assert_eq!(answer.code.as_deref(), Some("AccessDenied"), "{stack}: {sent:?}: {answer:?}");
        assert!(answer.handed.is_none(), "{stack}: {sent:?}: {answer:?}");
    }
    true
}

/// Anonymous Web Identity and other downstream action contracts retain parity; ordinary
/// AssumeRole is refused before its handler under ADR-0044.
#[test]
fn anonymous_form_admission_obeys_the_decoded_action_contract() {
    for body in [
        &b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=x.y.z"[..],
        b"Action=AssumeRoleWithClientGrants&Token=x.y.z",
        b"Action=AssumeRole&Version=2011-06-15",
        b"",
    ] {
        let sent = Sent::new(Signing::Anonymous).body(Bytes::from_static(body));
        let (legacy, gateway, asked) = both(&sent);
        assert_eq!(legacy.status, 200);
        assert!(legacy.handed == handed(None, &sent));
        if body == b"Action=AssumeRole&Version=2011-06-15" {
            assert_eq!(gateway.status, 403);
            assert_eq!(gateway.code.as_deref(), Some("AccessDenied"));
            assert!(gateway.handed.is_none());
            assert_eq!(asked, [("rustfs:AssumeRoleHandle".to_owned(), None)]);
            continue;
        }
        assert!(gateway == legacy, "independent action admission retains the legacy result");
        // Both stages ask the STS label, with no identity.
        assert_eq!(
            asked,
            [
                ("rustfs:AssumeRoleHandle".to_owned(), None),
                ("rustfs:AssumeRoleHandle".to_owned(), None)
            ]
        );
    }
}

/// The STS route retains its host, query and media-type predicate. Its ordinary-action
/// admission follows ADR-0044 after that route is selected, and SigV2 is refused on it by both
/// stacks (ADR-0052).
#[test]
fn the_sts_endpoint_is_taken_on_every_host_and_query_and_media_type_spelling() {
    let signed = Signing::Header {
        service: "sts",
        send_digest: false,
        secret: STS_SECRET,
    };
    for sent in [
        Sent::new(signed).host("photos.example.test"),
        Sent::new(signed).host("Bad_Bucket.example.test"),
        Sent::new(Signing::Anonymous).host("Bad_Bucket.example.test"),
        Sent::new(signed).query("delete"),
        Sent::new(signed).host("photos.example.test").query("delete"),
        Sent::new(Signing::Anonymous).query("uploads&x-id=DeleteObjects"),
        Sent::new(signed).query("Action=AssumeRole&Version=2011-06-15"),
        Sent::new(signed).content_type(Some("APPLICATION/X-WWW-FORM-URLENCODED")),
        Sent::new(signed).content_type(Some("application/x-www-form-urlencoded; charset=utf-8")),
        Sent::new(Signing::V2Header { secret: STS_SECRET }).host("photos.example.test"),
        Sent::new(Signing::V2Header { secret: STS_SECRET }).host("Bad_Bucket.example.test"),
        Sent::new(Signing::V2Presigned).host("photos.example.test"),
        Sent::new(Signing::Presigned {
            service: SigService::Sts,
            secret: STS_SECRET,
        })
        .host("photos.example.test"),
    ] {
        let (legacy, gateway, _) = both(&sent);
        if refuses_sigv2(&sent, &legacy, &gateway) {
            continue;
        }
        assert_eq!(legacy.status, 200);
        assert!(legacy.handed.is_some());
        let expected_code = match sent.signing() {
            Signing::Anonymous | Signing::Presigned { .. } => Some("AccessDenied"),
            _ => None,
        };
        if let Some(code) = expected_code {
            assert_eq!(gateway.status, 403);
            assert_eq!(gateway.code.as_deref(), Some(code));
            assert!(gateway.handed.is_none());
        } else {
            assert!(gateway == legacy, "header authentication retains the legacy result");
        }
    }
}

/// Negative — ordinary AssumeRole on a virtual host remains subject to its action-specific
/// credential contract (ADR-0044); a SigV2 presigned one is refused by both stacks (ADR-0052).
#[test]
fn ordinary_assume_role_on_a_virtual_host_refuses_query_credentials() {
    for signing in [
        Signing::Presigned {
            service: SigService::S3,
            secret: STS_SECRET,
        },
        Signing::V2Presigned,
    ] {
        let sent = Sent::new(signing)
            .host("photos.example.test")
            .query("delete")
            .body(Bytes::from_static(b"Action=AssumeRole&Version=2011-06-15&DurationSeconds=43200"));
        let (legacy, gateway, _) = both(&sent);
        if refuses_sigv2(&sent, &legacy, &gateway) {
            continue;
        }
        assert_eq!(legacy.status, 200);
        assert!(legacy.handed == handed(Some(ACCESS_KEY), &sent));
        assert_eq!(gateway.status, 403);
        assert_eq!(gateway.code.as_deref(), Some("AccessDenied"));
        assert!(gateway.handed.is_none());
    }
}

/// Negative — a known difference (ADR-0041): the facade's request acceptance refuses a repeated
/// `Content-Type` before anything routes, where legacy RustFS reads the first value and serves STS.
/// It fails closed: the gateway runs no handler and asks no authorizer.
#[test]
fn n_a_repeated_content_type_is_refused_before_routing_where_legacy_rustfs_serves_sts() {
    let now = RequestNow::capture();
    let mut request = Sent::new(Signing::Anonymous).request(now);
    request
        .headers_mut()
        .append(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
    let legacy = legacy_answer(&request);
    let (gateway, asked) = gateway_answer(&request, now);
    assert_eq!(legacy.status, 200, "{legacy:?}");
    assert!(legacy.handed.is_some(), "{legacy:?}");
    assert_eq!(gateway.status, 400, "{gateway:?}");
    assert!(gateway.handed.is_none(), "{gateway:?}");
    assert!(asked.is_empty(), "{asked:?}");
}

/// Negative — a forged SigV4 header or presigned signature is refused on both stacks with the same
/// status, code and message, and neither runs the STS handler. A forged SigV2 header is refused
/// `403` by both and runs no handler, with a known difference in the code: legacy RustFS verifies
/// the signature before its router's SigV2 refusal and answers `SignatureDoesNotMatch`, where the
/// gateway refuses SigV2 at the floor before any credential is resolved and answers
/// `AccessDenied` (ADR-0052), the same answer a correctly signed one gets.
#[test]
fn n_a_forged_credential_is_refused_and_runs_no_handler() {
    for signing in [
        Signing::Header {
            service: "sts",
            send_digest: false,
            secret: FORGED,
        },
        Signing::Header {
            service: "s3",
            send_digest: true,
            secret: FORGED,
        },
        Signing::Presigned {
            service: SigService::Sts,
            secret: FORGED,
        },
    ] {
        let sent = Sent::new(signing);
        let answer = same(&sent);
        assert_eq!(answer.status, 403, "{signing:?}");
        assert!(answer.handed.is_none(), "{signing:?}");
    }
    let (legacy, gateway, asked) = both(&Sent::new(Signing::V2Header { secret: FORGED }));
    assert_eq!(
        (legacy.status, legacy.code.as_deref()),
        (403, Some("SignatureDoesNotMatch")),
        "{legacy:?}"
    );
    assert_eq!((gateway.status, gateway.code.as_deref()), (403, Some("AccessDenied")), "{gateway:?}");
    assert_eq!((legacy.handed, gateway.handed), (None, None));
    assert!(asked.is_empty(), "{asked:?}");
}

/// Negative — an access key nobody issued is refused `403` on both stacks and runs no handler. The
/// oracle's credential callback answers `NotSignedUp` where RustFS IAM and the facade's provider
/// contract answer `InvalidAccessKeyId`, as for every other operation (`error_parity::form_method`).
#[test]
fn n_an_unknown_access_key_is_refused_and_runs_no_handler() {
    let (legacy, gateway, asked) = both(&Sent::new(Signing::UnknownKey));
    assert_eq!((gateway.status, legacy.status), (403, 403));
    assert_eq!(gateway.code.as_deref(), Some("InvalidAccessKeyId"));
    assert_eq!(legacy.code.as_deref(), Some("NotSignedUp"));
    assert_eq!((gateway.handed, legacy.handed), (None, None));
    assert!(asked.is_empty(), "{asked:?}");
}

/// Negative — a signature over a body other than the one sent is refused on both stacks, under the
/// `sts` digest RustFS computes and under a digest the request declares.
#[test]
fn n_a_signature_over_another_body_is_refused() {
    let signing = Signing::Header {
        service: "sts",
        send_digest: false,
        secret: STS_SECRET,
    };
    let now = RequestNow::capture();
    let mut request = Sent::new(signing).request(now);
    *request.body_mut() = Bytes::from_static(b"Action=AssumeRole&Version=2011-06-15&DurationSeconds=43200");
    let legacy = legacy_answer(&request);
    let (gateway, _) = gateway_answer(&request, now);
    assert_eq!(gateway, legacy);
    assert_eq!(legacy.status, 403);
    assert!(legacy.handed.is_none());
}

/// Negative — near misses of the predicate are not the STS endpoint on either stack: `POST //`, a
/// bucket path, a longer media type, no media type. Neither runs the STS handler.
#[test]
fn n_a_near_miss_of_the_sts_predicate_is_not_the_sts_endpoint() {
    let signed = Signing::Header {
        service: "s3",
        send_digest: true,
        secret: STS_SECRET,
    };
    for sent in [
        Sent::new(signed).path("//"),
        Sent::new(signed).path("/bucket"),
        Sent::new(signed).content_type(Some("application/x-www-form-urlencoded-x")),
        Sent::new(signed).content_type(None),
    ] {
        let (legacy, gateway, _) = both(&sent);
        assert!(legacy.handed.is_none(), "{sent:?}: {legacy:?}");
        assert!(gateway.handed.is_none(), "{sent:?}: {gateway:?}");
    }
}

/// Negative — a declared body past 1 MiB is refused `400 EntityTooLarge` with legacy RustFS's
/// sentence once the signature verifies, and `403` first when it does not; neither runs the handler.
#[test]
fn n_a_body_past_the_claimed_route_ceiling_is_refused_after_the_signature() {
    let large = Bytes::from(vec![b'a'; (1 << 20) + 1]);
    let valid = Sent::new(Signing::HeaderUnsigned { service: "s3" }).body(large.clone());
    let answer = same(&valid);
    assert_eq!((answer.status, answer.code.as_deref()), (400, Some("EntityTooLarge")), "{answer:?}");
    assert!(answer.handed.is_none());
    let forged = Sent::new(Signing::Header {
        service: "s3",
        send_digest: true,
        secret: FORGED,
    })
    .body(large);
    let answer = same(&forged);
    assert_eq!(answer.status, 403, "{answer:?}");
    assert!(answer.handed.is_none());
}
