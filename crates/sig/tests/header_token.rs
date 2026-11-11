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

//! The host-verified header token claim at the security floor (ADR-0050, rustfs/gateway#1586).
//!
//! Responsible for: the claim's grammar; admission of a lone claimed header on the operations
//! that admit the scheme and on no other; refusal, before any admission exists, of the header
//! beside every other credential surface, of a repeated, empty or misshapen value, and under a
//! floor that carries no claim; and what a verification yields — a header-token verdict from a
//! verifier that accepts, a rejection from one that refuses, never an anonymous verdict.
//! NOT responsible for: the facade's wiring of the verifier, its panic boundary and its contexts
//! (`rustfs-gateway`'s `tests/header_token.rs`), or the compile-time guarantees (the doctests in
//! `src/header_token.rs`).
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use std::sync::atomic::{AtomicUsize, Ordering};

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::{Limits, TransportExtensions, WireRequest};
use rustfs_gateway_sig::{
    Admission, AuthError, CustomAuthScheme, CustomSchemeRegistry, HeaderTokenAdmission, HeaderTokenClaim, HeaderTokenRefused,
    HeaderTokenRequest, HeaderTokenVerifier, Identity, OperationFloor, QueryBearerClaim, RawQuery, RequestNow, SecurityFloor,
    SigService, WireView,
};

use crate::security_floor_fixtures::*;

const HEADER: &str = "x-auth-token";
/// The token every case presents. A sentinel, so "no rendering holds it" is a search for bytes.
const TOKEN: &str = "gAAAAABsentinel-header-token";
const PRINCIPAL: &str = "KEYSTONEUSER";

fn claim() -> HeaderTokenClaim {
    HeaderTokenClaim::new(HEADER).expect("a legal claim")
}

/// The claim on the default floor, on the RustFS-profile recognition, and on a floor with every
/// service-level widening switched on. No policy of the floor may change what the claim admits.
fn claimed_floors() -> [(&'static str, SecurityFloor); 3] {
    [
        ("default", SecurityFloor::new().with_header_token_claim(claim())),
        (
            "legacy-recognition",
            SecurityFloor::new()
                .recognize_signatures_as_legacy_rustfs()
                .with_header_token_claim(claim()),
        ),
        (
            "widened",
            SecurityFloor::new()
                .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                .enable_sigv2_presigned_compatibility()
                .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                .recognize_signatures_as_legacy_rustfs()
                .with_header_token_claim(claim()),
        ),
    ]
}

fn standard_op() -> OperationFloor {
    OperationFloor::builtin("PutObject", SigService::S3)
}

fn with_token(extra: &[(&str, &str)]) -> HeaderMap {
    let mut pairs = vec![(HEADER, TOKEN)];
    pairs.extend_from_slice(extra);
    header_map(&pairs)
}

/// What an admission decided, as one word: the variant, or the refusal's code.
fn shape(admitted: &Result<Admission<'_>, AuthError>) -> String {
    match admitted {
        Ok(Admission::Sealed(_)) => "sealed".to_owned(),
        Ok(Admission::SealedSigV2(_)) => "sealed-sigv2".to_owned(),
        Ok(Admission::Custom(_)) => "custom".to_owned(),
        Ok(Admission::Anonymous(_)) => "anonymous".to_owned(),
        Ok(Admission::Bearer(_)) => "bearer".to_owned(),
        Ok(Admission::HeaderToken(_)) => "header-token".to_owned(),
        Ok(_) => "unknown".to_owned(),
        Err(error) => format!("refused:{}", error.code()),
    }
}

fn admit<'a>(
    floor: &SecurityFloor,
    headers: &'a HeaderMap,
    query: &'a str,
    form: Option<&'a [(&'a str, &'a str)]>,
    operation: &OperationFloor,
) -> Result<Admission<'a>, AuthError> {
    let view = WireView::new(headers, RawQuery::new(query));
    let view = match form {
        Some(fields) => view.with_form_fields(fields),
        None => view,
    };
    floor.admit(view, operation, now())
}

fn admission_of(floor: &SecurityFloor, headers: &HeaderMap, operation: &OperationFloor) -> HeaderTokenAdmission {
    match admit(floor, headers, "", None, operation) {
        Ok(Admission::HeaderToken(admission)) => admission,
        other => panic!("expected a header-token admission, got {}", shape(&other)),
    }
}

/// Reports [`PRINCIPAL`] for every request, and counts how often it was asked.
#[derive(Default)]
struct Accepts(AtomicUsize);

impl HeaderTokenVerifier for Accepts {
    fn verify(&self, _request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Identity::new(PRINCIPAL).map_err(|_| HeaderTokenRefused)
    }
}

struct Refuses;

impl HeaderTokenVerifier for Refuses {
    fn verify(&self, _request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
        Err(HeaderTokenRefused)
    }
}

/// What a host's outer layer leaves in the request for its verifier to report.
struct Established(&'static str);

/// A verifier as a host writes one: it reports the identity its outer layer installed in this
/// request, and refuses when there is none.
struct ReportsWhatTheOuterLayerInstalled;

impl HeaderTokenVerifier for ReportsWhatTheOuterLayerInstalled {
    fn verify(&self, request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
        let established = request.server_state::<Established>().ok_or(HeaderTokenRefused)?;
        Identity::new(established.0).map_err(|_| HeaderTokenRefused)
    }
}

/// The transport values of an accepted request that carries `installed`, or nothing.
fn server_state(installed: Option<Established>) -> TransportExtensions {
    let mut request = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(())
        .expect("a fixture request");
    if let Some(established) = installed {
        request.extensions_mut().insert(established);
    }
    WireRequest::accept(request, &Limits::default())
        .expect("an accepted fixture")
        .transport_extensions()
        .clone()
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

/// Positive — a lowercase header name outside the AWS surface is a claim, and names its header.
#[test]
fn a_lowercase_header_name_outside_the_aws_surface_is_a_claim() {
    for name in ["x-auth-token", "x-storage-token", "token", "x-9"] {
        assert_eq!(HeaderTokenClaim::new(name).map(|claim| claim.header()), Ok(name), "{name}");
    }
}

/// Negative — an empty, uppercase, malformed or AWS-owned name is no claim. `authorization` and
/// `x-amz-` belong to the signature path; `:` would name an HTTP/2 pseudo-header.
#[test]
fn n_a_name_outside_the_grammar_or_inside_the_aws_surface_is_no_claim() {
    for name in [
        "",
        "X-Auth-Token",
        "x-Auth-token",
        "authorization",
        "x-amz-auth-token",
        "x-amz-",
        "x-amz-security-token",
        "x_auth_token",
        "x auth token",
        "x-auth-token ",
        ":authority",
        "x-auth-token:",
        "-auth-token",
        "9-auth-token",
        "x-auth-t\u{f6}ken",
        "x-auth-token\r\n",
    ] {
        assert!(HeaderTokenClaim::new(name).is_err(), "{name:?} must not be a claim");
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Positive — a request whose only credential is the claimed header is admitted as a header
/// token on a standard operation, whatever else the floor is configured to do.
#[test]
fn a_lone_claimed_header_is_admitted_as_a_header_token() {
    for (name, floor) in claimed_floors() {
        let headers = with_token(&[]);
        for operation in [
            standard_op(),
            s3_object_op(),
            standard_op().allow_anonymous_after_listing_in_the_posture_report(),
            standard_op().allow_post_policy(),
        ] {
            let admitted = admit(&floor, &headers, "", None, &operation);
            assert_eq!(shape(&admitted), "header-token", "{name}: {operation:?}");
            assert!(floor.admits_header_token(&operation), "{name}: the predicate agrees");
        }
        let admission = admission_of(&floor, &headers, &standard_op());
        assert_eq!(admission.operation(), "PutObject", "{name}");
    }
}

/// Negative — without the claim the header is read by nothing: every request is decided exactly
/// as the same request without the header is, and no operation admits the scheme. The claimed
/// floor beside it is the control that the header can decide anything at all.
#[test]
fn n_a_floor_without_the_claim_reads_the_header_as_nothing() {
    let signed = signed_headers(SIGNED_AT);
    let mut signed_with_token = signed.clone();
    signed_with_token.insert(HEADER, HeaderValue::from_static(TOKEN));
    let anonymous_op = standard_op().allow_anonymous_after_listing_in_the_posture_report();
    let cases: [(&str, HeaderMap, HeaderMap, OperationFloor); 3] = [
        ("anonymous-admitting", HeaderMap::new(), with_token(&[]), anonymous_op),
        ("header-only", HeaderMap::new(), with_token(&[]), standard_op()),
        ("signed", signed, signed_with_token, standard_op()),
    ];
    for unclaimed in [
        SecurityFloor::new(),
        SecurityFloor::new().recognize_signatures_as_legacy_rustfs(),
        SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report(),
    ] {
        assert_eq!(unclaimed.header_token_claim(), None);
        for (name, without, with, operation) in &cases {
            let expected = shape(&admit(&unclaimed, without, "", None, operation));
            assert_ne!(expected, "header-token", "{name}");
            assert_eq!(shape(&admit(&unclaimed, with, "", None, operation)), expected, "{name}: {unclaimed:?}");
            assert!(!unclaimed.admits_header_token(operation), "{name}: nothing admits an unclaimed scheme");
        }
    }
    let claimed = SecurityFloor::new().with_header_token_claim(claim());
    assert_eq!(claimed.header_token_claim(), Some(claim()));
    assert_eq!(shape(&admit(&claimed, &with_token(&[]), "", None, &standard_op())), "header-token");
    // And the claimed floor leaves a request that does not carry the header alone.
    for (name, without, _, operation) in &cases {
        assert_eq!(
            shape(&admit(&claimed, without, "", None, operation)),
            shape(&admit(&SecurityFloor::new(), without, "", None, operation)),
            "{name}"
        );
    }
}

/// One other credential surface, presented beside the token.
struct Surface {
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
    query: &'static str,
    form: Option<&'static [(&'static str, &'static str)]>,
}

const fn header_surface(name: &'static str, headers: &'static [(&'static str, &'static str)]) -> Surface {
    Surface {
        name,
        headers,
        query: "",
        form: None,
    }
}

const fn query_surface(name: &'static str, query: &'static str) -> Surface {
    Surface {
        name,
        headers: &[],
        query,
        form: None,
    }
}

const fn form_surface(name: &'static str, form: &'static [(&'static str, &'static str)]) -> Surface {
    Surface {
        name,
        headers: &[],
        query: "",
        form: Some(form),
    }
}

/// Every credential surface the floor's own detection names, each in the spellings it reads.
const OTHER_SURFACES: &[Surface] = &[
    header_surface(
        "sigv4 authorization",
        &[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        )],
    ),
    header_surface(
        "sigv2 authorization",
        &[("authorization", "AWS AKIDEXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=")],
    ),
    header_surface("another scheme's authorization", &[("authorization", "Bearer opaque")]),
    header_surface("an unreadable authorization", &[("authorization", "garbage")]),
    header_surface("an empty authorization", &[("authorization", "")]),
    header_surface(
        "a repeated authorization",
        &[
            ("authorization", "AWS4-HMAC-SHA256 a"),
            ("authorization", "AWS4-HMAC-SHA256 b"),
        ],
    ),
    header_surface("a session token header", &[("x-amz-security-token", "session")]),
    query_surface("X-Amz-Algorithm", "X-Amz-Algorithm=AWS4-HMAC-SHA256"),
    query_surface(
        "X-Amz-Credential",
        "X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fs3%2Faws4_request",
    ),
    query_surface("X-Amz-Signature", "X-Amz-Signature=5fa00fa3"),
    query_surface("a repeated X-Amz-Signature", "X-Amz-Signature=5fa00fa3&X-Amz-Signature=5fa00fa4"),
    query_surface("an escaped X-Amz-Signature", "X-Amz-%53ignature=5fa00fa3"),
    query_surface("X-Amz-Security-Token", "X-Amz-Security-Token=session"),
    query_surface("AWSAccessKeyId", "AWSAccessKeyId=AKIDEXAMPLE"),
    query_surface("Signature", "Signature=frJIUN8DYpKDtOLCwo%2F%2FyllqDzg%3D"),
    query_surface(
        "a whole sigv2 presigned query",
        "AWSAccessKeyId=AKIDEXAMPLE&Expires=1440938160&Signature=frJIUN8D",
    ),
    form_surface("form x-amz-algorithm", &[("x-amz-algorithm", "AWS4-HMAC-SHA256")]),
    form_surface(
        "form x-amz-credential",
        &[("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request")],
    ),
    form_surface("form x-amz-signature", &[("X-Amz-Signature", "5fa00fa3")]),
    form_surface("form x-amz-security-token", &[("x-amz-security-token", "session")]),
    form_surface("form AWSAccessKeyId", &[("AWSAccessKeyId", "AKIDEXAMPLE")]),
    form_surface("form signature", &[("signature", "frJIUN8DYpKDtOLCwo//yllqDzg=")]),
    form_surface("form policy", &[("policy", "eyJleHBpcmF0aW9uIjoiIn0=")]),
    form_surface("a form with no signing field", &[("key", "photos/a.jpg")]),
    form_surface("an empty form", &[]),
];

/// Negative — the token beside any other credential surface is refused `AccessDenied` by the
/// floor itself: no admission exists, so no verifier of either credential can be asked. The same
/// request without the token keeps its own answer on the claimed floor, which is what makes the
/// refusal the token's doing.
#[test]
fn n_the_token_beside_any_other_credential_surface_is_refused() {
    // A post-policy operation, so that a form is refused for the token and not for the allow-list.
    let operation = s3_object_op().allow_post_policy();
    for (floor_name, floor) in claimed_floors() {
        for surface in OTHER_SURFACES {
            let at = format!("{floor_name}: {}", surface.name);
            let both = with_token(surface.headers);
            let admitted = admit(&floor, &both, surface.query, surface.form, &operation);
            assert_eq!(shape(&admitted), "refused:AccessDenied", "{at}");

            let alone = header_map(surface.headers);
            let unclaimed = match floor_name {
                "default" => SecurityFloor::new(),
                "legacy-recognition" => SecurityFloor::new().recognize_signatures_as_legacy_rustfs(),
                _ => SecurityFloor::new()
                    .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                    .enable_sigv2_presigned_compatibility()
                    .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                    .recognize_signatures_as_legacy_rustfs(),
            };
            assert_eq!(
                shape(&admit(&floor, &alone, surface.query, surface.form, &operation)),
                shape(&admit(&unclaimed, &alone, surface.query, surface.form, &operation)),
                "{at}: without the token the claimed floor answers as an unclaimed one"
            );
        }
    }
}

/// Negative — the token beside the routed operation's own query bearer token, and on that
/// operation without one, is refused: the parameter is a credential surface, and a bearer-claimed
/// route does not admit the scheme. The bearer token alone keeps its bearer admission.
#[test]
fn n_the_token_on_a_bearer_claimed_operation_is_refused_with_or_without_the_query_token() {
    let bearer_claim = QueryBearerClaim::new("token", ".zip");
    for (floor_name, floor) in claimed_floors() {
        for operation in [
            OperationFloor::custom("example:Download", SigService::S3).with_query_bearer_claim(bearer_claim),
            // Not privileged, so only the claim itself can be what refuses.
            standard_op().with_query_bearer_claim(bearer_claim),
        ] {
            let headers = with_token(&[]);
            for query in ["token=opaque", "note=x&token=opaque", "", "note=x"] {
                let admitted = admit(&floor, &headers, query, None, &operation);
                assert_eq!(shape(&admitted), "refused:AccessDenied", "{floor_name}: {query:?}");
            }
            assert!(!floor.admits_header_token(&operation), "{floor_name}");
            let none = HeaderMap::new();
            assert_eq!(
                shape(&admit(&floor, &none, "token=opaque", None, &operation)),
                "bearer",
                "{floor_name}: the control"
            );
        }
    }
}

/// Negative — a header under a registered custom scheme beside the token is refused, and so is a
/// claim whose own header falls under a registered prefix: neither verifier is chosen over the
/// other. The custom header alone keeps its custom admission.
#[test]
fn n_the_token_beside_a_registered_custom_scheme_is_refused() {
    let registry = |prefix: &'static str| {
        let mut registry = CustomSchemeRegistry::new();
        registry
            .register(CustomAuthScheme::new(prefix).expect("a legal prefix"))
            .expect("the first registration cannot conflict");
        registry
    };
    let floor = SecurityFloor::new()
        .with_custom_schemes(registry("x-vendor-auth-"))
        .with_header_token_claim(claim());
    let both = with_token(&[("x-vendor-auth-token", "opaque")]);
    assert_eq!(shape(&admit(&floor, &both, "", None, &standard_op())), "refused:AccessDenied");
    let custom_alone = header_map(&[("x-vendor-auth-token", "opaque")]);
    assert_eq!(shape(&admit(&floor, &custom_alone, "", None, &standard_op())), "custom", "the control");
    assert_eq!(
        shape(&admit(&floor, &with_token(&[]), "", None, &standard_op())),
        "header-token",
        "the control"
    );

    let overlapping = SecurityFloor::new()
        .with_custom_schemes(registry("x-auth-"))
        .with_header_token_claim(claim());
    let admitted = admit(&overlapping, &with_token(&[]), "", None, &standard_op());
    assert_eq!(shape(&admitted), "refused:AccessDenied", "one header, two schemes: neither is chosen");
}

fn token_headers(values: &[&[u8]]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for value in values {
        map.append(
            HeaderName::from_static(HEADER),
            HeaderValue::from_bytes(value).expect("a value the transport would carry"),
        );
    }
    map
}

/// Negative — a repeated, empty or misshapen value is refused: no occurrence is chosen over
/// another, a list is not a token, and interior whitespace, a control byte or a non-ASCII byte is
/// not one either. One well-formed value is the control.
#[test]
fn n_a_repeated_empty_or_misshapen_token_is_refused() {
    let refused: &[(&str, &[&[u8]])] = &[
        ("repeated, different", &[b"first", b"second"]),
        ("repeated, equal", &[b"same", b"same"]),
        ("repeated, one empty", &[b"token", b""]),
        ("empty", &[b""]),
        ("a list", &[b"first,second"]),
        ("a list with a space", &[b"first, second"]),
        ("a trailing comma", &[b"token,"]),
        ("interior space", &[b"to ken"]),
        ("interior tab", &[b"to\tken"]),
        ("only a space", &[b" "]),
        ("a non-ASCII byte", &[b"tok\xe9n"]),
        ("an obs-text byte", &[b"\x80token"]),
    ];
    for (floor_name, floor) in claimed_floors() {
        for (name, values) in refused {
            let headers = token_headers(values);
            let admitted = admit(&floor, &headers, "", None, &standard_op());
            assert_eq!(shape(&admitted), "refused:AccessDenied", "{floor_name}: {name}");
        }
        for value in [&b"t"[..], b"gAAAAAB_-.~+/=", b"!#$%&'*^`|:;<>?@[]{}()\"\\"] {
            let headers = token_headers(&[value]);
            assert_eq!(shape(&admit(&floor, &headers, "", None, &standard_op())), "header-token", "{floor_name}");
        }
    }
}

/// Positive and negative — the longest token the floor reads is admitted, and one byte more is
/// refused. The floor bounds the value itself because the facade removes it before acceptance
/// counts the head.
#[test]
fn the_longest_token_is_admitted_and_one_byte_more_is_refused() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    assert_eq!(HeaderTokenClaim::MAX_TOKEN_BYTES, 8192);
    let longest = vec![b'a'; HeaderTokenClaim::MAX_TOKEN_BYTES];
    let headers = token_headers(&[&longest]);
    assert_eq!(shape(&admit(&floor, &headers, "", None, &standard_op())), "header-token");
    let too_long = vec![b'a'; HeaderTokenClaim::MAX_TOKEN_BYTES + 1];
    let headers = token_headers(&[&too_long]);
    assert_eq!(shape(&admit(&floor, &headers, "", None, &standard_op())), "refused:AccessDenied");
}

/// Negative — the name is matched as HTTP matches one: any case of it is the claimed header, and
/// a name that merely resembles it is a different header, read by nothing.
#[test]
fn n_only_the_claimed_name_presents_a_token_in_any_case() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    for spelling in ["X-Auth-Token", "X-AUTH-TOKEN", "x-auth-token"] {
        let headers = header_map(&[(spelling, TOKEN)]);
        assert!(claim().presented(&headers), "{spelling}");
        assert_eq!(shape(&admit(&floor, &headers, "", None, &standard_op())), "header-token", "{spelling}");
    }
    let anonymous_op = standard_op().allow_anonymous_after_listing_in_the_posture_report();
    for other in ["x_auth_token", "x-auth-token2", "auth-token", "x-auth", "x-storage-token"] {
        let headers = header_map(&[(other, TOKEN)]);
        assert!(!claim().presented(&headers), "{other}");
        assert_eq!(shape(&admit(&floor, &headers, "", None, &anonymous_op)), "anonymous", "{other}");
        assert_eq!(
            shape(&admit(&floor, &headers, "", None, &standard_op())),
            "refused:AccessDenied",
            "{other}"
        );
    }
}

/// Negative — a privileged operation, a bearer-claimed one and one that requires SigV4 under every
/// policy refuse the scheme on every floor, whatever else each admits; the standard operations
/// beside them are the control. The predicate the posture report reads answers as `admit` does.
#[test]
fn n_privileged_bearer_claimed_and_sigv4_only_operations_refuse_the_scheme() {
    let refusing = [
        ("third-party default", OperationFloor::custom("example:Admin", SigService::S3)),
        ("marked privileged", admin_op()),
        (
            "privileged and anonymous",
            OperationFloor::custom("example:Bootstrap", SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
        ),
        (
            "bearer-claimed",
            standard_op().with_query_bearer_claim(QueryBearerClaim::new("token", ".zip")),
        ),
        (
            "sigv4 under every policy",
            OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3).require_sigv4_under_every_policy(),
        ),
        (
            "sigv4 under every policy, anonymous opted in",
            OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3)
                .require_sigv4_under_every_policy()
                .allow_anonymous_after_listing_in_the_posture_report(),
        ),
    ];
    let admitting = [
        ("header-only", standard_op()),
        ("presigned", OperationFloor::builtin_presigned("GetObject", SigService::S3)),
        ("anonymous", standard_op().allow_anonymous_after_listing_in_the_posture_report()),
    ];
    for (floor_name, floor) in claimed_floors() {
        let headers = with_token(&[]);
        for (name, operation) in &refusing {
            let admitted = admit(&floor, &headers, "", None, operation);
            assert_eq!(shape(&admitted), "refused:AccessDenied", "{floor_name}: {name}");
            assert!(!floor.admits_header_token(operation), "{floor_name}: {name}");
        }
        for (name, operation) in &admitting {
            assert_eq!(
                shape(&admit(&floor, &headers, "", None, operation)),
                "header-token",
                "{floor_name}: {name}"
            );
            assert!(floor.admits_header_token(operation), "{floor_name}: {name}");
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Positive — a verifier that accepts yields a header-token verdict naming its principal: not a
/// signed verdict, not an anonymous one, with no scope, and asked exactly once.
#[test]
fn a_verifier_that_accepts_yields_a_header_token_verdict() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let verifier = Accepts::default();
    let admission = admission_of(&floor, &with_token(&[]), &standard_op());
    let verdict = admission.verify(&verifier, &TransportExtensions::default());
    assert_eq!(verifier.0.load(Ordering::SeqCst), 1);
    let receipt = verdict.header_token_receipt().expect("a header-token verdict");
    assert_eq!(receipt.identity().access_key_id(), PRINCIPAL);
    assert_eq!(receipt.operation(), "PutObject");
    assert_eq!(verdict.identity().map(Identity::access_key_id), Some(PRINCIPAL));
    assert!(!verdict.is_authenticated(), "no signature was compared");
    assert!(!verdict.is_anonymous());
    assert!(verdict.rejection().is_none() && verdict.verified_scope().is_none() && verdict.bearer_receipt().is_none());
}

/// Negative — a verifier that refuses yields `AccessDenied`: no principal, no receipt, and never
/// an anonymous verdict.
#[test]
fn n_a_verifier_that_refuses_yields_a_rejection_and_never_anonymous() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let admission = admission_of(&floor, &with_token(&[]), &standard_op());
    let verdict = admission.verify(&Refuses, &TransportExtensions::default());
    assert_eq!(verdict.rejection(), Some(AuthError::AccessDenied));
    assert!(verdict.header_token_receipt().is_none() && verdict.identity().is_none());
    assert!(!verdict.is_anonymous() && !verdict.is_authenticated());
}

/// Negative and positive — a verifier that reports what the host's outer layer installed refuses
/// a request in which nothing was installed, and reports the installed identity otherwise. An
/// absent identity is a rejection, not an anonymous request.
#[test]
fn n_an_identity_nobody_installed_is_a_rejection() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = with_token(&[]);

    let nothing = admission_of(&floor, &headers, &standard_op()).verify(&ReportsWhatTheOuterLayerInstalled, &server_state(None));
    assert_eq!(nothing.rejection(), Some(AuthError::AccessDenied));
    assert!(!nothing.is_anonymous() && nothing.identity().is_none());

    let installed = admission_of(&floor, &headers, &standard_op())
        .verify(&ReportsWhatTheOuterLayerInstalled, &server_state(Some(Established("PROJECTMEMBER"))));
    assert_eq!(installed.identity().map(Identity::access_key_id), Some("PROJECTMEMBER"));

    // An identity that could not enter an audit record is refused by the verifier's own check.
    let unusable = admission_of(&floor, &headers, &standard_op())
        .verify(&ReportsWhatTheOuterLayerInstalled, &server_state(Some(Established("line\r\nbreak"))));
    assert_eq!(unusable.rejection(), Some(AuthError::AccessDenied));
}

/// Positive — the verifier reads the admission's own clock reading, the one `admit` was given.
#[test]
fn the_verifier_reads_the_admissions_one_clock_reading() {
    struct RecordsNow(std::sync::Mutex<Option<i64>>);

    impl HeaderTokenVerifier for RecordsNow {
        fn verify(&self, request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
            *self.0.lock().expect("uncontended") = Some(request.now().unix_seconds());
            Err(HeaderTokenRefused)
        }
    }

    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = with_token(&[]);
    for instant in [1_i64, SIGNED_AT_UNIX] {
        let view = WireView::new(&headers, RawQuery::new(""));
        let Ok(Admission::HeaderToken(admission)) = floor.admit(view, &standard_op(), RequestNow::from_unix_seconds(instant))
        else {
            panic!("expected a header-token admission");
        };
        let verifier = RecordsNow(std::sync::Mutex::new(None));
        let _ = admission.verify(&verifier, &TransportExtensions::default());
        assert_eq!(*verifier.0.lock().expect("uncontended"), Some(instant));
    }
}

/// Negative — no rendering of the admission, of the request the verifier is handed, or of the
/// verdict holds the token: the admission never copied it.
#[test]
fn n_no_rendering_of_an_admission_request_or_verdict_holds_the_token() {
    struct RendersItsRequest(std::sync::Mutex<String>);

    impl HeaderTokenVerifier for RendersItsRequest {
        fn verify(&self, request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
            *self.0.lock().expect("uncontended") = format!("{request:?}");
            Identity::new(PRINCIPAL).map_err(|_| HeaderTokenRefused)
        }
    }

    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = with_token(&[]);
    let admitted = admit(&floor, &headers, "", None, &standard_op());
    let mut rendered = vec![format!("{admitted:?}"), format!("{floor:?}"), format!("{:?}", claim())];
    let Ok(Admission::HeaderToken(admission)) = admitted else {
        panic!("expected a header-token admission");
    };
    rendered.push(format!("{admission:?}"));
    let verifier = RendersItsRequest(std::sync::Mutex::new(String::new()));
    let verdict = admission.verify(&verifier, &TransportExtensions::default());
    rendered.push(verifier.0.lock().expect("uncontended").clone());
    rendered.push(format!("{verdict:?}"));
    rendered.push(format!("{:?}", verdict.header_token_receipt().expect("a receipt")));
    let refused = admit(&floor, &with_token(&[("authorization", "Bearer x")]), "", None, &standard_op());
    rendered.push(format!("{refused:?}"));
    if let Err(error) = refused {
        rendered.push(error.to_string());
    }
    for text in &rendered {
        assert!(!text.is_empty());
        assert!(!text.to_ascii_lowercase().contains("sentinel"), "a rendering holds the token: {text}");
    }
    // The renderings are not empty shells: the verdict's names its principal.
    assert!(rendered.iter().any(|text| text.contains(PRINCIPAL)), "{rendered:?}");
}
