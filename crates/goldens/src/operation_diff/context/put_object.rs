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

//! PutObject: the request-context diff against the pinned s3s oracle.
//!
//! Responsible for: proving that, for the same raw PutObject request, the `s3s::S3Request` the
//! gateway can build through `compat::request_context` carries the same method, URI, headers,
//! extensions, credentials, region, service and trailer handle as the one the s3s service hands
//! its handler — anonymous and signed, path-style and virtual-hosted; that the comparison bites on
//! every member alone; that the conversion refuses by name what s3s cannot hold; and that every
//! context divergence this file knows of is a named test saying what each side does.
//! NOT responsible for: the input members or body consumption (the decode diff), or RustFS
//! extensions, which the conversion deliberately never produces.
//! Upstream: the harness in `super`. Downstream: nothing.

use std::sync::Arc;

use super::super::seam::request_context::{GatewayRequestContext, Principal, S3S_CONTEXT_MEMBERS, VerifiedScope, request_to_s3s};
use proptest::prelude::*;

use super::super::{BodyProbe, BodyReads, RawRequest, gateway_decode, oracle, s3s, s3s_exchange};
use super::{
    ACCESS_KEY, BASE_DOMAIN, COMPARED_MEMBERS, CapturedInput, Compared, ContextRequest, PATH_HOST, TransportMarker, access_key,
    compare, differing_context, exchange, region_of,
};

const NONE: &[&str] = &[];

fn compared(request: &ContextRequest) -> Compared {
    let compared = compare(request).expect("both stacks reach their PutObject handler");
    assert_eq!(compared.operation, "PutObject");
    compared
}

fn oracle_bucket_and_key(compared: &Compared) -> (String, String) {
    match &compared.oracle.input {
        CapturedInput::Put(input) => (input.bucket.clone(), input.key.clone()),
        CapturedInput::Location(_) => panic!("s3s handed the request to GetBucketLocation"),
    }
}

// ── zero diff ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_anonymous_path_style_request_has_the_same_context() {
    let request = ContextRequest::put(PATH_HOST, "/photos/2026/a.jpg", b"hello").header("content-type", b"image/jpeg");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.method, http::Method::PUT);
    assert_eq!(compared.converted.uri, "/photos/2026/a.jpg");
    assert!(compared.converted.credentials.is_none() && compared.oracle.credentials.is_none());
    assert_eq!((region_of(&compared.converted), region_of(&compared.oracle)), (None, None));
    assert_eq!((compared.converted.service.as_deref(), compared.oracle.service.as_deref()), (None, None));
    assert!(compared.converted.extensions.is_empty() && compared.oracle.extensions.is_empty());
    assert!(compared.converted.trailing_headers.is_none() && compared.oracle.trailing_headers.is_none());
    let expected = (String::from("photos"), String::from("2026/a.jpg"));
    assert_eq!(oracle_bucket_and_key(&compared), expected);
    assert_eq!(
        (compared.bucket.clone().unwrap_or_default(), compared.key.clone().unwrap_or_default()),
        expected
    );
}

#[test]
fn a_signed_path_style_request_carries_the_same_principal_region_and_service() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").signed("us-east-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(access_key(&compared.converted), Some(ACCESS_KEY));
    assert_eq!(access_key(&compared.oracle), Some(ACCESS_KEY));
    assert_eq!(region_of(&compared.converted), Some("us-east-1"));
    assert_eq!(region_of(&compared.oracle), Some("us-east-1"));
    assert_eq!(compared.converted.service.as_deref(), Some("s3"));
    assert_eq!(compared.oracle.service.as_deref(), Some("s3"));
    // The signed lines themselves are headers both handlers see.
    assert!(compared.converted.headers.contains_key(http::header::AUTHORIZATION));
    assert!(compared.converted.headers.contains_key("x-amz-date"));
}

/// Two regions are configured, so a conversion that reported the first one would pass the test
/// above and fail this one.
#[test]
fn a_request_signed_for_the_second_region_reports_that_region_on_both_stacks() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").signed("eu-west-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(region_of(&compared.converted), Some("eu-west-1"));
    assert_eq!(region_of(&compared.oracle), Some("eu-west-1"));
}

#[test]
fn a_virtual_hosted_request_keeps_the_raw_path_and_both_stacks_agree_on_bucket_and_key() {
    let host = format!("photos.{BASE_DOMAIN}");
    let request = ContextRequest::put(&host, "/2026/a.jpg", b"hello")
        .virtual_hosted()
        .signed("us-east-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri, "/2026/a.jpg");
    let expected = (String::from("photos"), String::from("2026/a.jpg"));
    assert_eq!(oracle_bucket_and_key(&compared), expected);
    assert_eq!(
        (compared.bucket.clone().unwrap_or_default(), compared.key.clone().unwrap_or_default()),
        expected
    );
    assert_eq!(compared.resolved.bucket().map(|bucket| bucket.as_str()), Some("photos"));
}

#[test]
fn repeated_metadata_and_unknown_headers_cross_as_the_same_lines() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello")
        .header("x-amz-meta-camera", b"x100")
        .header("x-amz-meta-lens", b"23mm")
        .header("x-proxy-note", b"first")
        .header("x-proxy-note", b"second")
        .header("x-amz-meta-city", "Z\u{fc}rich".as_bytes())
        .signed("us-east-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    let notes: Vec<_> = compared.converted.headers.get_all("x-proxy-note").iter().collect();
    assert_eq!(notes, ["first", "second"]);
    assert_eq!(
        compared
            .converted
            .headers
            .get("x-amz-meta-city")
            .map(http::HeaderValue::as_bytes),
        Some("Z\u{fc}rich".as_bytes())
    );
}

/// The URI is the raw target: a percent-encoded path is neither decoded nor re-encoded.
#[test]
fn a_percent_encoded_path_crosses_byte_for_byte() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a%20b.jpg", b"hello").signed("us-east-1");
    let compared = compared(&request);
    assert_eq!(compared.converted.uri, "/photos/a%20b.jpg");
    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
}

// ── the comparison bites ──────────────────────────────────────────────────────────────────────

#[test]
fn every_s3s_context_member_is_compared() {
    assert_eq!(COMPARED_MEMBERS, S3S_CONTEXT_MEMBERS);
}

/// Every member the comparison can be handed a second value for, changed alone, is named alone.
///
/// `trailing_headers` is the exception: the pinned s3s trailer handle has no public constructor,
/// so a `Some` cannot be built outside s3s. It is held instead by the refusal below, which is the
/// only way the conversion could ever disagree on it.
#[test]
fn each_context_mutation_is_named_alone() {
    let base = compared(&ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").signed("us-east-1")).converted;
    assert_eq!(differing_context(&base, &base.clone()), NONE);

    type Mutation = fn(&mut s3s::S3Request<()>);
    let mutations: &[(&str, Mutation)] = &[
        ("method", |r| r.method = http::Method::POST),
        ("uri", |r| r.uri = http::Uri::from_static("/photos/b.jpg")),
        ("headers", |r| {
            r.headers.append("x-proxy-note", http::HeaderValue::from_static("added"));
        }),
        ("headers", |r| {
            r.headers.remove(http::header::AUTHORIZATION);
        }),
        ("extensions", |r| {
            r.extensions.insert(TransportMarker);
        }),
        ("credentials", |r| r.credentials = None),
        ("credentials", |r| {
            if let Some(credentials) = r.credentials.as_mut() {
                credentials.access_key = String::from("AKIDOTHER");
            }
        }),
        ("credentials", |r| {
            if let Some(credentials) = r.credentials.as_mut() {
                credentials.secret_key = "another-secret-key".into();
            }
        }),
        ("region", |r| r.region = None),
        ("region", |r| r.region = Some("eu-west-1".parse().expect("a valid region"))),
        ("service", |r| r.service = None),
        ("service", |r| r.service = Some(String::from("sts"))),
    ];
    for (member, mutate) in mutations {
        let mut mutated = base.clone();
        mutate(&mut mutated);
        assert_eq!(differing_context(&mutated, &base), [*member], "mutating {member}");
    }
}

// ── the conversion refuses by name ────────────────────────────────────────────────────────────

fn context() -> GatewayRequestContext {
    GatewayRequestContext {
        method: http::Method::PUT,
        raw_path: String::from("/photos/a.jpg"),
        raw_query: String::new(),
        headers: http::HeaderMap::new(),
        principal: None,
        host_region: None,
        declares_trailers: false,
    }
}

fn principal(region: &str, service: &str) -> Principal {
    Principal {
        access_key: String::from(ACCESS_KEY),
        secret_key: "context-diff-secret-key".into(),
        scope: Some(VerifiedScope {
            region: region.to_owned(),
            service: service.to_owned(),
        }),
    }
}

fn refused_member(context: GatewayRequestContext) -> &'static str {
    request_to_s3s(context, ())
        .map(|_| ())
        .expect_err("the conversion refuses")
        .field
}

#[test]
fn declared_trailers_are_refused_by_name() {
    assert_eq!(
        refused_member(GatewayRequestContext {
            declares_trailers: true,
            ..context()
        }),
        "trailing_headers"
    );
}

#[test]
fn a_host_region_outside_the_s3s_grammar_is_refused_by_name() {
    assert_eq!(
        refused_member(GatewayRequestContext {
            host_region: Some(String::from("EU_WEST")),
            ..context()
        }),
        "region"
    );
}

#[test]
fn an_empty_verified_region_is_refused_by_name() {
    assert_eq!(
        refused_member(GatewayRequestContext {
            principal: Some(principal("", "s3")),
            ..context()
        }),
        "region"
    );
}

#[test]
fn an_empty_verified_service_is_refused_by_name() {
    assert_eq!(
        refused_member(GatewayRequestContext {
            principal: Some(principal("us-east-1", "")),
            ..context()
        }),
        "service"
    );
}

#[test]
fn an_empty_access_key_is_refused_by_name() {
    let mut principal = principal("us-east-1", "s3");
    principal.access_key.clear();
    assert_eq!(
        refused_member(GatewayRequestContext {
            principal: Some(principal),
            ..context()
        }),
        "credentials"
    );
}

/// An authenticated handler context whose authenticator did not hand the caller's secret over
/// cannot become s3s credentials: the conversion refuses by name rather than inventing a secret.
#[test]
fn a_principal_without_a_handed_off_secret_is_refused_by_name() {
    let refused = Principal::from_handler(ACCESS_KEY, None, None).expect_err("no secret to carry");
    assert_eq!(refused.field, "credentials");
}

/// A secret that is not UTF-8 has no s3s spelling; refused by name, never lossily converted.
#[test]
fn a_secret_that_is_not_utf8_is_refused_by_name() {
    let refused = Principal::from_handler(ACCESS_KEY, Some(b"\xff\xfe"), None).expect_err("no s3s spelling");
    assert_eq!(refused.field, "credentials");
}

/// A signed request through a service whose authenticator keeps the secret to itself (the
/// default) reaches the handler, and the adapter then refuses to build s3s credentials.
#[test]
fn a_signed_request_without_the_secret_hand_off_is_refused_by_name() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello")
        .signed("us-east-1")
        .without_secret_hand_off();
    let refusal = compare(&request).map(|_| ()).expect_err("the conversion refuses");
    assert!(refusal.contains("credentials"), "{refusal}");
}

#[test]
fn a_path_that_is_not_origin_form_is_refused_by_name() {
    for raw_path in ["photos/a.jpg", "/photos/a b.jpg"] {
        assert_eq!(
            refused_member(GatewayRequestContext {
                raw_path: String::from(raw_path),
                ..context()
            }),
            "uri",
            "{raw_path}"
        );
    }
}

/// Pins the s3s precedence the conversion follows: the verified signing region, then the host's.
#[test]
fn a_verified_region_takes_precedence_over_the_host_region() {
    let signed = request_to_s3s(
        GatewayRequestContext {
            principal: Some(principal("eu-west-1", "s3")),
            host_region: Some(String::from("us-west-2")),
            ..context()
        },
        (),
    )
    .expect("a representable context");
    assert_eq!(region_of(&signed), Some("eu-west-1"));

    let anonymous = request_to_s3s(
        GatewayRequestContext {
            host_region: Some(String::from("us-west-2")),
            ..context()
        },
        (),
    )
    .expect("a representable context");
    assert_eq!(region_of(&anonymous), Some("us-west-2"));
    assert_eq!(anonymous.service, None);
}

// ── named divergences ─────────────────────────────────────────────────────────────────────────

/// `photos.s3.eu-west-1.example.test`: the gateway resolver reads bucket `photos` and host region
/// `eu-west-1`; the pinned s3s `MultiDomain` strips only the base domain, so its bucket is the
/// whole prefix and it reports no region.
///
/// Ruling: `rd-ctx-0001`
#[test]
fn divergence_a_regional_virtual_host_names_a_different_bucket_and_region() {
    let host = format!("photos.s3.eu-west-1.{BASE_DOMAIN}");
    let request = ContextRequest::put(&host, "/a.jpg", b"hello").virtual_hosted();
    let compared = compared(&request);

    assert_eq!(compared.bucket.as_deref(), Some("photos"));
    assert_eq!(region_of(&compared.converted), Some("eu-west-1"));
    assert_eq!(oracle_bucket_and_key(&compared).0, "photos.s3.eu-west-1");
    assert_eq!(region_of(&compared.oracle), None);
    assert_eq!(differing_context(&compared.converted, &compared.oracle), ["region"]);
}

/// A field value that is not UTF-8 (here one Latin-1 byte, as some proxies write). The gateway's
/// text view still skips it (s3s#597 rule), but the handler context publishes every accepted line
/// through `iter_raw` (ADR-0022), so the request an adapter converts from the handler context
/// carries it byte for byte, exactly as the s3s handler receives it.
///
/// Ruling: `rd-ctx-0002`
#[test]
fn divergence_a_non_utf8_header_value_reaches_both_handlers() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").header("x-proxy-note", b"caf\xe9");
    let compared = compared(&request);

    let expected = Some(&b"caf\xe9"[..]);
    assert_eq!(
        compared
            .converted
            .headers
            .get("x-proxy-note")
            .map(http::HeaderValue::as_bytes),
        expected
    );
    assert_eq!(compared.oracle.headers.get("x-proxy-note").map(http::HeaderValue::as_bytes), expected);
    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
}

/// A transport layer's extension (RustFS installs its `RemoteAddr` and `RequestContext` this way)
/// reaches the s3s handler; the gateway's wire request keeps no extension bag.
///
/// Ruling: `rd-ctx-0003`
#[test]
fn divergence_a_transport_extension_reaches_only_the_s3s_handler() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").with_transport_extension();
    let compared = compared(&request);

    assert!(compared.converted.extensions.is_empty());
    assert!(compared.oracle.extensions.get::<TransportMarker>().is_some());
    assert_eq!(differing_context(&compared.converted, &compared.oracle), ["extensions"]);
}

/// An absolute-form target: s3s hands its handler the URI as it arrived, authority included; the
/// gateway keeps the raw path and query only.
///
/// Ruling: `rd-ctx-0004`
#[test]
fn divergence_an_absolute_form_target_keeps_its_authority_only_on_s3s() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").absolute_form();
    let compared = compared(&request);

    assert_eq!(compared.converted.uri, "/photos/a.jpg");
    assert_eq!(compared.oracle.uri.to_string(), format!("http://{PATH_HOST}/photos/a.jpg"));
    assert_eq!(compared.converted.uri.path(), compared.oracle.uri.path());
    assert_eq!(differing_context(&compared.converted, &compared.oracle), ["uri"]);
}

/// A bare `?`: s3s keeps an empty query, the gateway's query view cannot tell it from none.
///
/// Ruling: `rd-ctx-0005`
#[test]
fn divergence_an_empty_query_marker_is_kept_only_by_s3s() {
    let request = ContextRequest::put(PATH_HOST, "/photos/a.jpg", b"hello").empty_query_marker();
    let exchange = exchange(&request).expect("both stacks answer");
    let oracle = exchange.oracle.expect("s3s reaches its handler");

    assert_eq!(oracle.uri.query(), Some(""));
    let converted = exchange.gateway.converted.expect("a representable context");
    assert_eq!(converted.uri.query(), None);
    assert_eq!(differing_context(&converted, &oracle), ["uri"]);
}

/// Two lines for one `x-amz-meta-q` key, the second spelled in another case. Until
/// `rd-ctx-0006` the gateway decoded the request and kept only the **last** line, dropping the
/// first value without a refusal. Both stacks now refuse it with `400 InvalidRequest` before any
/// handler runs: the gateway at wire acceptance, s3s in its metadata parser. Found by the
/// generated-request property below, whose metadata names are distinct because this test names
/// the case.
///
/// Ruling: `rd-ctx-0006`
#[test]
fn divergence_repeated_metadata_lines_are_refused_by_both_stacks() {
    let request = RawRequest::put("/photos/a.jpg", b"hello", 5)
        .with("x-amz-meta-q", "a")
        .with("X-Amz-Meta-Q", "b");

    let probe = Arc::new(BodyProbe::default());
    let refusal = gateway_decode(&request, &probe).expect_err("the gateway refuses a repeated metadata key");
    assert_eq!(refusal, "wire refusal: DuplicateMetadataHeader(\"x-amz-meta-q\")");
    let wire = rustfs_gateway_http::WireReject::DuplicateMetadataHeader(http::HeaderName::from_static("x-amz-meta-q"));
    assert_eq!((wire.to_status().as_u16(), wire.error_code().as_str()), (400, "InvalidRequest"));
    assert_eq!(probe.reads(), BodyReads::default(), "the refused body was read");

    let exchange =
        s3s_exchange(&request, &Arc::new(BodyProbe::default()), oracle::PutObjectOutput::default()).expect("s3s answers");
    assert!(exchange.input.is_none(), "s3s handed the request to its handler");
    assert_eq!(exchange.answer.status, 400);
    assert_eq!(exchange.answer.error_code().as_deref(), Some("InvalidRequest"));
}

// ── generated requests ────────────────────────────────────────────────────────────────────────

fn generated_request() -> impl Strategy<Value = ContextRequest> {
    let segment = "[a-z0-9]{1,8}";
    // Distinct names: a repeated metadata name is refused by both stacks (the named test above),
    // so it is not a context comparison.
    let meta = proptest::collection::btree_map("[a-z]{1,6}", "[A-Za-z0-9._-]{0,12}", 0..4);
    (
        proptest::collection::vec(segment, 1..4),
        meta,
        any::<bool>(),
        prop_oneof![Just("us-east-1"), Just("eu-west-1")],
        any::<bool>(),
    )
        .prop_map(|(segments, meta, signed, region, virtual_hosted)| {
            let key = segments.join("/");
            let mut request = if virtual_hosted {
                ContextRequest::put(&format!("photos.{BASE_DOMAIN}"), &format!("/{key}"), b"generated").virtual_hosted()
            } else {
                ContextRequest::put(PATH_HOST, &format!("/photos/{key}"), b"generated")
            };
            for (name, value) in meta {
                request = request.header(&format!("x-amz-meta-{name}"), value.as_bytes());
            }
            if signed { request.signed(region) } else { request }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn generated_requests_have_the_same_context(request in generated_request()) {
        let compared = compare(&request).map_err(TestCaseError::fail)?;
        prop_assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
        prop_assert_eq!(compared.bucket.as_deref(), Some("photos"));
    }
}
