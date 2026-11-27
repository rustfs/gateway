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

//! End-to-end S3 Vectors isolation, canonical URI double-encoding, and native REST-JSON errors.
//!
//! Responsible for: verifying `ServiceBuilder::for_service(SigService::S3Vectors)` compatibility
//! with `rustfs_profile()`, automatic SigV4 canonical URI double-encoding, native REST-JSON error
//! rendering across every refusal path, and isolation from S3-only middleware.
//! NOT responsible for: pinning an AWS S3 Vectors Smithy model or backend storage semantics.
//! Upstream: `rustfs-gateway`, `rustfs-gateway-core`, `rustfs-gateway-sig`, `fixture`.
//! Downstream: CI integration test runner.

#[path = "fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use rustfs_gateway::{
    Classification, HOST_ID_HEADER, HandlerError, LegacyRustfsCors, LegacyRustfsVirtualHosts, REQUEST_ID_HEADER, ServiceConfig,
    SigService, VirtualHostStyle, X_REQUEST_ID_HEADER, response_filter,
};
use rustfs_gateway_types::ErrorCode;

use self::fixture::{
    CountingCorsSource, CountingOwnerSource, DOUBLE_ENCODED_ARN, SERVICE, TAG_ARN_PATH, VectorBackend, assert_rest_json_error,
    exchange_full, hand_signed, signed_request, vectors_builder,
};

// ── Item 1: for_service(S3Vectors) x rustfs_profile() ─────────────────────────────────────────

#[tokio::test]
async fn s3vectors_rustfs_profile_dispatches_declared_claimed_and_over_one_mib_bodies() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), true)
        .build()
        .expect("S3 Vectors with rustfs_profile");

    let posture = service.startup_posture();
    for s3_only in [
        "address_paths_as_legacy_rustfs",
        "select_operations_as_legacy_rustfs",
        "bound_claimed_route_bodies_as_legacy_rustfs",
        "bound_buffered_bodies_as_legacy_rustfs",
        "answer_cors_as_legacy_rustfs",
        "refuse_plaintext_customer_keys_before_routing",
    ] {
        assert!(!posture.contains(s3_only), "S3-only switch {s3_only} leaked into posture:\n{posture}");
    }

    let large_body = vec![b'a'; 1_500_000];
    let (status, headers, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/PutVectors", "", &[], &large_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "POST /PutVectors 1.5 MiB failed: {body}");
    assert_eq!(backend.last_body_len.load(Ordering::SeqCst), 1_500_000);
    assert!(headers.contains_key(REQUEST_ID_HEADER));
    assert!(headers.contains_key(X_REQUEST_ID_HEADER));
    assert!(!headers.contains_key(HOST_ID_HEADER), "x-amz-id-2 leaked: {headers:?}");

    let (status, headers, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", TAG_ARN_PATH, "", &[], &large_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "POST /tags/... 1.5 MiB failed: {body}");
    assert_eq!(backend.last_body_len.load(Ordering::SeqCst), 1_500_000);
    assert!(headers.contains_key(REQUEST_ID_HEADER), "claimed S3Vectors route keeps request id");
    assert!(!headers.contains_key(HOST_ID_HEADER));
}

#[tokio::test]
async fn n_s3vectors_manual_s3_legacy_switches_still_cannot_hijack_addressing_selection_or_caps() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), false)
        .address_paths_as_legacy_rustfs()
        .select_operations_as_legacy_rustfs()
        .bound_claimed_route_bodies_as_legacy_rustfs()
        .bound_buffered_bodies_as_legacy_rustfs()
        .answer_cors_as_legacy_rustfs(LegacyRustfsCors::with_fallback_origins(None))
        .refuse_plaintext_customer_keys_before_routing()
        .build()
        .expect("S3 Vectors with explicit S3 switches");

    let large_body = vec![b'z'; 1_200_000];
    let (status, _, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/PutVectors", "", &[], &large_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "POST /PutVectors failed: {body}");

    let (status, _, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", TAG_ARN_PATH, "", &[], &large_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claimed POST /tags/... over 1 MiB failed: {body}");
}

#[tokio::test]
async fn n_s3vectors_under_rustfs_profile_respects_configured_service_body_limit() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), true)
        .config(ServiceConfig::new(256))
        .0
        .build()
        .expect("S3 Vectors with tight configured limit");

    let oversized = vec![b'x'; 512];
    let (status, headers, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/PutVectors", "", &[], &oversized),
    )
    .await;
    assert_rest_json_error(status, &headers, &body, StatusCode::PAYLOAD_TOO_LARGE, "EntityTooLarge");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

// ── Item 2: SigV4 canonical URI path double-encoding for S3Vectors ────────────────────────────

#[tokio::test]
async fn s3vectors_verifies_double_encoded_tag_arn_automatically_under_default_and_rustfs_profile() {
    for profile in [false, true] {
        let backend = Arc::new(VectorBackend::default());
        let service = vectors_builder(Arc::clone(&backend), profile).build().expect("service");
        let (status, _, body) = exchange_full(
            &service,
            signed_request(SERVICE, Method::GET, "vectors.example.com", TAG_ARN_PATH, "", &[], b""),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "profile={profile}, body={body}");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn n_s3vectors_rejects_single_encoded_tag_arn_signature_under_default_and_rustfs_profile() {
    for profile in [false, true] {
        let backend = Arc::new(VectorBackend::default());
        let service = vectors_builder(Arc::clone(&backend), profile).build().expect("service");
        let single_encoded = hand_signed(
            SERVICE,
            "AKIDEXAMPLE",
            Method::GET,
            "vectors.example.com",
            TAG_ARN_PATH,
            TAG_ARN_PATH,
            "",
            b"",
        );
        let (status, headers, body) = exchange_full(&service, single_encoded).await;
        assert_rest_json_error(status, &headers, &body, StatusCode::FORBIDDEN, "SignatureDoesNotMatch");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0, "profile={profile}");
    }
}

// ── Item 3: Native service-level REST-JSON error rendering ────────────────────────────────────

#[tokio::test]
async fn n_s3vectors_renders_rest_json_for_unknown_route_auth_handler_filter_and_invariants() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), false)
        .build()
        .expect("default S3Vectors");

    let (status, headers, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/NoSuchAction", "", &[], b"{}"),
    )
    .await;
    assert_rest_json_error(status, &headers, &body, StatusCode::NOT_IMPLEMENTED, "NotImplemented");
    assert!(!body.contains("S3"), "S3 prose leaked: {body}");
    assert!(!body.contains("virtual host"), "vhost prose leaked: {body}");

    let unknown_key = hand_signed(
        SERVICE,
        "AKIDUNKNOWN",
        Method::POST,
        "vectors.example.com",
        "/PutVectors",
        "/PutVectors",
        "",
        b"{}",
    );
    let (status, headers, body) = exchange_full(&service, unknown_key).await;
    assert_rest_json_error(status, &headers, &body, StatusCode::FORBIDDEN, "InvalidAccessKeyId");

    let (status, headers, body) = exchange_full(
        &service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/FailVectors", "", &[], b""),
    )
    .await;
    assert_rest_json_error(status, &headers, &body, StatusCode::CONFLICT, "ConflictException");
    assert_eq!(body, r#"{"message":"vector \"a\\b\"\nexists"}"#);

    let head_unknown = Request::builder()
        .method(Method::HEAD)
        .uri("/NoSuchAction")
        .header(http::header::HOST, "vectors.example.com")
        .body(Bytes::new())
        .expect("head request");
    let (status, headers, body) = exchange_full(&service, head_unknown).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(headers.get("x-amzn-errortype").and_then(|v| v.to_str().ok()), Some("NotImplemented"));
    assert_eq!(
        headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert!(body.is_empty(), "HEAD must carry no body: {body}");
    assert!(!headers.contains_key(HOST_ID_HEADER));

    let filter_service = vectors_builder(Arc::new(VectorBackend::default()), false)
        .stage_filter(response_filter(|_view, _resp: &mut Response<rustfs_gateway_stream::Body>| {
            Err(HandlerError::new(
                ErrorCode::custom("ValidationException", StatusCode::BAD_REQUEST),
                "rejected by response filter",
            ))
        }))
        .build()
        .expect("filter service");
    let (status, headers, body) = exchange_full(
        &filter_service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/PutVectors", "", &[], b"{}"),
    )
    .await;
    assert_rest_json_error(status, &headers, &body, StatusCode::BAD_REQUEST, "ValidationException");
    assert_eq!(body, r#"{"message":"rejected by response filter"}"#);

    let invariant_service = vectors_builder(Arc::new(VectorBackend::default()), false)
        .stage_filter(response_filter(|_view, resp: &mut Response<rustfs_gateway_stream::Body>| {
            resp.headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("2"));
            resp.headers_mut()
                .insert(http::header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
            Ok(())
        }))
        .build()
        .expect("invariant service");
    let (status, headers, body) = exchange_full(
        &invariant_service,
        signed_request(SERVICE, Method::POST, "vectors.example.com", "/PutVectors", "", &[], b"{}"),
    )
    .await;
    assert_rest_json_error(status, &headers, &body, StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
}

#[tokio::test]
async fn n_s3vectors_under_rustfs_profile_omits_s3_service_list_on_wrong_scope_service() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), true)
        .build()
        .expect("rustfs_profile S3Vectors");
    let bad_scope = hand_signed(
        SigService::S3Express,
        "AKIDEXAMPLE",
        Method::POST,
        "vectors.example.com",
        "/PutVectors",
        "/PutVectors",
        "",
        b"{}",
    );
    let (status, headers, body) = exchange_full(&service, bad_scope).await;
    assert!(status.is_client_error(), "expected 4xx, got {status}: {body}");
    assert!(!body.contains("s3tables"), "S3 service list leaked: {body}");
    assert!(!body.contains("<Error"), "XML leaked: {body}");
    assert_eq!(
        headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

// ── Item 4: Isolate S3-only middleware + route-scoped tagKeys ─────────────────────────────────

#[tokio::test]
async fn s3vectors_isolates_virtual_host_style_and_legacy_virtual_hosts() {
    let resolvers: Vec<Arc<dyn rustfs_gateway::HostResolver>> = vec![
        Arc::new(VirtualHostStyle::new(["example.com"]).expect("vhost")),
        Arc::new(LegacyRustfsVirtualHosts::new(["example.com"]).expect("legacy domains")),
    ];
    for resolver in resolvers {
        let backend = Arc::new(VectorBackend::default());
        let saw_vhost_origin = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = Arc::clone(&saw_vhost_origin);
        let service = vectors_builder(Arc::clone(&backend), true)
            .host_resolver(resolver)
            .authorizer(rustfs_gateway::allow_when(move |req| {
                if req.target_origin != rustfs_gateway::TargetOrigin::Path || req.bucket.is_some() {
                    probe.fetch_add(1, Ordering::SeqCst);
                }
                true
            }))
            .build()
            .expect("S3Vectors");

        let (status, _, body) = exchange_full(
            &service,
            signed_request(SERVICE, Method::POST, "my-vectors.example.com", "/PutVectors", "", &[], b"{}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "POST /PutVectors on vhost failed: {body}");

        let (status, _, body) = exchange_full(
            &service,
            signed_request(SERVICE, Method::GET, "my-vectors.example.com", TAG_ARN_PATH, "", &[], b""),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GET /tags/... on vhost failed: {body}");
        assert_eq!(
            saw_vhost_origin.load(Ordering::SeqCst),
            0,
            "VirtualHostStyle must not leak TargetOrigin::VirtualHost or a bucket onto S3Vectors"
        );

        let (status, headers, body) =
            exchange_full(&service, signed_request(SERVICE, Method::PUT, "unknown-host.invalid", "/", "", &[], b"")).await;
        assert_rest_json_error(status, &headers, &body, StatusCode::NOT_IMPLEMENTED, "NotImplemented");
        assert!(!body.contains("virtual host"), "S3 VhostHint leaked: {body}");
        assert!(!body.contains("bucket"), "S3 bucket prose leaked: {body}");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn n_s3vectors_isolates_s3_cors_preflight_and_legacy_cors() {
    for profile in [false, true] {
        let cors = Arc::new(CountingCorsSource::default());
        let backend = Arc::new(VectorBackend::default());
        let service = vectors_builder(Arc::clone(&backend), profile)
            .cors_source(Arc::clone(&cors))
            .build()
            .expect("S3Vectors");

        let headerless = Request::builder()
            .method(Method::OPTIONS)
            .uri("/PutVectors")
            .header(http::header::HOST, "vectors.example.com")
            .body(Bytes::new())
            .expect("options request");
        let (parts, req_body) = headerless.into_parts();
        assert!(
            matches!(
                service.classify(&parts),
                Classification::Refused {
                    status: StatusCode::NOT_IMPLEMENTED,
                    ..
                }
            ),
            "classify must agree with call on OPTIONS /PutVectors"
        );
        let (status, headers, body) = exchange_full(&service, Request::from_parts(parts, req_body)).await;
        assert_rest_json_error(status, &headers, &body, StatusCode::NOT_IMPLEMENTED, "NotImplemented");

        let preflight = Request::builder()
            .method(Method::OPTIONS)
            .uri("/PutVectors")
            .header(http::header::HOST, "vectors.example.com")
            .header("origin", "https://app.example")
            .header("access-control-request-method", "POST")
            .body(Bytes::new())
            .expect("preflight request");
        let (status, headers, body) = exchange_full(&service, preflight).await;
        assert_rest_json_error(status, &headers, &body, StatusCode::NOT_IMPLEMENTED, "NotImplemented");

        let (status, _, body) = exchange_full(
            &service,
            signed_request(
                SERVICE,
                Method::POST,
                "vectors.example.com",
                "/PutVectors",
                "",
                &[("origin", "https://app.example")],
                b"{}",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "profile={profile}: {body}");
        assert_eq!(cors.calls.load(Ordering::SeqCst), 0, "S3 CorsSource was called on S3Vectors!");
    }
}

#[tokio::test]
async fn s3vectors_isolates_s3_only_headers_expected_owner_ssec_and_checksums() {
    for profile in [false, true] {
        let owner_source = Arc::new(CountingOwnerSource::default());
        let backend = Arc::new(VectorBackend::default());
        let service = vectors_builder(Arc::clone(&backend), profile)
            .bucket_owner_source(Arc::clone(&owner_source))
            .build()
            .expect("S3Vectors");

        let req = signed_request(
            SERVICE,
            Method::POST,
            "vectors.example.com",
            "/PutVectors",
            "",
            &[
                ("x-amz-expected-bucket-owner", "123456789012"),
                ("x-amz-source-expected-bucket-owner", "123456789012"),
                ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
                ("content-md5", "not-valid-base64!!!"),
                ("x-amz-checksum-sha256", "not-valid-base64!!!"),
                ("x-amz-sdk-checksum-algorithm", "UNKNOWN_ALGO"),
            ],
            b"{}",
        );
        let (status, headers, body) = exchange_full(&service, req).await;
        assert_eq!(status, StatusCode::OK, "S3 header check hijacked S3Vectors (profile={profile}): {body}");
        assert!(!headers.contains_key(HOST_ID_HEADER), "x-amz-id-2 leaked: {headers:?}");
        assert_eq!(owner_source.calls.load(Ordering::SeqCst), 0, "BucketOwnerSource was called on S3Vectors!");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn n_s3vectors_allows_repeated_tag_keys_only_on_untag_resource() {
    let backend = Arc::new(VectorBackend::default());
    let service = vectors_builder(Arc::clone(&backend), true)
        .build()
        .expect("S3Vectors service");

    let untag = signed_request(
        SERVICE,
        Method::DELETE,
        "vectors.example.com",
        TAG_ARN_PATH,
        "tagKeys=b&tagKeys=a",
        &[],
        b"",
    );
    let (status, _, body) = exchange_full(&service, untag).await;
    assert_eq!(status, StatusCode::OK, "UntagResource failed: {body}");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

    for (method, uri, canonical_uri, payload) in [
        (Method::POST, "/PutVectors?tagKeys=b&tagKeys=a", "/PutVectors", &b"{}"[..]),
        (Method::GET, &format!("{TAG_ARN_PATH}?tagKeys=b&tagKeys=a"), DOUBLE_ENCODED_ARN, &b""[..]),
        (
            Method::POST,
            &format!("{TAG_ARN_PATH}?tagKeys=b&tagKeys=a"),
            DOUBLE_ENCODED_ARN,
            &b"{}"[..],
        ),
    ] {
        let req = hand_signed(
            SERVICE,
            "AKIDEXAMPLE",
            method,
            "vectors.example.com",
            uri,
            canonical_uri,
            "tagKeys=a&tagKeys=b",
            payload,
        );
        let (status, headers, body) = exchange_full(&service, req).await;
        assert_rest_json_error(status, &headers, &body, StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed");
    }
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "rejected requests must not invoke handler");
}

#[tokio::test]
async fn n_s3_service_preserves_single_encoding_and_x_amz_id_2_and_xml_errors() {
    struct GetObjBackend;
    impl rustfs_gateway::Handler<rustfs_gateway::dto::GetObject> for GetObjBackend {
        async fn call(
            &self,
            _: rustfs_gateway::Req<rustfs_gateway::dto::GetObject>,
        ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::GetObject> {
            Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::GetObjectOutput::default()))
        }
    }
    let credentials = Arc::new(
        rustfs_gateway::StaticCredentials::new()
            .with(rustfs_gateway::Credentials::new("AKIDEXAMPLE", b"secret").expect("test creds")),
    );
    let s3 = rustfs_gateway::ServiceBuilder::new()
        .register::<rustfs_gateway::dto::GetObject, _>(Arc::new(GetObjBackend))
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("region"),
        ))
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(
            crate::support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("S3 service");

    // Single-encoded S3 request succeeds and keeps x-amz-id-2.
    let single = signed_request(SigService::S3, Method::GET, "s3.example.com", "/bucket/arn%3Aaws%2Fkey", "", &[], b"");
    let (status, headers, body) = exchange_full(&s3, single).await;
    assert_eq!(status, StatusCode::OK, "S3 single-encoded signature must verify: {body}");
    assert!(headers.contains_key(HOST_ID_HEADER), "S3 default response must keep x-amz-id-2");

    // Double-encoded signature on ordinary S3 is rejected with S3 XML.
    let double = hand_signed(
        SigService::S3,
        "AKIDEXAMPLE",
        Method::GET,
        "s3.example.com",
        "/bucket/arn%3Aaws%2Fkey",
        "/bucket/arn%253Aaws%252Fkey",
        "",
        b"",
    );
    let (status, headers, body) = exchange_full(&s3, double).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/xml")
    );
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(headers.contains_key(HOST_ID_HEADER), "S3 XML error must keep x-amz-id-2");
}
