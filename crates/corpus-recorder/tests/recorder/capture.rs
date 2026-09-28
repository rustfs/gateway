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

//! Responsible for: what the recorder hands the inner service and what it lets reach disk — a
//! byte- and frame-identical pass-through, the redaction of every credential carrier before a
//! byte is written (a-cp-0012, a-cp-0013), and the refusals that write nothing.
//! Not responsible for: the runtime gate (`gate`) or real signed-chunk traffic (`signed_chunks`).
//! Upstream: `CorpusRecorderLayer` over the fixtures in `support`.
//! Downstream: nothing.

use tower::{Layer as _, ServiceExt as _};

use rustfs_gateway_corpus::redact::PLACEHOLDER;

use crate::support::{
    Frames, Seen, config, entries, ignoring_service, reading_service, recorder, request, settle, settle_unwritten,
    stop_at_end_service,
};

const SSE_C_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const SESSION_TOKEN: &str = "FQoGZXIvYXdzEBYaDLiveSessionTokenValue";
const COOKIE: &str = "session=live-cookie-value";

/// Positive — the inner service receives exactly the frames the client sent, one for one, and the
/// entry records the whole body with its response head.
#[tokio::test]
async fn the_inner_service_sees_every_frame_unchanged() {
    let parts: [&[u8]; 3] = [b"hel", b"lo wo", b"rld"];
    let config = config("capture-identity");
    let layer = recorder(config.clone());
    let seen = Seen::default();
    let response = layer
        .layer(reading_service(seen.clone()))
        .oneshot(request("PUT", "/bucket/key", &[], Frames::of(&parts)))
        .await
        .expect("an infallible service");
    assert_eq!(response.status(), 200);
    assert_eq!(seen.frames(), parts.iter().map(|part| part.to_vec()).collect::<Vec<_>>());
    settle(&layer, 1).await;
    let recorded = entries(&config);
    assert_eq!(recorded.len(), 1);
    let entry = &recorded[0];
    assert_eq!(entry.op, "PutObject");
    assert_eq!(entry.target, "/bucket/key");
    assert_eq!(serde_json::to_value(entry.capture).expect("serializable"), "head_full");
    assert_eq!(
        serde_json::to_value(entry.chunks.as_ref().expect("a recorded body")).expect("serializable"),
        serde_json::json!([{ "bytes_b64": "aGVsbG8gd29ybGQ=" }]),
    );
    let response = entry.resp.as_ref().expect("a recorded response");
    assert_eq!(response.status, 200);
    assert!(response.headers.contains(&("set-cookie".to_owned(), PLACEHOLDER.to_owned())));
}

/// Negative (a-cp-0012, a-cp-0013) — an SSE-C key, a session token and a cookie never reach the
/// file; each is replaced with the placeholder and named in `redacted`.
#[tokio::test]
async fn n_credential_headers_never_reach_the_file() {
    let config = config("capture-headers");
    let layer = recorder(config.clone());
    let headers = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key", SSE_C_KEY),
        ("x-amz-security-token", SESSION_TOKEN),
        ("cookie", COOKIE),
    ];
    let _ = layer
        .layer(reading_service(Seen::default()))
        .oneshot(request("PUT", "/bucket/key", &headers, Frames::of(&[b"data"])))
        .await;
    settle(&layer, 1).await;
    let written = std::fs::read_to_string(&config.output).expect("an output file");
    for secret in [SSE_C_KEY, SESSION_TOKEN, COOKIE, "live-cookie-value"] {
        assert!(!written.contains(secret), "`{secret}` reached the file: {written}");
    }
    let entry = &entries(&config)[0];
    for name in ["cookie", "x-amz-security-token", "x-amz-server-side-encryption-customer-key"] {
        assert!(
            entry.redacted.iter().any(|field| field == name),
            "{name} missing from {:?}",
            entry.redacted
        );
        assert_eq!(entry.header_values(name).collect::<Vec<_>>(), [PLACEHOLDER]);
    }
}

/// Negative — a presigned URL's signature and credential never reach the file.
#[tokio::test]
async fn n_presigned_query_credentials_never_reach_the_file() {
    let signature = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
    let config = config("capture-presigned");
    let layer = recorder(config.clone());
    let target = format!(
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=compatmatrixkey%2F20260928%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature={signature}"
    );
    let _ = layer
        .layer(reading_service(Seen::default()))
        .oneshot(request("GET", &target, &[], Frames::of(&[])))
        .await;
    settle(&layer, 1).await;
    let written = std::fs::read_to_string(&config.output).expect("an output file");
    assert!(!written.contains(signature), "{written}");
    assert!(!written.contains("aws4_request"), "{written}");
    let entry = &entries(&config)[0];
    assert_eq!(entry.op, "GetObject");
    assert_eq!(entry.redacted, ["set-cookie", "x-amz-credential", "x-amz-signature"]);
}

/// Negative — a credential inside a body cannot be sanitized, so the entry is refused and nothing
/// of it is written; the request itself is still served.
#[tokio::test]
async fn n_a_body_credential_is_refused_and_nothing_is_written() {
    let config = config("capture-body-secret");
    let layer = recorder(config.clone());
    let seen = Seen::default();
    let body: &[u8] = b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let response = layer
        .layer(reading_service(seen.clone()))
        .oneshot(request("PUT", "/bucket/key", &[], Frames::of(&[body])))
        .await
        .expect("an infallible service");
    assert_eq!(response.status(), 200);
    assert_eq!(seen.frames(), [body.to_vec()]);
    let stats = settle(&layer, 1).await;
    assert_eq!((stats.refused, stats.recorded), (1, 0));
    assert_eq!(std::fs::read_to_string(&config.output).expect("an output file"), "");
}

/// Negative — a body over the cap is passed through whole but recorded as no body at all, never
/// as a truncated prefix posing as the whole.
#[tokio::test]
async fn n_an_over_cap_body_is_passed_through_but_not_recorded() {
    let mut config = config("capture-over-cap");
    config.max_body_bytes = 4;
    let layer = recorder(config.clone());
    let seen = Seen::default();
    let parts: [&[u8]; 2] = [b"abc", b"defgh"];
    let _ = layer
        .layer(reading_service(seen.clone()))
        .oneshot(request("PUT", "/bucket/key", &[], Frames::of(&parts)))
        .await;
    assert_eq!(seen.frames(), [b"abc".to_vec(), b"defgh".to_vec()]);
    let stats = settle(&layer, 1).await;
    assert_eq!(stats.body_not_recorded, 1);
    assert!(entries(&config)[0].chunks.is_none());
}

/// Negative — a body the service never read to its end was not observed, so none of it is
/// recorded.
#[tokio::test]
async fn n_an_unread_body_is_not_recorded() {
    let config = config("capture-unread");
    let layer = recorder(config.clone());
    let response = layer
        .layer(ignoring_service())
        .oneshot(request("PUT", "/bucket/key", &[], Frames::of(&[b"never read"])))
        .await
        .expect("an infallible service");
    assert_eq!(response.status(), 403);
    let stats = settle(&layer, 1).await;
    assert_eq!(stats.body_not_recorded, 1);
    let entry = &entries(&config)[0];
    assert!(entry.chunks.is_none());
    assert_eq!(entry.resp.as_ref().map(|response| response.status), Some(403));
}

/// Negative — a request whose head declares a body the service never read is not written at all:
/// an entry with the head's `Content-Length` and no body claims a request no client sent, and
/// replays as one. The checked-in corpus held fourteen such entries, every one an operation the
/// reference server answered 501 before reading the body. Counted as a body not recorded.
#[tokio::test]
async fn n_an_unread_declared_body_is_not_written() {
    for declared in [("content-length", "10"), ("transfer-encoding", "chunked")] {
        let config = config(&format!("capture-unread-declared-{}", declared.0));
        let layer = recorder(config.clone());
        let response = layer
            .layer(ignoring_service())
            .oneshot(request("PUT", "/bucket/key", &[declared], Frames::of(&[b"never read"])))
            .await
            .expect("an infallible service");
        assert_eq!(response.status(), 403, "the request is still served");
        let stats = settle_unwritten(&layer).await;
        assert_eq!((stats.body_not_recorded, stats.recorded), (1, 0), "{declared:?}");
        assert_eq!(std::fs::read_to_string(&config.output).unwrap_or_default(), "", "{declared:?}");
    }
    let config = config("capture-unread-declared-empty");
    let layer = recorder(config.clone());
    let _ = layer
        .layer(ignoring_service())
        .oneshot(request("PUT", "/bucket/key", &[("content-length", "0")], Frames::of(&[])))
        .await;
    let stats = settle(&layer, 1).await;
    assert_eq!(stats.recorded, 1, "a declared empty body was observed in full");
}

/// Negative — a request no S3 route names is served but not recorded, and counted.
#[tokio::test]
async fn n_an_unrouted_request_is_served_but_not_recorded() {
    let config = config("capture-unrouted");
    let layer = recorder(config.clone());
    let seen = Seen::default();
    let response = layer
        .layer(reading_service(seen.clone()))
        .oneshot(request("PATCH", "/bucket/key", &[], Frames::of(&[b"x"])))
        .await
        .expect("an infallible service");
    assert_eq!(response.status(), 200);
    assert_eq!(seen.frames(), [b"x".to_vec()]);
    assert_eq!(layer.stats().unrouted, 1);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(std::fs::read_to_string(&config.output).expect("an output file"), "");
}

/// Positive — a body whose end is signalled only by a final `None` (a chunked upload) is still
/// recorded whole.
#[tokio::test]
async fn a_body_ended_only_by_none_is_recorded_whole() {
    let config = config("capture-unannounced");
    let layer = recorder(config.clone());
    let _ = layer
        .layer(reading_service(Seen::default()))
        .oneshot(request("PUT", "/bucket/key", &[], Frames::unannounced(&[b"ab", b"cd"])))
        .await;
    settle(&layer, 1).await;
    assert!(entries(&config)[0].chunks.is_some(), "{:?}", layer.stats());
}

/// Positive — a consumer that stops at `is_end_stream` without polling the final `None` has
/// still read the whole body, and the whole body is recorded.
#[tokio::test]
async fn a_body_read_to_its_announced_end_is_recorded_whole() {
    let config = config("capture-announced");
    let layer = recorder(config.clone());
    let _ = layer
        .layer(stop_at_end_service())
        .oneshot(request("PUT", "/bucket/key", &[], Frames::of(&[b"ab", b"cd"])))
        .await;
    settle(&layer, 1).await;
    assert!(entries(&config)[0].chunks.is_some(), "{:?}", layer.stats());
}
