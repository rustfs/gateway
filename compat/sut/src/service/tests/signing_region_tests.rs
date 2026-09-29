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

//! The signing regions the RustFS-profile launcher verifies (rustfs/backlog#1677, R2).
//!
//! Responsible for: a request signed for an empty region — RustFS's replication client — or for a
//! region the launcher does not serve being verified and answered, while the signature is still
//! checked over the presented bytes and a region legacy RustFS refuses is still refused.
//! NOT responsible for: the default refusal of either, which the conformance corpus pins
//! (`c-location-0005`), or the scope rules themselves (`rustfs_gateway_sig::enforce_scope`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/regions", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn signed_for(region: Option<&str>, secret: &str, method: http::Method, target: &str) -> http::Request<Bytes> {
    signed_in(region, MAIN_KEY, secret, method, target, Bytes::new(), &[])
}

/// Positive — the HeadBucket, ListObjectsV2 and PutObject of a client signing with an empty region
/// (RustFS's replication client) are verified and answered, as legacy RustFS answers them.
#[tokio::test]
async fn an_empty_signing_region_is_verified_and_answered() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    let head = exchange(&service, signed_for(None, MAIN_SECRET, http::Method::HEAD, "/regions")).await;
    assert_eq!(head.status(), 200, "{}", body_of(&head));
    let listed = exchange(&service, signed_for(None, MAIN_SECRET, http::Method::GET, "/regions?list-type=2")).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    let put = signed_in(
        None,
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/regions/replica",
        Bytes::from_static(b"r"),
        &[],
    );
    let stored = exchange(&service, put).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let read = exchange(&service, as_main(http::Method::GET, "/regions/replica", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(read.body().as_ref(), b"r");
}

/// A presigned `GET` of `path`, scoped to `region` (`None`: the empty region), signed now.
fn presigned_get(region: Option<&str>, path: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = match region {
        Some(region) => SigningScope::new(stamp.day(), region, SigService::S3).expect("a valid signing scope"),
        None => SigningScope::with_empty_region(stamp.day(), SigService::S3),
    };
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        &http::Method::GET,
        path,
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    let signed = SigV4Signer::new(credentials, scope)
        .presign(&signing, 900)
        .expect("a presignable request");
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::new()).expect("a valid presigned request")
}

/// Positive — a presigned URL scoped to the empty region is verified too, where the default
/// refuses it as an unreadable credential (`c-sig-0597`).
#[tokio::test]
async fn a_presigned_url_with_an_empty_region_is_verified() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/regions/shared", Bytes::from_static(b"s"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));

    let read = exchange(&service, presigned_get(None, "/regions/shared")).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(read.body().as_ref(), b"s");
}

/// Positive — a region in the configured-name grammar the launcher does not serve is verified.
#[tokio::test]
async fn an_unserved_region_in_the_grammar_is_verified() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for region in ["rustfs-local", "eu-west-1"] {
        let head = exchange(&service, signed_for(Some(region), MAIN_SECRET, http::Method::HEAD, "/regions")).await;
        assert_eq!(head.status(), 200, "{region}: {}", body_of(&head));
    }
}

/// Negative — the region is admitted, the signature is not: an empty-region request signed with
/// the wrong secret is `403 SignatureDoesNotMatch`, and nothing is stored.
#[tokio::test]
async fn n_an_empty_region_does_not_waive_the_signature() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    let forged = exchange(&service, signed_for(None, ALT_SECRET, http::Method::HEAD, "/regions")).await;
    assert_eq!(forged.status(), 403);
    let put = signed_in(
        None,
        MAIN_KEY,
        ALT_SECRET,
        http::Method::PUT,
        "/regions/forged",
        Bytes::from_static(b"f"),
        &[],
    );
    let refused = exchange(&service, put).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&refused));
    let missing = exchange(&service, as_main(http::Method::GET, "/regions/forged", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
}

/// Negative — a region legacy RustFS refuses (outside its region grammar) is still refused, and as
/// legacy refuses it: after the signature, with `400 InvalidRequest` (rustfs/gateway#1075). Until
/// #1075 this asserted the scope check's `AuthorizationHeaderMalformed`; the goldens differential
/// `a_scope_region_outside_the_legacy_grammar_is_refused_by_both_stacks_with_different_codes`
/// measures legacy's `InvalidRequest`, which is why the expectation moved.
#[tokio::test]
async fn n_a_region_outside_the_grammar_is_still_refused() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for region in ["US-EAST-1", "rustfs_local", "eu.west.1"] {
        let refused = exchange(&service, signed_for(Some(region), MAIN_SECRET, http::Method::GET, "/regions?location")).await;
        assert_eq!(refused.status(), 400, "{region}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains("<Code>InvalidRequest</Code>"),
            "{region}: {}",
            body_of(&refused)
        );
        assert!(!body_of(&refused).contains("<Region>"), "{region}: {}", body_of(&refused));
    }
}

/// Negative — the signature over such a region is checked first, as legacy checks it: a wrong
/// secret is `403 SignatureDoesNotMatch`, not the region refusal, and a write stores nothing.
#[tokio::test]
async fn n_a_wrong_signature_over_an_unreadable_region_is_signature_does_not_match() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    let forged = exchange(
        &service,
        signed_for(Some("US-EAST-1"), ALT_SECRET, http::Method::GET, "/regions?location"),
    )
    .await;
    assert_eq!(forged.status(), 403, "{}", body_of(&forged));
    assert!(body_of(&forged).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&forged));
    let put = signed_in(
        Some("US-EAST-1"),
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/regions/unread",
        Bytes::from_static(b"u"),
        &[],
    );
    let refused = exchange(&service, put).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    let missing = exchange(&service, as_main(http::Method::GET, "/regions/unread", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
}

// ── Regions past the parser's ceiling (the RustFS profile reads them at any length) ──

/// HMAC-SHA256, written out: this module signs regions the gateway's own signer refuses to name.
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `method path` signed by hand for the main identity with `secret`, scoped to `region` — any
/// ASCII-graphic string, as a legacy RustFS client may name — in the `Authorization` header, or in
/// the query when `presigned`. Only paths and regions that need no percent-encoding.
fn signed_by_hand(
    region: &str,
    secret: &str,
    method: http::Method,
    path: &str,
    body: Bytes,
    presigned: bool,
) -> http::Request<Bytes> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/{region}/s3/aws4_request");
    let (query, headers, signed_headers, payload) = if presigned {
        let credential = format!("{MAIN_KEY}%2F{}", scope.replace('/', "%2F"));
        let query = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={credential}&X-Amz-Date={stamp}&X-Amz-Expires=900&X-Amz-SignedHeaders=host"
        );
        (query, "host:s3.example.com\n".to_owned(), "host", "UNSIGNED-PAYLOAD".to_owned())
    } else {
        let payload = hex(&Sha256::digest(&body));
        let headers = format!("host:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n");
        (String::new(), headers, "host;x-amz-content-sha256;x-amz-date", payload)
    };
    let canonical = format!("{method}\n{path}\n{query}\n{headers}\n{signed_headers}\n{payload}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), day.as_bytes());
    for part in [region.as_bytes(), b"s3", b"aws4_request"] {
        key = hmac(&key, part);
    }
    let signature = hex(&hmac(&key, string_to_sign.as_bytes()));
    let mut request = http::Request::builder()
        .method(method)
        .header(http::header::HOST, "s3.example.com");
    if presigned {
        request = request.uri(format!("{path}?{query}&X-Amz-Signature={signature}"));
    } else {
        request = request
            .uri(path)
            .header("x-amz-date", stamp.as_str())
            .header("x-amz-content-sha256", payload.as_str())
            .header(
                http::header::AUTHORIZATION,
                format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"),
            );
    }
    if !body.is_empty() {
        request = request.header(http::header::CONTENT_LENGTH, body.len());
    }
    request.body(body).expect("a valid hand-signed request")
}

/// Positive — a region of the grammar longer than any real one is verified and served, in the
/// header and in a presigned URL, as legacy RustFS serves it; `us-east-1` is the control that
/// proves the hand-made signature is one the gateway verifies at all.
#[tokio::test]
async fn a_region_of_the_grammar_past_the_ceiling_is_verified_and_served() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for region in ["us-east-1".to_owned(), "a".repeat(65), "us-east-1-".repeat(400)] {
        let put = signed_by_hand(&region, MAIN_SECRET, http::Method::PUT, "/regions/long", Bytes::from_static(b"l"), false);
        let stored = exchange(&service, put).await;
        assert_eq!(stored.status(), 200, "{}: {}", region.len(), body_of(&stored));
        let read = exchange(
            &service,
            signed_by_hand(&region, MAIN_SECRET, http::Method::GET, "/regions/long", Bytes::new(), false),
        )
        .await;
        assert_eq!(read.status(), 200, "{}: {}", region.len(), body_of(&read));
        assert_eq!(read.body().as_ref(), b"l");
        let presigned = exchange(
            &service,
            signed_by_hand(&region, MAIN_SECRET, http::Method::GET, "/regions/long", Bytes::new(), true),
        )
        .await;
        assert_eq!(presigned.status(), 200, "{}: {}", region.len(), body_of(&presigned));
    }
}

/// Negative — past the ceiling the signature is still checked first and the grammar still holds:
/// a wrong secret is `403 SignatureDoesNotMatch`, a region outside the grammar is refused after the
/// signature with `400 InvalidRequest`, and neither stores anything.
#[tokio::test]
async fn n_a_region_past_the_ceiling_keeps_the_signature_and_the_grammar() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let long = "a".repeat(65);
    let shouted = "A".repeat(65);

    for presigned in [false, true] {
        let forged = exchange(
            &service,
            signed_by_hand(&long, ALT_SECRET, http::Method::GET, "/regions/absent", Bytes::new(), presigned),
        )
        .await;
        assert_eq!(forged.status(), 403, "{}", body_of(&forged));
        assert!(body_of(&forged).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&forged));
        let refused = exchange(
            &service,
            signed_by_hand(&shouted, MAIN_SECRET, http::Method::GET, "/regions/absent", Bytes::new(), presigned),
        )
        .await;
        assert_eq!(refused.status(), 400, "{}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>InvalidRequest</Code>"), "{}", body_of(&refused));
    }
    for (region, secret, status, code) in [
        (long.as_str(), ALT_SECRET, 403, "SignatureDoesNotMatch"),
        (shouted.as_str(), MAIN_SECRET, 400, "InvalidRequest"),
    ] {
        let put = signed_by_hand(region, secret, http::Method::PUT, "/regions/never", Bytes::from_static(b"n"), false);
        let refused = exchange(&service, put).await;
        assert_eq!(refused.status(), status, "{}", body_of(&refused));
        assert!(body_of(&refused).contains(&format!("<Code>{code}</Code>")), "{}", body_of(&refused));
    }
    let missing = exchange(&service, as_main(http::Method::GET, "/regions/never", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
}

/// `bytes` in standard base64, for a POST policy document.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |word, (index, byte)| word | u32::from(*byte) << (16 - 8 * index));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(word >> (18 - 6 * index) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const BOUNDARY: &str = "----RustFSSigningRegion";

/// A browser `POST` of `file` to the `regions` bucket under `key`, its policy signed by hand now for
/// the main identity with `secret`, scoped to `region`.
fn posted_by_hand(region: &str, secret: &str, key: &str, file: &str) -> http::Request<Bytes> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let now = i64::try_from(now).expect("a representable clock");
    let stamp = Timestamp::from_secs(now)
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let expires = Timestamp::from_secs(now + 3600)
        .render(TimestampFormat::Iso8601)
        .expect("a representable expiration");
    let day = &stamp[..8];
    let credential = format!("{MAIN_KEY}/{day}/{region}/s3/aws4_request");
    let document = format!(
        "{{\"expiration\":\"{expires}\",\"conditions\":[{{\"bucket\":\"regions\"}},[\"eq\",\"$key\",\"{key}\"],\
         {{\"x-amz-algorithm\":\"AWS4-HMAC-SHA256\"}},{{\"x-amz-credential\":\"{credential}\"}},{{\"x-amz-date\":\"{stamp}\"}}]}}"
    );
    let policy = base64(document.as_bytes());
    let mut signing_key = hmac(format!("AWS4{secret}").as_bytes(), day.as_bytes());
    for part in [region.as_bytes(), b"s3", b"aws4_request"] {
        signing_key = hmac(&signing_key, part);
    }
    let signature = hex(&hmac(&signing_key, policy.as_bytes()));
    let mut body = String::new();
    for (name, value) in [
        ("key", key),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", credential.as_str()),
        ("x-amz-date", stamp.as_str()),
        ("policy", policy.as_str()),
        ("x-amz-signature", signature.as_str()),
    ] {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"
    ));
    http::Request::builder()
        .method(http::Method::POST)
        .uri("/regions")
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid form request")
}

/// Positive — a browser `POST` whose policy is signed under a region past the ceiling is verified,
/// read again when the form is resolved, and stored, as legacy RustFS stores it; `us-east-1` is the
/// control. A wrong secret under the same region stores nothing.
#[tokio::test]
async fn a_post_policy_signed_past_the_ceiling_is_verified_and_stored() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;

    for (region, key) in [("us-east-1".to_owned(), "control"), ("a".repeat(65), "long")] {
        let posted = exchange(&service, posted_by_hand(&region, MAIN_SECRET, key, "f")).await;
        assert_eq!(posted.status(), 204, "{}: {}", region.len(), body_of(&posted));
        let read = exchange(&service, as_main(http::Method::GET, &format!("/regions/{key}"), Bytes::new())).await;
        assert_eq!(read.status(), 200, "{}: {}", region.len(), body_of(&read));
        assert_eq!(read.body().as_ref(), b"f");
    }
    let forged = exchange(&service, posted_by_hand(&"a".repeat(65), ALT_SECRET, "forged", "x")).await;
    assert_eq!(forged.status(), 403, "{}", body_of(&forged));
    assert!(body_of(&forged).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&forged));
    let missing = exchange(&service, as_main(http::Method::GET, "/regions/forged", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
}
