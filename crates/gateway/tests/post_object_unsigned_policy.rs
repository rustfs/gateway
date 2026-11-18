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

//! Anonymous browser forms carrying a POST policy no signature covers (rustfs/backlog#2734).
//!
//! Responsible for: that the RustFS profile parses and enforces such a policy with legacy RustFS's
//! codes and the sentences RustFS's suite reads, that the request stays anonymous whatever
//! credential fields the form names, and that every other assembly still refuses the policy.
//! NOT responsible for: signed forms (`post_object_sigv2.rs`, `post_object_runtime.rs`) or the
//! form grammar (`post_object_legacy_form.rs`).
//! Upstream: the facade public API. Downstream: the integration test target.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, SecurityFloor, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, allow_when,
};

const BOUNDARY: &str = "unsigned-policy-form";
const KEY: &str = "uploads/report.txt";
const LIVE: &str = "2099-01-01T00:00:00.000Z";
const BASE: &str = r#"{"bucket":"example-bucket"},{"key":"uploads/report.txt"},["content-length-range",0,1024]"#;

#[derive(Default)]
struct Backend {
    stored: Mutex<Option<(String, Vec<u8>)>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let mut body = input.body.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("the POST file stream failed"))?;
            if let Ok(data) = frame.into_data() {
                bytes.extend_from_slice(&data);
            }
        }
        *self.stored.lock().expect("observation lock") = Some((input.key.as_str().to_owned(), bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Assembly {
    /// Both halves of the RustFS profile.
    Profile,
    /// No legacy reading at all.
    Default,
    /// The profile's form grammar and signature recognition, without its policy reading.
    GrammarOnly,
    /// The policy reading and signature recognition, under the gateway's own form grammar.
    PolicyOnly,
}

struct Outcome {
    status: StatusCode,
    body: String,
    stored: Option<(String, Vec<u8>)>,
    /// Whether each authorization the request reached carried an authenticated identity.
    authenticated: Vec<bool>,
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |word, (at, byte)| word | u32::from(*byte) << (16 - 8 * at));
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(char::from(ALPHABET[(word >> (18 - 6 * at) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn policy(expiration: &str, conditions: &str) -> String {
    base64(format!(r#"{{"expiration":"{expiration}","conditions":[{conditions}]}}"#).as_bytes())
}

fn live(extra_conditions: &str) -> String {
    if extra_conditions.is_empty() {
        policy(LIVE, BASE)
    } else {
        policy(LIVE, &format!("{BASE},{extra_conditions}"))
    }
}

fn service(assembly: Assembly, backend: &Arc<Backend>, authenticated: &Arc<Mutex<Vec<bool>>>) -> rustfs_gateway::S3Service {
    let seen = Arc::clone(authenticated);
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let authenticator = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"));
    let builder = ServiceBuilder::new()
        .clock_with_skew_ack(
            crate::support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<PostObject, _>(Arc::clone(backend))
        .authorizer(allow_when(move |request| {
            seen.lock().expect("observation lock").push(request.identity.is_some());
            true
        }));
    let builder = match assembly {
        Assembly::Profile => builder.authenticator(authenticator.rustfs_profile()).rustfs_profile(),
        Assembly::Default => builder.authenticator(authenticator),
        Assembly::GrammarOnly => builder
            .authenticator(authenticator)
            .security_floor(SecurityFloor::new().recognize_signatures_as_legacy_rustfs())
            .legacy_rustfs_post_forms(),
        Assembly::PolicyOnly => builder
            .authenticator(authenticator)
            .security_floor(SecurityFloor::new().recognize_signatures_as_legacy_rustfs())
            .enforce_unsigned_post_policies_as_legacy_rustfs(),
    };
    builder.build().expect("complete service")
}

fn form(fields: &[(&str, &str)], file: &str) -> String {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"
    ));
    body
}

async fn post_with(assembly: Assembly, fields: &[(&str, &str)], file: &str, declared_length: bool) -> Outcome {
    let body = form(fields, file);
    let mut request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"));
    if declared_length {
        request = request.header("content-length", body.len());
    }
    exchange(assembly, request.body(Bytes::from(body)).expect("valid request")).await
}

async fn exchange(assembly: Assembly, request: Request<Bytes>) -> Outcome {
    let backend = Arc::new(Backend::default());
    let authenticated = Arc::new(Mutex::new(Vec::new()));
    let service = service(assembly, &backend, &authenticated);
    let response = service.call_bytes(request).await;
    let status = response.status();
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    let stored = backend.stored.lock().expect("observation lock").clone();
    let authenticated = authenticated.lock().expect("observation lock").clone();
    Outcome {
        status,
        body: String::from_utf8(body.to_vec()).expect("UTF-8 response"),
        stored,
        authenticated,
    }
}

async fn post(assembly: Assembly, fields: &[(&str, &str)], file: &str) -> Outcome {
    post_with(assembly, fields, file, true).await
}

/// The form's key and `encoded` policy, then `extra`.
fn fields<'a>(encoded: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![("key", KEY), ("policy", encoded)];
    fields.extend_from_slice(extra);
    fields
}

/// Asserts a refusal with `status` and `code` whose body names `mention`, and that nothing was
/// stored.
fn assert_refused(outcome: &Outcome, status: StatusCode, code: &str, mention: &str) {
    assert_eq!(outcome.status, status, "{}", outcome.body);
    assert!(outcome.body.contains(&format!("<Code>{code}</Code>")), "{}", outcome.body);
    assert!(outcome.body.contains(mention), "{mention:?} missing from {}", outcome.body);
    assert_eq!(outcome.stored, None, "a refused form stores nothing");
}

/// Every authorization stage the request reached, and it reached at least one, saw nobody.
fn assert_anonymous(authenticated: &[bool]) {
    assert!(!authenticated.is_empty() && authenticated.iter().all(|seen| !seen), "{authenticated:?}");
}

/// The opposite control: every authorization stage the request reached, and it reached at least
/// one, saw an authenticated identity.
fn assert_authenticated(authenticated: &[bool]) {
    assert!(!authenticated.is_empty() && authenticated.iter().all(|seen| *seen), "{authenticated:?}");
}

/// Positive — under the profile an anonymous form whose policy admits it is stored, and the
/// request reaches authorization as nobody.
#[tokio::test]
async fn the_profile_stores_an_anonymous_form_its_unsigned_policy_admits() {
    let encoded = live("");
    let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
    assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{}", outcome.body);
    assert_eq!(outcome.stored, Some((KEY.to_owned(), b"hello".to_vec())));
    assert_anonymous(&outcome.authenticated);
}

/// Positive and negative — credential fields without a signature authenticate nobody: an access
/// key the store holds (exempt from the policy, as legacy RustFS exempts it) and the SigV4 fields
/// the policy names both reach authorization anonymous.
#[tokio::test]
async fn n_credential_fields_without_a_signature_authenticate_nobody() {
    let sigv4 = live(
        r#"{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20990101/us-east-1/s3/aws4_request"},{"x-amz-date":"20990101T000000Z"}"#,
    );
    let plain = live("");
    let cases: [(&str, Vec<(&str, &str)>); 2] = [
        ("sigv2 access key", fields(&plain, &[("AWSAccessKeyId", "AKIDEXAMPLE")])),
        (
            "sigv4 fields",
            fields(
                &sigv4,
                &[
                    ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
                    ("x-amz-credential", "AKIDEXAMPLE/20990101/us-east-1/s3/aws4_request"),
                    ("x-amz-date", "20990101T000000Z"),
                ],
            ),
        ),
    ];
    for (case, fields) in cases {
        let outcome = post(Assembly::Profile, &fields, "hello").await;
        assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{case}: {}", outcome.body);
        assert_anonymous(&outcome.authenticated);
    }
}

/// A named form, its fields, and the status and code its refusal carries.
type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, StatusCode, &'a str);

/// Negative — a signature field the form names, even an empty one, or a SigV2 `signature` with no
/// access key, is a signed form that fails, not an unsigned policy: it is refused and nothing is
/// stored, where a policy with neither field would have been enforced and stored.
#[tokio::test]
async fn n_a_named_signature_field_makes_the_form_a_signed_one() {
    let encoded = live("");
    let cases: [Case; 3] = [
        (
            "empty x-amz-signature",
            fields(&encoded, &[("x-amz-signature", "")]),
            StatusCode::FORBIDDEN,
            "AccessDenied",
        ),
        (
            "empty signature",
            fields(&encoded, &[("signature", ""), ("AWSAccessKeyId", "AKIDEXAMPLE")]),
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
        ),
        (
            "signature without an access key",
            fields(&encoded, &[("signature", "c2lnbmF0dXJl")]),
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
        ),
    ];
    for (case, form, status, code) in cases {
        let outcome = post(Assembly::Profile, &form, "hello").await;
        assert_refused(&outcome, status, code, "<Message>");
        assert!(!outcome.body.contains("Policy condition"), "{case}: {}", outcome.body);
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut block = [0_u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Positive — the control for the anonymity cases above: a form whose SigV4 signature verifies
/// reaches authorization as the access key's principal, so an observer stuck on "anonymous"
/// would fail here.
#[tokio::test]
async fn a_correctly_signed_form_reaches_authorization_authenticated() {
    let encoded = policy(
        LIVE,
        &format!(
            r#"{BASE},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"}},{{"x-amz-date":"20260102T030405Z"}}"#
        ),
    );
    let mut signing_key = hmac(b"AWS4secret", b"20260102");
    for part in ["us-east-1", "s3", "aws4_request"] {
        signing_key = hmac(&signing_key, part.as_bytes());
    }
    let signature: String = hmac(&signing_key, encoded.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let form_fields = fields(
        &encoded,
        &[
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20260102T030405Z"),
            ("x-amz-signature", signature.as_str()),
        ],
    );
    let outcome = post(Assembly::Profile, &form_fields, "hello").await;
    assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{}", outcome.body);
    assert_eq!(outcome.stored, Some((KEY.to_owned(), b"hello".to_vec())));
    assert_authenticated(&outcome.authenticated);
}

/// A request whose `Authorization` header is signed, carrying `form_fields`.
fn header_signed(form_fields: &[(&str, &str)]) -> Request<Bytes> {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    crate::support::signed_target_with_body_and_headers(
        http::Method::POST,
        "/example-bucket",
        &[("content-type", content_type.as_str())],
        Bytes::from(form(form_fields, "hello")),
    )
}

/// Positive and negative — a signed `Authorization` header is verified before the form is read, and
/// a policy without signature fields does not take that identity away: the authorizer sees the
/// header's principal, and the policy is still enforced.
#[tokio::test]
async fn a_header_signed_request_keeps_its_principal_under_an_unsigned_policy() {
    let encoded = live(r#"{"x-amz-meta-project":"alpha-demo"}"#);
    let outcome = exchange(
        Assembly::Profile,
        header_signed(&fields(&encoded, &[("x-amz-meta-project", "alpha-demo")])),
    )
    .await;
    assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{}", outcome.body);
    assert_eq!(outcome.stored, Some((KEY.to_owned(), b"hello".to_vec())));
    assert_authenticated(&outcome.authenticated);

    let outcome = exchange(
        Assembly::Profile,
        header_signed(&fields(&encoded, &[("x-amz-meta-project", "beta-demo")])),
    )
    .await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "x-amz-meta-project");
}

/// Positive — an `x-ignore-*` field needs no condition.
#[tokio::test]
async fn an_ignored_field_needs_no_condition() {
    let encoded = live("");
    let outcome = post(Assembly::Profile, &fields(&encoded, &[("x-ignore-trace-id", "trace-1")]), "hello").await;
    assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{}", outcome.body);
}

/// Negative — a failed exact condition is `400 InvalidPolicyDocument` naming the field, and
/// echoes neither the policy's value nor the form's.
#[tokio::test]
async fn n_a_failed_exact_condition_names_the_field_and_echoes_no_value() {
    let encoded = live(r#"{"x-amz-meta-project":"alpha-demo"}"#);
    let outcome = post(Assembly::Profile, &fields(&encoded, &[("x-amz-meta-project", "beta-demo")]), "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "x-amz-meta-project");
    assert!(
        !outcome.body.contains("alpha-demo") && !outcome.body.contains("beta-demo"),
        "{}",
        outcome.body
    );
    assert!(outcome.authenticated.is_empty(), "refused before authorization");
}

/// Negative — a condition over a field the form does not carry is refused without naming it: the
/// name would come from the policy alone.
#[tokio::test]
async fn n_a_condition_over_an_absent_field_is_not_named() {
    let encoded = live(r#"{"x-amz-meta-hidden-name":"v"}"#);
    let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "Policy condition");
    assert!(!outcome.body.contains("hidden-name"), "{}", outcome.body);
}

/// Positive and negative — legacy RustFS reads a field the form lacks as the empty string under
/// `starts-with`: an empty prefix admits the form, a non-empty one and an exact match do not.
#[tokio::test]
async fn an_empty_prefix_over_an_absent_field_admits_the_form() {
    let encoded = live(r#"["starts-with","$x-amz-server-side-encryption",""]"#);
    let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
    assert_eq!(outcome.status, StatusCode::NO_CONTENT, "{}", outcome.body);
    for condition in [
        r#"["starts-with","$x-amz-meta-absent","a"]"#,
        r#"["eq","$x-amz-meta-absent",""]"#,
    ] {
        let encoded = live(condition);
        let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
        assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "Policy condition");
    }
}

/// Negative — a failed prefix condition names its operator.
#[tokio::test]
async fn n_a_failed_prefix_condition_names_starts_with() {
    let encoded = policy(LIVE, r#"{"bucket":"example-bucket"},["starts-with","$key","other/"]"#);
    let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
    assert_refused(
        &outcome,
        StatusCode::BAD_REQUEST,
        "InvalidPolicyDocument",
        "&apos;starts-with&apos; for field &apos;key&apos;",
    );
}

/// Negative — a field no condition names is `403 AccessDenied` naming it, whether the file's
/// length is declared (judged before the handler) or found at its end.
#[tokio::test]
async fn n_a_field_the_policy_does_not_name_is_denied_by_name() {
    let encoded = live("");
    for declared_length in [true, false] {
        let outcome = post_with(
            Assembly::Profile,
            &fields(&encoded, &[("Cache-Control", "max-age=60")]),
            "hello",
            declared_length,
        )
        .await;
        assert_refused(
            &outcome,
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "&quot;cache-control&quot; not specified in the policy",
        );
    }
}

/// Negative — a file outside the size range answers the range's own code and sentence, under the
/// profile and under the policy switch alone, whose grammar finds the size only at the file's end.
#[tokio::test]
async fn n_a_file_outside_the_size_range_is_refused_with_its_code() {
    let large = policy(
        LIVE,
        r#"{"bucket":"example-bucket"},{"key":"uploads/report.txt"},["content-length-range",0,5]"#,
    );
    let small = policy(
        LIVE,
        r#"{"bucket":"example-bucket"},{"key":"uploads/report.txt"},["content-length-range",10,20]"#,
    );
    for (assembly, declared_length) in [
        (Assembly::Profile, true),
        (Assembly::Profile, false),
        (Assembly::PolicyOnly, true),
    ] {
        let outcome = post_with(assembly, &fields(&large, &[]), "payload-too-large", declared_length).await;
        assert_refused(&outcome, StatusCode::BAD_REQUEST, "EntityTooLarge", "maximum allowed object size");
        let outcome = post_with(assembly, &fields(&small, &[]), "tiny", declared_length).await;
        assert_refused(&outcome, StatusCode::BAD_REQUEST, "EntityTooSmall", "minimum allowed object size");
    }
}

/// Negative — a form `bucket` other than the routed one is `InvalidPolicyDocument` naming the
/// value the form sent, escaped as every message is.
#[tokio::test]
async fn n_a_form_bucket_other_than_the_routed_one_is_named() {
    let encoded = live("");
    let outcome = post(Assembly::Profile, &fields(&encoded, &[("bucket", "different-bucket")]), "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "different-bucket");
    let outcome = post(Assembly::Profile, &fields(&encoded, &[("bucket", "a<b")]), "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "a&lt;b");
    assert!(!outcome.body.contains("a<b"), "{}", outcome.body);
}

/// Negative — an expired unsigned policy is `403 AccessDenied`, as a signed one would be.
#[tokio::test]
async fn n_an_expired_unsigned_policy_is_denied() {
    let encoded = policy("2000-01-01T00:00:00.000Z", BASE);
    let outcome = post(Assembly::Profile, &fields(&encoded, &[]), "hello").await;
    assert_refused(&outcome, StatusCode::FORBIDDEN, "AccessDenied", "Request has expired");
}

/// Negative — a policy that cannot be read is `400 InvalidPolicyDocument`.
#[tokio::test]
async fn n_an_unreadable_policy_is_an_invalid_policy_document() {
    for encoded in ["not base64!", &base64(b"{\"conditions\":[]}")] {
        let outcome = post(Assembly::Profile, &fields(encoded, &[]), "hello").await;
        assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "failed to parse POST policy");
    }
}

/// Negative — off the profile an unsigned policy is refused as before, byte for byte, by the
/// gateway's default and by the profile's form grammar alone: the policy reading is its own switch.
#[tokio::test]
async fn n_every_other_assembly_still_refuses_an_unsigned_policy() {
    let encoded = live(r#"{"x-amz-meta-project":"alpha-demo"}"#);
    for assembly in [Assembly::Default, Assembly::GrammarOnly] {
        for extra in [
            &[("x-amz-meta-project", "alpha-demo")][..],
            &[("x-amz-meta-project", "beta-demo")],
        ] {
            let outcome = post(assembly, &fields(&encoded, extra), "hello").await;
            assert_refused(
                &outcome,
                StatusCode::BAD_REQUEST,
                "MalformedPOSTRequest",
                "the POST policy was not accepted",
            );
            assert!(outcome.authenticated.is_empty());
        }
    }
}

/// Negative — under the profile a repeated `key` or `bucket` is `400 InvalidPolicyDocument`, the
/// answer legacy RustFS gives once its policy check reads the last value, and still refused before
/// either value is acted on.
#[tokio::test]
async fn n_a_repeated_key_or_bucket_is_an_invalid_policy_document() {
    let encoded = live("");
    let repeated_key = [("key", KEY), ("key", "other-object.txt"), ("policy", encoded.as_str())];
    let outcome = post(Assembly::Profile, &repeated_key, "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "multiple values");
    let repeated_bucket = fields(&encoded, &[("bucket", "example-bucket"), ("bucket", "anotherbucket")]);
    let outcome = post(Assembly::Profile, &repeated_bucket, "hello").await;
    assert_refused(&outcome, StatusCode::BAD_REQUEST, "InvalidPolicyDocument", "multiple values");
    assert!(!outcome.body.contains("anotherbucket"), "{}", outcome.body);
}

/// Negative — any other repeated field, and a repeated `key` off the profile, stay the form's own
/// `400 MalformedPOSTRequest`.
#[tokio::test]
async fn n_other_repeated_fields_stay_malformed() {
    let encoded = live("");
    let other = fields(&encoded, &[("x-amz-meta-a", "1"), ("x-amz-meta-a", "2")]);
    let key = [("key", KEY), ("key", "other-object.txt"), ("policy", encoded.as_str())];
    for (assembly, form) in [
        (Assembly::Profile, &other[..]),
        (Assembly::Default, &key[..]),
        (Assembly::GrammarOnly, &key[..]),
    ] {
        let outcome = post(assembly, form, "hello").await;
        assert_refused(
            &outcome,
            StatusCode::BAD_REQUEST,
            "MalformedPOSTRequest",
            "the POST form was not accepted",
        );
    }
}
