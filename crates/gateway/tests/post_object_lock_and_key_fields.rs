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

//! The Object Lock and customer-key fields of a POST Object form (rustfs/gateway#1167): carried to
//! the handler as the `PutObject` members of the same name, the lock actions asked for them, and a
//! customer key held to the rules a header key is held to.
//!
//! Responsible for: the three `x-amz-object-lock-*` fields and the three
//! `x-amz-server-side-encryption-customer-*` fields reaching `PostObjectInput::fields` under both
//! grammars; `s3:PutObjectRetention` and `s3:PutObjectLegalHold` asked for a form naming a lock,
//! an empty field included, by the form's fields and never by the request's headers; a
//! retain-until date its grammar cannot read (legacy RustFS's RFC 3339 reading under the RustFS
//! profile, the header's ISO 8601 one otherwise) refused before authorization; and a form key
//! refused over cleartext, incomplete, with another algorithm, beside a managed algorithm, or
//! disagreeing with its digest, exactly as the header gate refuses it, never reaching a handler
//! and never echoed.
//! NOT responsible for: the other members (`post_object_legacy_fields.rs`), the closed value sets
//! of the mode and hold, which the handler holds a header to as well (the conformance fixture), or
//! what a backend stores.
//! Upstream: the facade's public API. Downstream: nothing.
//!
//! Evidence: legacy RustFS's `put_object` access hook runs for a POST and asks
//! `s3:PutObjectLegalHold` for a form naming a hold and `s3:PutObjectRetention` for one naming a
//! mode or a date (`rustfs/src/storage/access.rs:3214-3220` at rustfs/rustfs `19978b2cb6`), and
//! its handler encrypts with the key the form carries, falling back to the request's own headers
//! (`rustfs/src/app/object/put.rs:1283-1287`). Its cleartext customer-key refusal reads headers
//! only, so a form key over cleartext is one it would have used; this gateway refuses it.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectFields, PostObjectOutput};
use rustfs_gateway::{
    Credentials, Decision, ETag, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials, Timestamp,
    TimestampFormat, TransportSecurity, decide_with,
};
use rustfs_gateway_core::sse::headers::{
    SSE_ALGORITHM, SSE_BUCKET_KEY_ENABLED, SSE_CONTEXT, SSE_KMS_KEY_ID, SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5,
};

const BOUNDARY: &str = "----RustFSLockAndKeyFields";

/// A 32-byte key and its true MD5, and a second key with its own.
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const MD5_A: &str = "tP/LI3N87DFaSk0aoqYgzg==";
const MD5_B: &str = "v2HomVYPq94vbXb0BabrcA==";

const PLAINTEXT_SENTENCE: &str = "requests specifying a customer-provided encryption key must be made over a secure connection";

/// Records the members each handled form was handed.
#[derive(Default)]
struct Backend {
    handed: Mutex<Option<PostObjectFields>>,
    managed_algorithm: Mutex<Option<String>>,
    customer_proof: Mutex<Option<bool>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        *self.managed_algorithm.lock().expect("observation lock") = request
            .sse()
            .managed_algorithm()
            .map(|algorithm| algorithm.as_str().to_owned());
        *self.customer_proof.lock().expect("observation lock") = Some(request.sse().customer_key_fingerprint().is_some());
        let input = request.into_input();
        let _ = input.body.into_body().collect().await;
        *self.handed.lock().expect("observation lock") = Some(input.fields);
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("storage-etag").expect("the fixture entity tag is valid")),
            version_id: None,
        }))
    }
}

/// How one exchange is set up.
#[derive(Clone, Copy)]
struct Setup {
    legacy_grammar: bool,
    allow: bool,
    transport: TransportSecurity,
    /// The RustFS profile's pre-routing cleartext customer-key gate, which reads headers only.
    plaintext_keys_before_routing: bool,
    /// Lock headers on the request itself, which a form upload never reads.
    lock_request_headers: bool,
    managed_request_header: Option<&'static str>,
}

const OVER_TLS: Setup = Setup {
    legacy_grammar: true,
    allow: true,
    transport: TransportSecurity::Encrypted,
    plaintext_keys_before_routing: false,
    lock_request_headers: false,
    managed_request_header: None,
};

const OVER_CLEARTEXT: Setup = Setup {
    transport: TransportSecurity::Plaintext,
    ..OVER_TLS
};

/// What came back: the status, the answer, what the handler was handed, and the actions the
/// authorizer was asked, in order.
struct Answer {
    status: StatusCode,
    body: String,
    handed: Option<PostObjectFields>,
    managed_algorithm: Option<String>,
    customer_proof: Option<bool>,
    asked: Vec<String>,
}

impl Answer {
    /// The actions asked besides the base one, in order. The base action is asked at the route
    /// stage and again at the input stage; the extras are the route stage's and come once each.
    fn extras_asked(&self) -> Vec<&str> {
        assert_eq!(self.asked.first().map(String::as_str), Some("s3:PutObject"), "{:?}", self.asked);
        self.asked
            .iter()
            .map(String::as_str)
            .filter(|action| *action != "s3:PutObject")
            .collect()
    }
}

fn service(backend: Arc<Backend>, setup: Setup, asked: Arc<Mutex<Vec<String>>>) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let allow = setup.allow;
    let mut builder = ServiceBuilder::new()
        .register::<PostObject, _>(backend)
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty region set"),
        ))
        .authorizer(decide_with(move |request| {
            asked.lock().expect("observation lock").push(request.action.to_owned());
            if allow { Decision::Allow } else { Decision::Deny }
        }));
    if setup.legacy_grammar {
        builder = builder.legacy_rustfs_post_forms();
    }
    if setup.plaintext_keys_before_routing {
        builder = builder.refuse_plaintext_customer_keys_before_routing();
    }
    builder.build().expect("complete POST Object service")
}

/// A form with the key `k`, then `fields` in order, then a one-byte file.
fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = String::new();
    for (name, value) in [("key", "k")].iter().chain(fields) {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nc\r\n--{BOUNDARY}--\r\n"
    ));
    body.into_bytes()
}

async fn post(fields: &[(&str, &str)], setup: Setup) -> Answer {
    post_with_headers(fields, &[], setup).await
}

async fn post_with_headers(fields: &[(&str, &str)], headers: &[(&str, &str)], setup: Setup) -> Answer {
    let backend = Arc::new(Backend::default());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let body = form(fields);
    let mut request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len());
    if setup.lock_request_headers {
        request = request
            .header("x-amz-object-lock-mode", "GOVERNANCE")
            .header("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")
            .header("x-amz-object-lock-legal-hold", "ON");
    }
    if let Some(algorithm) = setup.managed_request_header {
        request = request.header(SSE_ALGORITHM, algorithm);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Bytes::from(body)).expect("valid request");
    // Exactly what a TLS-terminating transport does, and the only channel that is believed.
    request.extensions_mut().insert(setup.transport);
    let response = service(Arc::clone(&backend), setup, Arc::clone(&asked))
        .call_bytes(request)
        .await;
    let status = response.status();
    let answer = response.into_body().collect().await.expect("the answer body").to_bytes();
    let handed = backend.handed.lock().expect("observation lock").take();
    let managed_algorithm = backend.managed_algorithm.lock().expect("observation lock").take();
    let customer_proof = backend.customer_proof.lock().expect("observation lock").take();
    let asked = asked.lock().expect("observation lock").clone();
    Answer {
        status,
        body: String::from_utf8_lossy(&answer).into_owned(),
        handed,
        managed_algorithm,
        customer_proof,
        asked,
    }
}

fn trio(key: &'static str, digest: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![(SSEC_ALGORITHM, "AES256"), (SSEC_KEY, key), (SSEC_KEY_MD5, digest)]
}

const LOCK: [(&str, &str); 3] = [
    ("x-amz-object-lock-mode", "GOVERNANCE"),
    ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
    ("x-amz-object-lock-legal-hold", "ON"),
];

/// Asserts the answer was refused before any handler, with `code`, and carries the key nowhere.
fn refused_before_the_handler(answer: &Answer, code: &str, context: &str) {
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{context}: {}", answer.body);
    assert!(answer.body.contains(&format!("<Code>{code}</Code>")), "{context}: {}", answer.body);
    assert!(answer.handed.is_none(), "{context}: the handler ran");
    assert!(!answer.body.contains(KEY_A), "{context}: the key was echoed");
}

// ── positive ──────────────────────────────────────────────────────────────────────────────────

/// Positive — under either grammar, over TLS, the six fields reach the handler as the `PutObject`
/// members of the same name: the mode and hold as sent, the instant parsed, the key readable
/// only through its exposure boundary. A mode outside the closed set is carried as sent too; the
/// closed set is the handler's rule, as it is for the header.
#[tokio::test]
async fn the_lock_and_customer_key_fields_reach_the_handler_as_the_same_named_members() {
    for legacy_grammar in [true, false] {
        let setup = Setup {
            legacy_grammar,
            ..OVER_TLS
        };
        let mut fields = LOCK.to_vec();
        fields.extend(trio(KEY_A, MD5_A));
        let answer = post(&fields, setup).await;
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{legacy_grammar}: {}", answer.body);
        let handed = answer.handed.expect("the handler ran");
        assert_eq!(handed.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some("GOVERNANCE"));
        assert_eq!(
            handed.object_lock_retain_until_date,
            Some(Timestamp::parse("2030-01-01T00:00:00Z", TimestampFormat::Iso8601).expect("an instant"))
        );
        assert_eq!(handed.object_lock_legal_hold_status.as_ref().map(|status| status.as_str()), Some("ON"));
        assert_eq!(handed.sse_customer_algorithm.as_deref(), Some("AES256"));
        assert_eq!(handed.sse_customer_key.as_ref().map(|key| key.expose_secret()), Some(KEY_A));
        assert_eq!(handed.sse_customer_key_md5.as_deref(), Some(MD5_A));

        let answer = post(&[("x-amz-object-lock-mode", "ARCHIVE"), ("x-amz-object-lock-legal-hold", "on")], setup).await;
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{legacy_grammar}: {}", answer.body);
        let handed = answer.handed.expect("the handler ran");
        assert_eq!(handed.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some("ARCHIVE"));
        assert_eq!(handed.object_lock_legal_hold_status.as_ref().map(|status| status.as_str()), Some("on"));
        assert_eq!(handed.object_lock_retain_until_date, None);
    }
}

/// Positive — a form naming a mode or a date is asked `s3:PutObjectRetention`, one naming a hold
/// (`OFF` included, as legacy RustFS reads it) `s3:PutObjectLegalHold`, each after the base action,
/// under either grammar. A field sent empty is set, never absent for being empty: legacy RustFS's
/// decoder reads it as `Some("")` and its hook asks the action for it, and the handler is handed
/// the empty member, so the action is asked exactly when the member reaches the handler.
#[tokio::test]
async fn a_form_naming_a_lock_is_asked_the_lock_actions() {
    for legacy_grammar in [true, false] {
        for (fields, expected) in [
            (LOCK.to_vec(), vec!["s3:PutObjectRetention", "s3:PutObjectLegalHold"]),
            (
                vec![("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")],
                vec!["s3:PutObjectRetention"],
            ),
            (vec![("x-amz-object-lock-legal-hold", "OFF")], vec!["s3:PutObjectLegalHold"]),
            (vec![("x-amz-object-lock-mode", "")], vec!["s3:PutObjectRetention"]),
            (vec![("x-amz-object-lock-legal-hold", "")], vec!["s3:PutObjectLegalHold"]),
        ] {
            let setup = Setup {
                legacy_grammar,
                ..OVER_TLS
            };
            let answer = post(&fields, setup).await;
            let context = format!("{legacy_grammar} {fields:?}");
            assert_eq!(answer.status, StatusCode::NO_CONTENT, "{context}: {}", answer.body);
            assert_eq!(answer.extras_asked(), expected, "{context}");
            let handed = answer.handed.expect("the handler ran");
            let handed_lock = handed.object_lock_mode.is_some()
                || handed.object_lock_retain_until_date.is_some()
                || handed.object_lock_legal_hold_status.is_some();
            assert!(handed_lock, "{context}: the member that asked was not handed");
        }
    }
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

/// Negative — a form without a lock field asks the base action alone, and a field whose name only
/// starts with a lock field's triggers nothing; lock headers on the request itself trigger nothing
/// and set nothing, since a form upload reads none of its request's headers.
#[tokio::test]
async fn n_a_form_without_lock_fields_asks_only_the_base_action_whatever_its_headers_say() {
    for (fields, setup) in [
        (Vec::new(), OVER_TLS),
        (vec![("x-amz-object-lock-mode-extra", "")], OVER_TLS),
        (
            Vec::new(),
            Setup {
                lock_request_headers: true,
                ..OVER_TLS
            },
        ),
    ] {
        let answer = post(&fields, setup).await;
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{fields:?}: {}", answer.body);
        assert!(answer.extras_asked().is_empty(), "{fields:?}: {:?}", answer.asked);
        let handed = answer.handed.expect("the handler ran");
        assert!(handed.object_lock_retain_until_date.is_none(), "{fields:?}");
        assert!(handed.object_lock_legal_hold_status.is_none(), "{fields:?}");
    }
}

/// Negative — a retain-until date the decoder cannot read is `400 InvalidArgument` before
/// authorization, under either grammar: the authorizer is never asked and no handler runs.
#[tokio::test]
async fn n_an_unreadable_retain_until_date_is_refused_before_authorization() {
    for legacy_grammar in [true, false] {
        for value in ["Tue, 01 Jan 2030 00:00:00 GMT", "2030-01-01", "", "20300101T000000Z", "value"] {
            let setup = Setup {
                legacy_grammar,
                allow: false,
                ..OVER_TLS
            };
            let answer = post(&[("x-amz-object-lock-retain-until-date", value)], setup).await;
            refused_before_the_handler(&answer, "InvalidArgument", &format!("{legacy_grammar} {value:?}"));
            assert!(answer.asked.is_empty(), "{value:?}: the authorizer was asked first");
        }
    }
}

/// Negative — the retain-until date is read with the grammar of the profile that reads the form:
/// the RustFS profile reads it as legacy RustFS's RFC 3339 reader does
/// (`post_object/legacy_date.rs`), the gateway grammar as the ISO 8601 instant the header is
/// (`q-timestamp-0011`). Each spelling here is read by one of them, as the instant it names, and
/// refused by the other `400 InvalidArgument` before authorization.
#[tokio::test]
async fn n_each_grammar_refuses_the_dates_only_the_other_reads() {
    for (value, legacy_reads, instant) in [
        ("2030-01-01t00:00:00z", true, "2030-01-01T00:00:00Z"),
        ("2030-01-01 00:00:00Z", true, "2030-01-01T00:00:00Z"),
        ("2030-12-31T23:59:60Z", true, "2030-12-31T23:59:59.999999999Z"),
        ("2030-01-01T08:00:00+0800", false, "2030-01-01T00:00:00Z"),
        ("2030-01-01T00:00:00.Z", false, "2030-01-01T00:00:00Z"),
    ] {
        for legacy_grammar in [true, false] {
            let setup = Setup {
                legacy_grammar,
                ..OVER_TLS
            };
            let answer = post(&[("x-amz-object-lock-retain-until-date", value)], setup).await;
            let context = format!("{legacy_grammar} {value:?}");
            if legacy_grammar == legacy_reads {
                assert_eq!(answer.status, StatusCode::NO_CONTENT, "{context}: {}", answer.body);
                let handed = answer.handed.expect("the handler ran");
                assert_eq!(
                    handed.object_lock_retain_until_date,
                    Some(Timestamp::parse(instant, TimestampFormat::Iso8601).expect("an instant")),
                    "{context}"
                );
            } else {
                refused_before_the_handler(&answer, "InvalidArgument", &context);
                assert!(answer.asked.is_empty(), "{context}: the authorizer was asked first");
            }
        }
    }
}

/// Negative — a customer key in a form over cleartext is refused as a header key is: the same
/// code and sentence, before its shape is judged, a lone fragment of the trio and a mixed-case
/// spelling included, under either grammar and whether or not the RustFS profile's header-only
/// pre-routing gate is on. It sits where the header gate sits, after authorization, so a refused
/// caller is told `403` first.
#[tokio::test]
async fn n_a_form_customer_key_over_cleartext_is_refused_as_a_header_key_is() {
    for legacy_grammar in [true, false] {
        for plaintext_keys_before_routing in [false, true] {
            let setup = Setup {
                legacy_grammar,
                plaintext_keys_before_routing,
                ..OVER_CLEARTEXT
            };
            // The third spelling is the trio in mixed case: a field name is read without regard to
            // case, so a differently cased key field cannot slip past the gate as "some other field".
            let mixed_case = vec![
                ("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256"),
                ("X-Amz-Server-Side-Encryption-Customer-Key", KEY_A),
                ("X-Amz-Server-Side-Encryption-Customer-Key-MD5", MD5_A),
            ];
            for fields in [trio(KEY_A, MD5_A), trio(KEY_A, MD5_B), mixed_case, vec![(SSEC_KEY_MD5, "")]] {
                let answer = post(&fields, setup).await;
                let context = format!("{legacy_grammar} {plaintext_keys_before_routing} {fields:?}");
                refused_before_the_handler(&answer, "InvalidRequest", &context);
                assert!(answer.body.contains(PLAINTEXT_SENTENCE), "{context}: {}", answer.body);
            }
        }
    }
    let answer = post(
        &trio(KEY_A, MD5_A),
        Setup {
            allow: false,
            ..OVER_CLEARTEXT
        },
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert!(answer.handed.is_none());
    assert!(!answer.body.contains(KEY_A), "the key was echoed");
}

/// Negative — over TLS, a form key is held to the header rules with the header sentences: all
/// three or none, `AES256`, a key that agrees with its digest, and no managed algorithm beside it
/// under either grammar.
#[tokio::test]
async fn n_a_form_customer_key_over_tls_is_held_to_the_header_rules() {
    let mut contradiction = trio(KEY_A, MD5_A);
    contradiction.push((SSE_ALGORITHM, "AES256"));
    for (fields, sentence, grammars) in [
        (
            vec![(SSEC_ALGORITHM, "AES256"), (SSEC_KEY, KEY_A)],
            "algorithm, key and key MD5 headers must all be present or all be absent",
            &[true, false][..],
        ),
        (
            vec![(SSEC_ALGORITHM, "aes256"), (SSEC_KEY, KEY_A), (SSEC_KEY_MD5, MD5_A)],
            "the customer-provided encryption algorithm must be AES256",
            &[true, false][..],
        ),
        (trio(KEY_A, MD5_B), "must be base64 of 32 and 16 bytes and must agree", &[true, false][..]),
        (contradiction, "not both", &[true, false][..]),
    ] {
        for legacy_grammar in grammars.iter().copied() {
            let answer = post(
                &fields,
                Setup {
                    legacy_grammar,
                    ..OVER_TLS
                },
            )
            .await;
            let context = format!("{legacy_grammar} {fields:?}");
            refused_before_the_handler(&answer, "InvalidArgument", &context);
            assert!(answer.body.contains(sentence), "{context}: {}", answer.body);
        }
    }
}

/// Positive — both grammars carry all four managed fields and the proof selected from them.
#[tokio::test]
async fn managed_form_fields_reach_the_handler_with_the_matching_proof() {
    for legacy_grammar in [true, false] {
        let answer = post(
            &[
                (SSE_ALGORITHM, "aws:kms"),
                ("x-amz-server-side-encryption-aws-kms-key-id", "example-key"),
                ("x-amz-server-side-encryption-context", "e30="),
                ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
            ],
            Setup {
                legacy_grammar,
                ..OVER_TLS
            },
        )
        .await;
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{legacy_grammar}: {}", answer.body);
        assert_eq!(answer.managed_algorithm.as_deref(), Some("aws:kms"), "{legacy_grammar}");
        let fields = answer.handed.expect("the handler ran");
        assert_eq!(
            fields.server_side_encryption.as_ref().map(|algorithm| algorithm.as_str()),
            Some("aws:kms")
        );
        assert_eq!(fields.ssekms_key_id.as_deref(), Some("example-key"));
        assert_eq!(fields.ssekms_encryption_context.as_deref(), Some("e30="));
        assert_eq!(fields.bucket_key_enabled, Some(true));
    }
}

/// Negative — gateway-grammar managed declarations use the header rules, including orphan qualifiers,
/// the closed algorithm set, KMS-only qualifiers, and the bounded JSON context grammar.
#[tokio::test]
async fn n_managed_form_fields_are_held_to_the_header_rules() {
    let legacy_grammar = false;
    for fields in [
        vec![(SSE_ALGORITHM, "aes256")],
        vec![(SSE_ALGORITHM, "")],
        vec![("x-amz-server-side-encryption-aws-kms-key-id", "example-key")],
        vec![("x-amz-server-side-encryption-context", "e30=")],
        vec![("x-amz-server-side-encryption-bucket-key-enabled", "false")],
        vec![
            (SSE_ALGORITHM, "AES256"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "example-key"),
        ],
        vec![(SSE_ALGORITHM, "AES256"), ("x-amz-server-side-encryption-context", "e30=")],
        vec![
            (SSE_ALGORITHM, "aws:kms"),
            ("x-amz-server-side-encryption-context", "not-base64"),
        ],
        vec![(SSE_ALGORITHM, "aws:kms"), ("x-amz-server-side-encryption-context", "W10=")],
        vec![
            (SSE_ALGORITHM, "aws:kms"),
            ("x-amz-server-side-encryption-bucket-key-enabled", "yes"),
        ],
    ] {
        let answer = post(
            &fields,
            Setup {
                legacy_grammar,
                ..OVER_TLS
            },
        )
        .await;
        refused_before_the_handler(&answer, "InvalidArgument", &format!("{legacy_grammar}: {fields:?}"));
    }
}

/// Negative — only the legacy grammar delegates ignored qualifiers and opaque algorithms to
/// the host. Its proof describes the effective legacy request, while every raw member is retained.
#[tokio::test]
async fn n_legacy_managed_intent_does_not_change_raw_fields_or_relax_the_gateway_grammar() {
    for (fields, header, effective) in [
        (vec![(SSE_CONTEXT, "not-base64")], None, None),
        (vec![(SSE_BUCKET_KEY_ENABLED, "false")], None, None),
        (vec![(SSE_ALGORITHM, "AES256"), (SSE_CONTEXT, "not-base64")], None, Some("AES256")),
        (vec![(SSE_ALGORITHM, "AES256"), (SSE_KMS_KEY_ID, "key")], None, Some("aws:kms")),
        (vec![(SSE_ALGORITHM, "AWS:KMS")], None, Some("aws:kms")),
        (vec![(SSE_KMS_KEY_ID, "")], None, Some("aws:kms")),
        (vec![(SSE_ALGORITHM, "opaque"), (SSE_KMS_KEY_ID, "key")], None, Some("aws:kms")),
        (vec![(SSE_ALGORITHM, "aes256")], None, None),
        (vec![(SSE_ALGORITHM, "")], None, None),
        (vec![(SSE_ALGORITHM, "opaque")], Some("AES256"), Some("AES256")),
    ] {
        let context = format!("{fields:?} header={header:?}");
        let legacy = post(
            &fields,
            Setup {
                managed_request_header: header,
                ..OVER_TLS
            },
        )
        .await;
        assert_eq!(legacy.status, StatusCode::NO_CONTENT, "{context}: {}", legacy.body);
        assert_eq!(legacy.managed_algorithm.as_deref(), effective, "{context}");
        assert_eq!(legacy.customer_proof, Some(false), "{context}");
        let handed = legacy.handed.expect("the legacy handler ran");
        let raw = |name| fields.iter().find_map(|(field, value)| (*field == name).then_some(*value));
        assert_eq!(
            handed.server_side_encryption.as_ref().map(|algorithm| algorithm.as_str()),
            raw(SSE_ALGORITHM),
            "{context}"
        );
        assert_eq!(handed.ssekms_key_id.as_deref(), raw(SSE_KMS_KEY_ID), "{context}");
        assert_eq!(handed.ssekms_encryption_context.as_deref(), raw(SSE_CONTEXT), "{context}");
        assert_eq!(
            handed.bucket_key_enabled,
            raw(SSE_BUCKET_KEY_ENABLED).map(|value| value == "true"),
            "{context}"
        );
        let gateway = post(
            &fields,
            Setup {
                legacy_grammar: false,
                managed_request_header: header,
                ..OVER_TLS
            },
        )
        .await;
        refused_before_the_handler(&gateway, "InvalidArgument", &context);
    }
}

/// Negative — an opaque legacy algorithm receives no managed proof; the gateway grammar's
/// recognized DSSE declaration does, and a real legacy KMS header remains effective beside AES.
#[tokio::test]
async fn n_legacy_opaque_values_and_header_kms_keep_their_existing_proof_boundary() {
    for (fields, header, legacy_proof, gateway_proof) in [
        (vec![(SSE_ALGORITHM, "aws:kms:dsse")], None, None, Some("aws:kms:dsse")),
        (vec![(SSE_ALGORITHM, "AES256")], Some("aws:kms"), Some("aws:kms"), Some("AES256")),
    ] {
        for (legacy_grammar, expected) in [(true, legacy_proof), (false, gateway_proof)] {
            let answer = post(
                &fields,
                Setup {
                    legacy_grammar,
                    managed_request_header: header,
                    ..OVER_TLS
                },
            )
            .await;
            assert_eq!(answer.status, StatusCode::NO_CONTENT, "{legacy_grammar} {fields:?}: {}", answer.body);
            assert_eq!(answer.managed_algorithm.as_deref(), expected, "{legacy_grammar} {fields:?}");
            assert_eq!(answer.customer_proof, Some(false));
            assert_eq!(
                answer
                    .handed
                    .expect("the handler ran")
                    .server_side_encryption
                    .as_ref()
                    .map(|algorithm| algorithm.as_str()),
                Some(fields[0].1)
            );
        }
    }
}

/// Negative — the legacy customer-key gate still ignores KMS qualifiers, without ignoring the
/// raw managed algorithm's contradiction. The gateway grammar judges all of the fields.
#[tokio::test]
async fn n_legacy_customer_key_lookup_preserves_its_original_contradictions() {
    for qualifier in [
        (SSE_CONTEXT, "not-base64"),
        (SSE_KMS_KEY_ID, ""),
        (SSE_BUCKET_KEY_ENABLED, "false"),
    ] {
        let mut fields = trio(KEY_A, MD5_A);
        fields.push(qualifier);
        let legacy = post(&fields, OVER_TLS).await;
        assert_eq!(legacy.status, StatusCode::NO_CONTENT, "{qualifier:?}: {}", legacy.body);
        assert_eq!(legacy.customer_proof, Some(true), "{qualifier:?}");
        assert_eq!(legacy.managed_algorithm, None, "{qualifier:?}");
        let handed = legacy.handed.expect("the legacy handler ran");
        match qualifier.0 {
            SSE_CONTEXT => assert_eq!(handed.ssekms_encryption_context.as_deref(), Some(qualifier.1)),
            SSE_KMS_KEY_ID => assert_eq!(handed.ssekms_key_id.as_deref(), Some(qualifier.1)),
            _ => assert_eq!(handed.bucket_key_enabled, Some(false)),
        }
        let gateway = post(
            &fields,
            Setup {
                legacy_grammar: false,
                ..OVER_TLS
            },
        )
        .await;
        refused_before_the_handler(&gateway, "InvalidArgument", &format!("{qualifier:?}"));
    }
    for algorithm in ["opaque", ""] {
        let mut fields = trio(KEY_A, MD5_A);
        fields.push((SSE_ALGORITHM, algorithm));
        let answer = post(&fields, OVER_TLS).await;
        refused_before_the_handler(&answer, "InvalidArgument", algorithm);
        assert!(answer.body.contains("not both"), "{}", answer.body);
    }
}

/// Negative — decoding a form's malformed flag must not reorder the shared gate's refusals.
/// Header controls measure the same raw family; mixed plaintext requests also retain the header
/// transport refusal. Legacy keeps its earlier unreadable-field refusal under either transport.
#[tokio::test]
async fn n_managed_flag_keeps_the_gateway_header_order_and_the_legacy_decode_order() {
    let mut gateway = Vec::new();
    let mut headers = Vec::new();
    let mut legacy = Vec::new();
    let mut legacy_expected = Vec::new();
    for (name, mut fields, transport) in [
        ("complete-plaintext", trio(KEY_A, MD5_A), TransportSecurity::Plaintext),
        ("partial-plaintext", vec![(SSEC_ALGORITHM, "AES256")], TransportSecurity::Plaintext),
        ("contradiction-tls", trio(KEY_A, MD5_A), TransportSecurity::Encrypted),
        ("algorithm-tls", vec![(SSE_ALGORITHM, "opaque")], TransportSecurity::Encrypted),
    ] {
        let setup = Setup {
            legacy_grammar: false,
            transport,
            ..OVER_TLS
        };
        fields.push((SSE_BUCKET_KEY_ENABLED, "yes"));
        let core = rustfs_gateway_core::sse::enforce_with(
            |name| {
                fields
                    .iter()
                    .find_map(|(field, value)| (*field == name).then_some(std::borrow::Cow::Borrowed(*value)))
            },
            transport,
            &rustfs_gateway_core::sse::SseConfig::default(),
        );
        println!("{name} core refusal: {:?}", core.err());
        let control = post_with_headers(&[], &fields, setup).await;
        let form = post(&fields, setup).await;
        headers.push((name, "form", refusal_tuple(&control)));
        gateway.push((name, "form", refusal_tuple(&form)));
        let old_form = post(
            &fields,
            Setup {
                legacy_grammar: true,
                ..setup
            },
        )
        .await;
        legacy.push((name, "form", refusal_tuple(&old_form)));
        legacy_expected.push((name, "form", unreadable_flag_tuple()));
        if transport == TransportSecurity::Plaintext {
            let form_flag = [(SSE_BUCKET_KEY_ENABLED, "yes")];
            let customer_headers = &fields[..fields.len() - 1];
            let mixed = post_with_headers(&form_flag, customer_headers, setup).await;
            headers.push((name, "mixed", refusal_tuple(&control)));
            gateway.push((name, "mixed", refusal_tuple(&mixed)));
            let old_mixed = post_with_headers(
                &form_flag,
                customer_headers,
                Setup {
                    legacy_grammar: true,
                    ..setup
                },
            )
            .await;
            legacy.push((name, "mixed", refusal_tuple(&old_mixed)));
            legacy_expected.push((name, "mixed", unreadable_flag_tuple()));
        }
    }
    println!("header controls: {headers:?}; gateway forms: {gateway:?}; legacy forms: {legacy:?}");
    assert_eq!(gateway, headers, "gateway form/header refusal order");
    assert_eq!(legacy, legacy_expected, "unchanged legacy boolean decode order");
}

fn refusal_tuple(answer: &Answer) -> (u16, Option<String>, Option<String>) {
    let text = |tag| {
        answer
            .body
            .split_once(&format!("<{tag}>"))
            .and_then(|(_, tail)| tail.split_once(&format!("</{tag}>")))
            .map(|(value, _)| value.replace("&quot;", "\""))
    };
    (answer.status.as_u16(), text("Code"), text("Message"))
}

fn unreadable_flag_tuple() -> (u16, Option<String>, Option<String>) {
    (
        400,
        Some("InvalidArgument".to_owned()),
        Some("invalid field value: x-amz-server-side-encryption-bucket-key-enabled: \"yes\"".to_owned()),
    )
}
