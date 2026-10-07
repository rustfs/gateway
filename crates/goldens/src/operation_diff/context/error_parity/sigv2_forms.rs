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

//! SigV2 browser forms on the bucket path through both stacks (rustfs/gateway#1185): the same
//! `POST /photos` form, signed with a SigV2 policy signature, sent to the pinned legacy stack with
//! SigV2 enabled as RustFS enables it and to the gateway with the RustFS profile's form, selection,
//! date and SigV2 switches.
//!
//! Responsible for: the policy and field matrix — operators and their case, every condition kind
//! met and broken, the size range on each side of the file, expiry with a valid and a forged
//! signature, a missing or unreadable policy, missing credentials, fields the policy does and does
//! not check — and, for each, whether the upload reaches `PostObject` (the fixture's stand-in for
//! "stored") and, when it does not, the status and code of the refusal; for a field the policy does
//! not name, that the legacy stack refused it for that reason.
//! NOT responsible for: what a handler stores (the fixture backend reads no file, so the answer
//! after a reached handler is not compared), object-path forms (`form_method`), or SigV4 forms.
//! Upstream: `super::both`. Downstream: nothing.

use http::Method;
use serde_json::{Value, json};

use super::super::{ACCESS_KEY, ContextRequest, PATH_HOST, SECRET_KEY};
use super::{Length, Pair, Scenario, both};

const CONTENT_TYPE: &str = "multipart/form-data; boundary=form";
/// The uploaded file: ten bytes.
const FILE: &str = "file bytes";
const FORGED: &str = "not-the-secret";
const LATER: &str = "2099-01-01T00:00:00Z";

/// A SigV2 form: its fields in order, the file last.
struct Form {
    fields: Vec<(&'static str, String)>,
}

impl Form {
    /// `document` encoded as the policy and signed with `secret`, for the key `a.txt`.
    fn signed(document: &Value, secret: &str) -> Self {
        Self::over(base64(document.to_string().as_bytes()), secret)
    }

    /// `policy`, already encoded, signed with `secret`.
    fn over(policy: String, secret: &str) -> Self {
        let signature = rustfs_gateway_sig::SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
            .expect("a signer")
            .post_policy_signature(&policy);
        Self {
            fields: vec![
                ("key", "a.txt".into()),
                ("AWSAccessKeyId", ACCESS_KEY.into()),
                ("policy", policy),
                ("signature", signature),
            ],
        }
    }

    fn with(mut self, name: &'static str, value: &str) -> Self {
        self.fields.retain(|(field, _)| *field != name);
        self.fields.push((name, value.into()));
        self
    }

    fn without(mut self, name: &str) -> Self {
        self.fields.retain(|(field, _)| *field != name);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut body = String::new();
        for (name, value) in &self.fields {
            body.push_str(&format!("--form\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        body.push_str(&format!(
            "--form\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n{FILE}\r\n--form--\r\n"
        ));
        body.into_bytes()
    }
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let triple = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (index, byte)| acc | (u32::from(*byte) << (16 - 8 * index)));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(DIGITS[((triple >> (18 - 6 * index)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A policy expiring at `expiration` with `conditions` after the bucket's.
fn policy<const N: usize>(expiration: &str, conditions: [Value; N]) -> Value {
    let mut all = vec![json!({"bucket": "photos"})];
    all.extend(conditions);
    json!({"expiration": expiration, "conditions": all})
}

/// The answer to `form` on the bucket path, from both stacks under the RustFS profile's switches,
/// its length declared as a browser and every SDK declares it.
fn sent(form: &Form) -> Pair {
    let body = form.bytes();
    let length = u64::try_from(body.len()).expect("a small form");
    let request =
        ContextRequest::new(Method::POST, PATH_HOST, "/photos", "", &body).header("content-type", CONTENT_TYPE.as_bytes());
    both(
        &Scenario::new(request)
            .selecting_as_legacy_rustfs()
            .reading_dates_as_legacy_rustfs()
            .with_sigv2()
            .length(Length::Declared(length)),
    )
    .expect("both stacks answer")
}

/// What one stack did with a form: reached `PostObject`, or refused it with this status and code.
/// Messages are not compared: the gateway's are fixed sentences that never echo the request, where
/// the legacy stack's quote the condition and the value.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Reached,
    Refused { status: u16, code: Option<String> },
}

fn outcomes(pair: &Pair) -> (Outcome, Outcome) {
    let of = |reply: &super::Reply| {
        if reply.reached {
            Outcome::Reached
        } else {
            Outcome::Refused {
                status: reply.status,
                code: reply.code().map(str::to_owned),
            }
        }
    };
    (of(&pair.gateway), of(&pair.oracle))
}

/// Every case in `cases` answered alike on both stacks; the differences, if any, all at once.
fn assert_alike(cases: Vec<(&'static str, Form)>) -> Vec<(&'static str, Outcome)> {
    let mut differences = Vec::new();
    let mut answered = Vec::new();
    for (kind, form) in cases {
        let (gateway, oracle) = outcomes(&sent(&form));
        if gateway != oracle {
            differences.push((kind, gateway, oracle));
            continue;
        }
        answered.push((kind, oracle));
    }
    assert!(differences.is_empty(), "(case, gateway, legacy): {differences:#?}");
    answered
}

/// Positive — forms whose policy every field and the file satisfy reach `PostObject` on both
/// stacks: each operator in any ASCII case, a size range around the file, and fields the policy
/// checks.
#[test]
fn a_sigv2_form_its_policy_admits_reaches_the_upload_on_both_stacks() {
    let starts = json!(["starts-with", "$key", ""]);
    let answered = assert_alike(vec![
        ("starts-with", Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY)),
        ("eq", Form::signed(&policy(LATER, [json!(["eq", "$key", "a.txt"])]), SECRET_KEY)),
        ("EQ", Form::signed(&policy(LATER, [json!(["EQ", "$key", "a.txt"])]), SECRET_KEY)),
        (
            "Starts-With",
            Form::signed(&policy(LATER, [json!(["Starts-With", "$key", "a"])]), SECRET_KEY),
        ),
        ("object condition", Form::signed(&policy(LATER, [json!({"key": "a.txt"})]), SECRET_KEY)),
        (
            "size range around the file",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 1, 100])]), SECRET_KEY),
        ),
        (
            "size range exactly the file",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 10, 10])]), SECRET_KEY),
        ),
        (
            "checked metadata",
            Form::signed(&policy(LATER, [starts.clone(), json!(["eq", "$x-amz-meta-color", "red"])]), SECRET_KEY)
                .with("x-amz-meta-color", "red"),
        ),
        (
            "checked content type",
            Form::signed(
                &policy(LATER, [starts.clone(), json!(["starts-with", "$Content-Type", "text/"])]),
                SECRET_KEY,
            )
            .with("Content-Type", "text/plain"),
        ),
        (
            "unlisted submit",
            Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).with("submit", "Upload"),
        ),
        (
            "unlisted ignored field",
            Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).with("x-ignore-note", "n"),
        ),
        (
            "unlisted server-side encryption",
            Form::signed(&policy(LATER, [starts]), SECRET_KEY).with("x-amz-server-side-encryption", "AES256"),
        ),
    ]);
    for (kind, outcome) in answered {
        assert_eq!(outcome, Outcome::Reached, "{kind}");
    }
}

/// Negative — forms whose policy, credentials or fields legacy RustFS refuses are refused on both
/// stacks with the same status and code, and neither reaches `PostObject`. Coverage is checked
/// last on both: a bucket or size refusal wins over an unnamed field.
#[test]
fn n_a_sigv2_form_legacy_rustfs_refuses_is_refused_alike_and_reaches_nothing() {
    let starts = json!(["starts-with", "$key", ""]);
    let answered = assert_alike(vec![
        (
            "key eq mismatch",
            Form::signed(&policy(LATER, [json!(["eq", "$key", "b.txt"])]), SECRET_KEY),
        ),
        (
            "key prefix mismatch",
            Form::signed(&policy(LATER, [json!(["starts-with", "$key", "b"])]), SECRET_KEY),
        ),
        (
            "bucket mismatch",
            Form::signed(
                &json!({"expiration": LATER, "conditions": [{"bucket": "other"}, starts.clone()]}),
                SECRET_KEY,
            ),
        ),
        (
            "file above the range",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 1, 5])]), SECRET_KEY),
        ),
        (
            "file below the range",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 100, 200])]), SECRET_KEY),
        ),
        (
            "bucket mismatch and an unnamed field",
            Form::signed(
                &json!({"expiration": LATER, "conditions": [{"bucket": "other"}, starts.clone()]}),
                SECRET_KEY,
            )
            .with("x-amz-meta-color", "red"),
        ),
        (
            "file above the range and an unnamed field",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 1, 5])]), SECRET_KEY)
                .with("x-amz-meta-color", "red"),
        ),
        (
            "file below the range and an unnamed field",
            Form::signed(&policy(LATER, [starts.clone(), json!(["content-length-range", 100, 200])]), SECRET_KEY)
                .with("x-amz-meta-color", "red"),
        ),
        ("expired", Form::signed(&policy("2000-01-01T00:00:00Z", [starts.clone()]), SECRET_KEY)),
        (
            "expired and forged",
            Form::signed(&policy("2000-01-01T00:00:00Z", [starts.clone()]), FORGED),
        ),
        ("forged", Form::signed(&policy(LATER, [starts.clone()]), FORGED)),
        (
            "unchecked metadata",
            Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).with("x-amz-meta-color", "red"),
        ),
        (
            "metadata eq mismatch",
            Form::signed(&policy(LATER, [starts.clone(), json!(["eq", "$x-amz-meta-color", "blue"])]), SECRET_KEY)
                .with("x-amz-meta-color", "red"),
        ),
        (
            "no expiration",
            Form::signed(&json!({"conditions": [{"bucket": "photos"}, starts.clone()]}), SECRET_KEY),
        ),
        ("no conditions", Form::signed(&json!({"expiration": LATER}), SECRET_KEY)),
        ("policy not JSON", Form::over(base64(b"not json"), SECRET_KEY)),
        ("policy not base64", Form::over("not base64!".to_owned(), SECRET_KEY)),
        (
            "unknown operator",
            Form::signed(&policy(LATER, [json!(["matches", "$key", "a.txt"])]), SECRET_KEY),
        ),
        (
            "no access key",
            Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).without("AWSAccessKeyId"),
        ),
        ("no policy", Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).without("policy")),
        (
            "unlisted credential field",
            Form::signed(&policy(LATER, [starts]), SECRET_KEY).with("x-amz-date", "20260102T030405Z"),
        ),
    ]);
    for (kind, outcome) in answered {
        assert!(matches!(outcome, Outcome::Refused { .. }), "{kind}: {outcome:?}");
    }
}

/// Negative — a known difference, failing closed on both stacks: a form carrying an
/// `x-amz-security-token` no condition names is refused `403 AccessDenied` by legacy RustFS for the
/// unlisted field, and `403 InvalidAccessKeyId` by the gateway, which reads the token as a session
/// credential before the policy and finds none for this key. Neither reaches `PostObject`.
#[test]
fn n_an_unlisted_session_token_is_refused_on_both_stacks_with_another_code() {
    let form =
        Form::signed(&policy(LATER, [json!(["starts-with", "$key", ""])]), SECRET_KEY).with("x-amz-security-token", "token");
    let (gateway, oracle) = outcomes(&sent(&form));
    let refused = |code: &str| Outcome::Refused {
        status: 403,
        code: Some(code.to_owned()),
    };
    assert_eq!((gateway, oracle), (refused("InvalidAccessKeyId"), refused("AccessDenied")));
}

/// Negative — a field the policy does not name is refused by both stacks for that reason: the
/// legacy stack says so, and the gateway answers its `403 AccessDenied`.
#[test]
fn n_an_unnamed_field_is_refused_for_coverage_on_both_stacks() {
    let starts = json!(["starts-with", "$key", ""]);
    for (name, value) in [("x-amz-meta-color", "red"), ("x-amz-date", "20260102T030405Z")] {
        let pair = sent(&Form::signed(&policy(LATER, [starts.clone()]), SECRET_KEY).with(name, value));
        assert!(
            pair.oracle
                .message()
                .is_some_and(|message| message.contains("not specified in the policy")),
            "{name}: {:?}",
            pair.oracle.message()
        );
        assert_eq!(
            (pair.gateway.status, pair.gateway.code(), pair.gateway.reached),
            (403, Some("AccessDenied"), false),
            "{name}"
        );
    }
}

/// Negative — a second known difference, failing closed: a form whose policy names its
/// `x-amz-security-token` is stored by legacy RustFS, which reads no session token from a form and
/// authenticates the static key, and refused `403 InvalidAccessKeyId` by the gateway, which reads
/// the token as a session credential and finds none for this key.
#[test]
fn n_a_named_session_token_with_a_static_key_is_refused_where_legacy_rustfs_stores() {
    let form = Form::signed(
        &policy(LATER, [json!(["starts-with", "$key", ""]), json!({"x-amz-security-token": "token"})]),
        SECRET_KEY,
    )
    .with("x-amz-security-token", "token");
    let (gateway, oracle) = outcomes(&sent(&form));
    assert_eq!(
        (gateway, oracle),
        (
            Outcome::Refused {
                status: 403,
                code: Some("InvalidAccessKeyId".to_owned())
            },
            Outcome::Reached
        )
    );
}
