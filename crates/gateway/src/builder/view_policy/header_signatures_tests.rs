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

//! The unit suite of the legacy header-signature refusals: each rule alone, their order, and the
//! requests the switch leaves to the security floor and the authenticator.
//!
//! Responsible for: `super::HeaderRefusals::refusal` over hand-built request heads.
//! NOT responsible for: the served assembly (`compat/sut`'s `header_signature_tests.rs`).
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;

/// 2015-08-30T12:36:00Z, the instant the heads below are signed at.
const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";
const SIGNATURE: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
const EMPTY_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A request head: its headers, its raw query and its method.
type Head = (HeaderMap, String, Method);

/// A refusal as `(status, code, sentence)`, or none.
type Refusal = Option<(u16, String, String)>;

fn authorization(service: &str, day: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKID/{day}/us-east-1/{service}/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={SIGNATURE}"
    )
}

/// A head with `pairs` as its headers, `GET` with `query`.
fn head_with(pairs: &[(&str, &str)], query: &str, method: Method) -> Head {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    (headers, query.to_owned(), method)
}

/// A well-formed header-signed `GET`, with `change` applied to its headers.
fn signed(change: impl FnOnce(&mut Vec<(&'static str, String)>)) -> Head {
    let mut pairs = vec![
        ("host", "s3.example.com".to_owned()),
        ("x-amz-date", STAMP.to_owned()),
        ("x-amz-content-sha256", EMPTY_DIGEST.to_owned()),
        ("authorization", authorization("s3", "20150830")),
    ];
    change(&mut pairs);
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(name, value)| (*name, value.as_str())).collect();
    head_with(&borrowed, "", Method::GET)
}

fn set(pairs: &mut Vec<(&'static str, String)>, name: &'static str, value: &str) {
    pairs.retain(|(existing, _)| *existing != name);
    pairs.push((name, value.to_owned()));
}

fn remove(pairs: &mut Vec<(&'static str, String)>, name: &str) {
    pairs.retain(|(existing, _)| *existing != name);
}

/// The refusal legacy RustFS gives `head`, as `(status, code, sentence)`.
fn refusal_of(head: &Head, mode: HeaderRefusals) -> Refusal {
    let (headers, query, method) = head;
    let head = SignedHead {
        method,
        headers,
        query,
        now: RequestNow::from_unix_seconds(NOW),
        window: SkewWindow::DEFAULT,
    };
    mode.refusal(&head, ResponseKind::Other, false).map(|error| {
        (
            error.status().as_u16(),
            error.code().map(|code| code.as_str().to_owned()).unwrap_or_default(),
            error.message().unwrap_or_default().to_owned(),
        )
    })
}

fn legacy(head: &Head) -> Refusal {
    refusal_of(head, HeaderRefusals::LegacyRustfs)
}

fn answer(status: u16, code: &str, sentence: &str) -> Refusal {
    Some((status, code.to_owned(), sentence.to_owned()))
}

/// Positive — a well-formed header signature, each signing service, and an `sts` scope without a
/// payload declaration are left to the floor and the authenticator.
#[test]
fn a_request_legacy_rustfs_reads_is_left_to_the_pipeline() {
    assert_eq!(legacy(&signed(|_| {})), None);
    for service in ["s3", "sts", "s3tables"] {
        assert_eq!(
            legacy(&signed(|pairs| set(pairs, "authorization", &authorization(service, "20150830")))),
            None
        );
    }
    let sts_without_digest = signed(|pairs| {
        set(pairs, "authorization", &authorization("sts", "20150830"));
        remove(pairs, "x-amz-content-sha256");
    });
    assert_eq!(legacy(&sts_without_digest), None);
    for declared in [
        "UNSIGNED-PAYLOAD",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    ] {
        assert_eq!(legacy(&signed(|pairs| set(pairs, "x-amz-content-sha256", declared))), None, "{declared}");
    }
}

/// Negative — every rule alone gives legacy RustFS's answer.
#[test]
fn n_each_rule_alone_is_answered_as_legacy_rustfs_answers_it() {
    let cases: [(&str, Head, Refusal); 12] = [
        (
            "an unreadable value of another scheme",
            signed(|pairs| set(pairs, "authorization", "Bearer token")),
            answer(400, "InvalidRequest", "invalid header: authorization"),
        ),
        (
            "SigV2 without its colon",
            signed(|pairs| set(pairs, "authorization", "AWS AKID")),
            answer(400, "InvalidRequest", "invalid header: authorization"),
        ),
        (
            "an unknown service",
            signed(|pairs| set(pairs, "authorization", &authorization("foo", "20150830"))),
            answer(
                501,
                "NotImplemented",
                "unknown service 'foo' in credential scope; expected one of: s3, sts, s3tables",
            ),
        ),
        (
            "no x-amz-date",
            signed(|pairs| remove(pairs, "x-amz-date")),
            answer(400, "InvalidRequest", "missing header: x-amz-date"),
        ),
        (
            "a Date in place of x-amz-date",
            signed(|pairs| {
                remove(pairs, "x-amz-date");
                set(pairs, "date", "Sun, 30 Aug 2015 12:36:00 GMT");
            }),
            answer(400, "InvalidRequest", "missing header: x-amz-date"),
        ),
        (
            "an x-amz-date in another spelling",
            signed(|pairs| set(pairs, "x-amz-date", "Sun, 30 Aug 2015 12:36:00 GMT")),
            answer(400, "InvalidRequest", "invalid header: x-amz-date"),
        ),
        (
            "a scope date other than the x-amz-date day",
            signed(|pairs| set(pairs, "authorization", &authorization("s3", "20150829"))),
            answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date"),
        ),
        (
            "hour 24",
            signed(|pairs| set(pairs, "x-amz-date", "20150830T240000Z")),
            answer(400, "InvalidRequest", "invalid amz date"),
        ),
        (
            "second 60",
            signed(|pairs| set(pairs, "x-amz-date", "20150830T123660Z")),
            answer(400, "InvalidRequest", "invalid amz date"),
        ),
        (
            "a clock sixteen minutes behind",
            signed(|pairs| set(pairs, "x-amz-date", "20150830T122000Z")),
            answer(403, "RequestTimeTooSkewed", "request time is too far from server time"),
        ),
        (
            "an uppercase hex digest",
            signed(|pairs| set(pairs, "x-amz-content-sha256", &EMPTY_DIGEST.to_uppercase())),
            answer(403, "SignatureDoesNotMatch", "invalid header: x-amz-content-sha256"),
        ),
        (
            "no x-amz-content-sha256 on an s3 scope",
            signed(|pairs| remove(pairs, "x-amz-content-sha256")),
            answer(400, "InvalidRequest", "missing header: x-amz-content-sha256"),
        ),
    ];
    for (label, head, expected) in cases {
        assert_eq!(legacy(&head), expected, "{label}");
    }
    let tables_without_digest = signed(|pairs| {
        set(pairs, "authorization", &authorization("s3tables", "20150830"));
        remove(pairs, "x-amz-content-sha256");
    });
    assert_eq!(
        legacy(&tables_without_digest),
        answer(400, "InvalidRequest", "missing header: x-amz-content-sha256")
    );
}

/// Negative — two faults at once are answered in legacy RustFS's order: the service before the
/// timestamp, the timestamp before the scope date, the scope date before the clock, the clock before
/// the payload declaration.
#[test]
fn n_two_faults_are_answered_in_legacy_rustfs_order() {
    let service_and_date = signed(|pairs| {
        set(pairs, "authorization", &authorization("foo", "20150830"));
        remove(pairs, "x-amz-date");
    });
    assert_eq!(legacy(&service_and_date).map(|answer| answer.0), Some(501));
    let date_and_payload = signed(|pairs| {
        remove(pairs, "x-amz-date");
        set(pairs, "x-amz-content-sha256", "garbage");
    });
    assert_eq!(legacy(&date_and_payload), answer(400, "InvalidRequest", "missing header: x-amz-date"));
    let scope_and_clock = signed(|pairs| {
        set(pairs, "authorization", &authorization("s3", "20150829"));
        set(pairs, "x-amz-date", "20150830T000000Z");
    });
    assert_eq!(
        legacy(&scope_and_clock),
        answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date")
    );
    let clock_and_payload = signed(|pairs| {
        set(pairs, "x-amz-date", "20150830T122000Z");
        set(pairs, "x-amz-content-sha256", "garbage");
    });
    assert_eq!(
        legacy(&clock_and_payload),
        answer(403, "RequestTimeTooSkewed", "request time is too far from server time")
    );
}

/// Negative — what is not a header signature by legacy RustFS's reading, and what its own guard
/// answers, is left alone: a presigned query signature (SigV4 or SigV2), a browser form, another
/// algorithm, an unreadable SigV4 value, an uppercase signature, and no `Authorization` at all.
#[test]
fn n_what_is_not_a_readable_header_signature_is_left_alone() {
    let broken = signed(|pairs| remove(pairs, "x-amz-date"));
    let (headers, _, _) = &broken;
    let presigned = (headers.clone(), "X-Amz-Signature=abc".to_owned(), Method::GET);
    assert_eq!(legacy(&presigned), None);
    let sigv2_presigned = (headers.clone(), "Signature=abc".to_owned(), Method::GET);
    assert_eq!(legacy(&sigv2_presigned), None);
    let mut form_headers = headers.clone();
    form_headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("multipart/form-data; boundary=x"));
    assert_eq!(legacy(&(form_headers, String::new(), Method::POST)), None);
    for value in [
        authorization("s3", "20150830").replace("AWS4-HMAC-SHA256", "AWS4-HMAC-SHA512"),
        "AWS4-HMAC-SHA256 garbage".to_owned(),
        authorization("s3", "20150830").replace(SIGNATURE, &SIGNATURE.to_uppercase()),
        authorization("s3", "20150231"),
    ] {
        let head = signed(|pairs| {
            set(pairs, "authorization", &value);
            remove(pairs, "x-amz-date");
        });
        assert_eq!(legacy(&head), None, "{value}");
    }
    assert_eq!(legacy(&signed(|pairs| remove(pairs, "authorization"))), None);
}

/// Negative — a header is read as UTF-8, as legacy RustFS reads one: a non-ASCII `x-amz-date` or
/// `x-amz-content-sha256` is unreadable rather than missing, a region carrying a non-ASCII
/// character still leaves the scope date to be held to its day, and a value that is not UTF-8 is
/// read as absent. Observed against legacy RustFS (`e870a6d25b`) over raw sockets: `400
/// InvalidRequest` "invalid header: x-amz-date", `403 SignatureDoesNotMatch` "invalid header:
/// x-amz-content-sha256", `403 SignatureDoesNotMatch` "credential scope date does not match
/// x-amz-date", and "missing header: x-amz-date" and "missing header: x-amz-content-sha256".
#[test]
fn n_a_header_is_read_as_utf8_as_legacy_rustfs_reads_it() {
    let date = signed(|pairs| set(pairs, "x-amz-date", "2015083\u{e9}T123600Z"));
    assert_eq!(legacy(&date), answer(400, "InvalidRequest", "invalid header: x-amz-date"));
    let digest = signed(|pairs| set(pairs, "x-amz-content-sha256", "\u{e9}\u{e9}\u{e9}"));
    assert_eq!(
        legacy(&digest),
        answer(403, "SignatureDoesNotMatch", "invalid header: x-amz-content-sha256")
    );
    let region = authorization("s3", "20150829").replace("/us-east-1/", "/us-\u{e9}ast/");
    let dated_elsewhere = signed(|pairs| set(pairs, "authorization", &region));
    assert_eq!(
        legacy(&dated_elsewhere),
        answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date")
    );
    for (name, sentence) in [
        ("x-amz-date", "missing header: x-amz-date"),
        ("x-amz-content-sha256", "missing header: x-amz-content-sha256"),
    ] {
        let (mut headers, query, method) = signed(|_| {});
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_bytes(b"20150830T12\xff600Z").expect("obs-text is a header value"),
        );
        assert_eq!(legacy(&(headers, query, method)), answer(400, "InvalidRequest", sentence), "{name}");
    }
}

/// Negative — without the switch nothing is answered here.
#[test]
fn n_the_default_answers_nothing() {
    for head in [
        signed(|pairs| remove(pairs, "x-amz-date")),
        signed(|pairs| set(pairs, "authorization", "Bearer token")),
        signed(|pairs| remove(pairs, "x-amz-content-sha256")),
    ] {
        assert_eq!(refusal_of(&head, HeaderRefusals::Gateway), None);
    }
    assert_eq!(HeaderRefusals::default(), HeaderRefusals::Gateway);
}

/// Positive — the legacy grammar reads what legacy RustFS reads: tabs and no spaces around the
/// separators, an empty key or region, a region with a comma, and a trailing space.
#[test]
fn the_legacy_grammar_reads_every_spelling_legacy_rustfs_reads() {
    for value in [
        format!("AWS4-HMAC-SHA256\tCredential=AKID/20150830/us-east-1/s3/aws4_request,SignedHeaders=host,Signature={SIGNATURE}"),
        format!("AWS4-HMAC-SHA256 Credential=/20150830//s3/aws4_request, SignedHeaders=a;;b, Signature={SIGNATURE} "),
        format!("AWS4-HMAC-SHA256 Credential=AKID/20150830/us,east/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE}"),
        format!("AWS4-HMAC-SHA256 Credential=AKID/20160229/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE}"),
    ] {
        let read = read_authorization(&value).expect("readable");
        assert!(read.canonical_signature, "{value}");
    }
    for value in [
        format!("AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AKID/20150830/us-east-1/s3/aws4_request, Signature={SIGNATURE}"),
        format!("AWS4-HMAC-SHA256 Credential=AKID/20150230/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE}"),
        format!("AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1//aws4_request, SignedHeaders=host, Signature={SIGNATURE}"),
        format!("AWS4-HMAC-SHA256Credential=AKID/20150830/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE}"),
        format!(
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE} x"
        ),
    ] {
        assert!(read_authorization(&value).is_none(), "{value}");
    }
}

/// A header-signed SigV2 `GET` dated by `date` and `amz_date`, whichever are given.
fn sigv2(date: Option<&str>, amz_date: Option<&str>) -> Head {
    let mut pairs = vec![("host", "s3.example.com"), ("authorization", "AWS AKID:c2lnbmF0dXJl")];
    if let Some(date) = date {
        pairs.push(("date", date));
    }
    if let Some(amz_date) = amz_date {
        pairs.push(("x-amz-date", amz_date));
    }
    head_with(&pairs, "", Method::GET)
}

/// Positive — a SigV2 request dated as legacy RustFS reads a date is left to the pipeline: an
/// IMF-fixdate `Date` in `GMT` (its weekday not held to the date), a SigV4-spelled `x-amz-date`,
/// which also wins over any `Date`.
#[test]
fn a_sigv2_date_legacy_rustfs_reads_is_left_to_the_pipeline() {
    for head in [
        sigv2(Some("Sun, 30 Aug 2015 12:36:00 GMT"), None),
        sigv2(Some("Mon, 30 Aug 2015 12:36:00 GMT"), None),
        sigv2(None, Some(STAMP)),
        sigv2(Some("garbage"), Some(STAMP)),
    ] {
        assert_eq!(legacy(&head), None);
    }
}

/// Negative — a SigV2 request with no date, or a date legacy RustFS does not read, or one outside
/// the window, is answered as legacy RustFS answers it.
#[test]
fn n_a_sigv2_date_legacy_rustfs_refuses_is_answered_as_it_answers() {
    let cases = [
        (sigv2(None, None), answer(400, "InvalidRequest", "missing date")),
        (
            sigv2(None, Some("Sun, 30 Aug 2015 12:36:00 +0000")),
            answer(400, "InvalidRequest", "invalid x-amz-date"),
        ),
        (
            sigv2(Some("Sun, 30 Aug 2015 12:36:00 GMT"), Some("Sun, 30 Aug 2015 12:36:00 GMT")),
            answer(400, "InvalidRequest", "invalid x-amz-date"),
        ),
        (sigv2(None, Some("20150830T253600Z")), answer(400, "InvalidRequest", "invalid x-amz-date")),
        (
            sigv2(Some("Sun, 30 Aug 2015 12:36:00 +0000"), None),
            answer(400, "InvalidRequest", "invalid date"),
        ),
        (
            sigv2(Some("sun, 30 aug 2015 12:36:00 gmt"), None),
            answer(400, "InvalidRequest", "invalid date"),
        ),
        (sigv2(Some(STAMP), None), answer(400, "InvalidRequest", "invalid date")),
        (
            sigv2(Some("Sun, 31 Sep 2015 12:36:00 GMT"), None),
            answer(400, "InvalidRequest", "invalid date"),
        ),
        (
            sigv2(Some("Sun, 30 Aug 2015 12:20:00 GMT"), None),
            answer(403, "RequestTimeTooSkewed", "request time is too far from server time"),
        ),
        (
            sigv2(None, Some("20150830T125200Z")),
            answer(403, "RequestTimeTooSkewed", "request time is too far from server time"),
        ),
    ];
    for (head, expected) in cases {
        assert_eq!(legacy(&head), expected, "{:?}", head.0);
    }
    let presigned = (sigv2(None, None).0, "Signature=abc".to_owned(), Method::GET);
    assert_eq!(legacy(&presigned), None);
}
