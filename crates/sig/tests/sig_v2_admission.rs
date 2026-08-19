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

//! P2-06 wiring evidence at the floor: what `SecurityFloor::admit` does with a SigV2 request.
//!
//! Responsible for: the admission decisions no served request can exercise — the POST-form shape
//! the pipeline never assembles, the duplicate-parameter rule, and the two structural claims the
//! wiring rests on: **a SigV2 request never becomes a `SealedAws`**, and **a SigV2 request never
//! becomes an `Admission::Anonymous`**.
//! NOT responsible for: the string-to-sign (`sig_v2.rs`) or the verdict an assembled service
//! produces (`crates/gateway/tests/sigv2_runtime.rs`).
//! Upstream: `rustfs_gateway_sig::SecurityFloor`. Downstream: `tests/integration.rs`, the only
//! Cargo target that compiles this file.
//!
//! # The claim these cases exist to keep
//!
//! Before P2-06's wiring, `admit` answered every SigV2 request `NotImplemented(SigV2)`. That one
//! line was the whole reason a SigV2 request could not reach the SigV4 verifier. It is gone, and
//! what replaces it has to be checked structurally rather than by reading the code: every SigV2
//! request leaves `admit` as an error or as an `Admission::SealedSigV2`, and there is no path from
//! `SealedSigV2` to `SealedAws`.
//!
//! Negative cases outnumber positive ones; there are no positive cases in this file.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};
use rustfs_gateway_sig::sig_v2::SigV2Policy;
use rustfs_gateway_sig::{Admission, AuthError, OperationFloor, RawQuery, RequestNow, SecurityFloor, SigService, WireView};

/// `Tue, 27 Mar 2007 19:36:42 GMT`, the instant AWS's own SigV2 documentation signs at.
const SIGNED_AT: &str = "Tue, 27 Mar 2007 19:36:42 GMT";
/// The same instant in seconds since the epoch, so the skew window is satisfied by construction.
const SIGNED_AT_UNIX: i64 = 1_175_024_202;
/// Twenty zero bytes in standard base64. Syntactically perfect and cryptographically worthless,
/// which is exactly right here: the floor admits, it does not verify.
const WELL_FORMED_SIGNATURE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn now() -> RequestNow {
    RequestNow::from_unix_seconds(SIGNED_AT_UNIX)
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
        map.append(name, HeaderValue::from_str(value).expect("test header value"));
    }
    map
}

fn signed_headers() -> HeaderMap {
    headers(&[
        ("date", SIGNED_AT),
        ("authorization", &format!("AWS AKIDEXAMPLE:{WELL_FORMED_SIGNATURE}")),
    ])
}

/// An operation that permits every shape this file tries, so a refusal is never the allow-list's.
fn operation() -> OperationFloor {
    OperationFloor::builtin_presigned("PutObject", SigService::S3)
        .allow_post_policy()
        .allow_anonymous_after_listing_in_the_posture_report()
}

/// The query one correctly shaped SigV2 presigned URL carries.
fn presigned_query(expires_at: i64) -> String {
    format!("AWSAccessKeyId=AKIDEXAMPLE&Expires={expires_at}&Signature=AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D")
}

// ---------------------------------------------------------------------------------------------
// Negative
// ---------------------------------------------------------------------------------------------

/// Negative — c-sig-0561: an admitted SigV2 request is **never** an `Admission::Sealed`.
///
/// This is the anti-downgrade assertion in its structural form. `SealedAws` is the input type of
/// the built-in SigV4 verifier; if a SigV2 request could be admitted as one, the SigV4 path would
/// receive an `Authorization` header it cannot parse and the outcome would depend on which
/// rejection fired first. The variant it does produce carries a `SealedSigV2`, which has no
/// conversion to `SealedAws` anywhere in the crate.
#[test]
fn c_sig_0561_a_sigv2_request_is_never_sealed_for_the_sigv4_verifier() {
    let map = signed_headers();
    let view = WireView::new(&map, RawQuery::new(""));
    let admitted = SecurityFloor::new()
        .admit(view, &operation(), now())
        .expect("a well-formed SigV2 request is admitted");
    let sealed_for_sigv2 = matches!(admitted, Admission::SealedSigV2(_));
    assert!(sealed_for_sigv2, "SigV2 must not reach the SigV4 verifier's input type");
}

/// Negative — c-sig-0562: a SigV2 credential this crate cannot parse is a rejection, never an
/// anonymous admission — on an operation that *does* accept anonymous requests, so the two
/// outcomes are genuinely distinguishable here.
#[test]
fn c_sig_0562_an_unparsable_sigv2_credential_is_never_admitted_anonymously() {
    let map = headers(&[("date", SIGNED_AT), ("authorization", "AWS AKIDEXAMPLE")]);
    let view = WireView::new(&map, RawQuery::new(""));
    let refusal = SecurityFloor::new()
        .admit(view, &operation(), now())
        .expect_err("an unparsable credential is refused");
    assert_eq!(refusal, AuthError::AuthorizationHeaderMalformed);
}

/// Negative — c-sig-0563: the POST-form SigV2 shape is refused rather than half-verified.
///
/// `AWSAccessKeyId` and `signature` form fields are SigV2's browser-POST spelling. Its field-level
/// enforcement is P2-05's, and a signature checked without those rules is worse than no signature
/// at all, so the floor answers `NotImplemented` and stops.
#[test]
fn c_sig_0563_the_sigv2_post_form_shape_is_refused() {
    let map = HeaderMap::new();
    let fields = [
        ("AWSAccessKeyId", "AKIDEXAMPLE"),
        ("signature", WELL_FORMED_SIGNATURE),
        ("policy", "e30="),
    ];
    let view = WireView::new(&map, RawQuery::new("")).with_form_fields(&fields);
    let refusal = SecurityFloor::new()
        .admit(view, &operation(), now())
        .expect_err("the POST-form shape is refused");
    assert_eq!(refusal, AuthError::NotImplemented(rustfs_gateway_sig::Unimplemented::SigV2));
}

/// Negative — c-sig-0564: a repeated `Expires` is refused by **H6**, before any other rule runs.
///
/// `Expires` was missing from the signature-bearing parameter list until the SigV2 verifier was
/// wired, because until then nothing read it. A server reading the first occurrence and a proxy
/// reading the last disagree about when the URL dies.
///
/// The policy is `Disabled` on purpose, and that is the whole case. Every other refusal this
/// request could earn is `AccessDenied`: the scheme allow-list refuses presigned SigV2 under this
/// policy, and so does the SigV2 branch. Only H6 answers
/// `AuthorizationQueryParametersError` — and H6 answers it only if `Expires` is in
/// `SIGNED_QUERY_PARAMS`. Asserted the obvious way instead, under a policy that admits presigned
/// SigV2, this case passes with `Expires` removed from that list, because the strict query reader
/// refuses a duplicate on its own and produces the same error code. That version was written
/// first and survived its mutation; this one does not.
#[test]
fn c_sig_0564_a_repeated_sigv2_expires_is_refused_before_every_other_rule() {
    let map = HeaderMap::new();
    let query = format!("{}&Expires={}", presigned_query(SIGNED_AT_UNIX + 900), SIGNED_AT_UNIX + 604_800);
    let view = WireView::new(&map, RawQuery::new(&query));
    let refusal = SecurityFloor::new()
        .with_sigv2_policy(SigV2Policy::Disabled)
        .admit(view, &operation(), now())
        .expect_err("a repeated Expires is refused");
    assert_eq!(refusal, AuthError::AuthorizationQueryParametersError);

    // The control: the same request with one `Expires` reaches the policy and is refused by it.
    let single = presigned_query(SIGNED_AT_UNIX + 900);
    let view = WireView::new(&map, RawQuery::new(&single));
    let refusal = SecurityFloor::new()
        .with_sigv2_policy(SigV2Policy::Disabled)
        .admit(view, &operation(), now())
        .expect_err("presigned SigV2 is refused under the disabled policy");
    assert_eq!(refusal, AuthError::AccessDenied);
}

/// Negative — c-sig-0565: `SigV2Policy::Disabled` refuses a request the default admits.
///
/// Both directions in one case, because a switch that always refuses satisfies every negative
/// assertion written against it.
#[test]
fn c_sig_0565_the_disabled_policy_refuses_what_the_default_admits() {
    let map = signed_headers();
    let disabled = SecurityFloor::new().with_sigv2_policy(SigV2Policy::Disabled);
    let refusal = disabled
        .admit(WireView::new(&map, RawQuery::new("")), &operation(), now())
        .expect_err("Disabled refuses header authentication");
    assert_eq!(refusal, AuthError::AccessDenied);

    let admitted = SecurityFloor::new()
        .admit(WireView::new(&map, RawQuery::new("")), &operation(), now())
        .expect("the default admits header authentication");
    assert!(matches!(admitted, Admission::SealedSigV2(_)));
}

/// Negative — c-sig-0566: a SigV2 presigned URL missing its `Signature` parameter is refused.
///
/// `AWSAccessKeyId` alone is still an AWS credential marker, so the request cannot fall through to
/// the anonymous branch; it has to be refused explicitly.
#[test]
fn c_sig_0566_a_presigned_url_without_a_signature_is_refused() {
    let map = HeaderMap::new();
    let query = format!("AWSAccessKeyId=AKIDEXAMPLE&Expires={}", SIGNED_AT_UNIX + 900);
    let view = WireView::new(&map, RawQuery::new(&query));
    let refusal = SecurityFloor::new()
        .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
        .admit(view, &operation(), now())
        .expect_err("a presigned URL without a signature is refused");
    assert_eq!(refusal, AuthError::AuthorizationQueryParametersError);
}

/// Negative — c-sig-0567: an `Expires` more than seven days ahead is refused through `admit`, not
/// only by the parser it delegates to.
#[test]
fn c_sig_0567_a_presigned_expires_beyond_seven_days_is_refused() {
    let map = HeaderMap::new();
    let query = presigned_query(SIGNED_AT_UNIX + 604_801);
    let view = WireView::new(&map, RawQuery::new(&query));
    let refusal = SecurityFloor::new()
        .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
        .admit(view, &operation(), now())
        .expect_err("an Expires beyond the ceiling is refused");
    assert_eq!(refusal, AuthError::AuthorizationQueryParametersError);
}

/// Negative — c-sig-0568: a SigV2 request declaring `aws-chunked` framing is refused at the floor.
///
/// SigV2 has no streaming form. The pipeline decodes framing only for a payload mode it was given
/// and the SigV2 path gives it none, so an ignored declaration would deliver chunk headers to the
/// operation as object bytes.
#[test]
fn c_sig_0568_a_framed_payload_declaration_is_refused() {
    let map = headers(&[
        ("date", SIGNED_AT),
        ("authorization", &format!("AWS AKIDEXAMPLE:{WELL_FORMED_SIGNATURE}")),
        ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
    ]);
    let view = WireView::new(&map, RawQuery::new(""));
    let refusal = SecurityFloor::new()
        .admit(view, &operation(), now())
        .expect_err("a framed SigV2 payload is refused");
    assert_eq!(refusal, AuthError::NotImplemented(rustfs_gateway_sig::Unimplemented::StreamingSigV2));
}

/// Negative — c-sig-0569: a `Date` outside the skew window is refused, and the same request inside
/// it is admitted. H1 reaches SigV2 through the one `enforce_clock_skew`, not a copy of it.
#[test]
fn c_sig_0569_the_skew_window_reaches_sigv2_in_both_directions() {
    let map = signed_headers();
    let floor = SecurityFloor::new();
    let skewed = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 16 * 60);
    let refusal = floor
        .admit(WireView::new(&map, RawQuery::new("")), &operation(), skewed)
        .expect_err("a stale Date is refused");
    assert_eq!(refusal, AuthError::RequestTimeTooSkewed);

    let inside = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 14 * 60);
    let admitted = floor
        .admit(WireView::new(&map, RawQuery::new("")), &operation(), inside)
        .expect("a Date inside the window is admitted");
    assert!(matches!(admitted, Admission::SealedSigV2(_)));
}
