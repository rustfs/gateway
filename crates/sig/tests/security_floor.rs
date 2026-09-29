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

//! The security-floor time and scope cases (`c-sig-0301` .. `c-sig-0347`).
//!
//! Responsible for: the positive admissions, the clock-skew window on all three signing paths
//! (H1) — both bounds on the header and POST-policy paths, the future bound on the presigned path,
//! whose past bound is its lifetime (`c-sig-0309`, `c-sig-0310`, `c-sig-0336` .. `c-sig-0339`) —
//! the presigned expiry rules (H2), and the credential-scope cross-check (H5).
//! NOT responsible for: the presented-credential rule, the duplicate-parameter rule, the
//! privileged surface and the sealed boundary — those are `tests/security_floor_schemes.rs`; nor
//! the `compile_fail` cases, which are rustdoc examples on `clock`, `scope`, `derive`, `verdict`
//! and `verifier` and run as doctests.
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use core::time::Duration;

use http::header::HeaderMap;
use rustfs_gateway_sig::{
    Admission, AuthError, CredentialScope, EmptyRegion, ExpectedScope, MAX_PRESIGNED_EXPIRY_SECONDS, OperationFloor, RawQuery,
    RegionSet, RequestClock, RequestNow, ScopeRegion, ScopeRejection, SecurityFloor, SigService, SkewWindow, SystemClock,
    WireView, enforce_scope,
};

use crate::security_floor_fixtures::*;

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — c-sig-0301: a header-signed request inside the window is admitted, and the clock
/// receipt it carries names the timestamp that was checked.
#[test]
fn c_sig_0301_a_header_signature_inside_the_window_is_admitted() {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let sealed = match SecurityFloor::default().admit(view, &s3_object_op(), now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    assert_eq!(sealed.clock().signed_at().as_str(), SIGNED_AT);
    assert!(sealed.expiry().is_none(), "a header signature has no expiry");
}

/// Positive — c-sig-0302: a presigned URL stamped ten minutes in the future is accepted, because a
/// client clock that runs slightly fast is the common case (s3s#216).
#[test]
fn c_sig_0302_a_presigned_url_ten_minutes_in_the_future_is_accepted() {
    let query = presigned_query(SIGNED_AT, "3600");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    let earlier = RequestNow::from_unix_seconds(SIGNED_AT_UNIX - 600);
    assert!(matches!(
        SecurityFloor::default().admit(view, &s3_object_op(), earlier),
        Ok(Admission::Sealed(_))
    ));
}

/// Positive — c-sig-0303: `X-Amz-Expires=604800` is the documented ceiling and is accepted.
#[test]
fn c_sig_0303_the_seven_day_ceiling_is_accepted() {
    let query = presigned_query(SIGNED_AT, "604800");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    let sealed = match SecurityFloor::default().admit(view, &s3_object_op(), now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let expiry = sealed.expiry().expect("a presigned request has an expiry");
    assert_eq!(expiry.expires_in_seconds(), MAX_PRESIGNED_EXPIRY_SECONDS);
    assert_eq!(expiry.expires_at_unix_seconds(), SIGNED_AT_UNIX + 604_800);
}

/// Positive — c-sig-0304: the lower bound, `X-Amz-Expires=1`, used within its one second.
#[test]
fn c_sig_0304_the_one_second_lower_bound_is_accepted() {
    let query = presigned_query(SIGNED_AT, "1");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert!(matches!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()),
        Ok(Admission::Sealed(_))
    ));
}

/// Positive — c-sig-0305: a scope whose date, region and service all agree with the server's own
/// view produces the `VerifiedScope` that `signing_key` requires.
#[test]
fn c_sig_0305_an_agreeing_scope_produces_a_verified_scope() {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let sealed = match SecurityFloor::default().admit(view, &s3_object_op(), now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let presented = CredentialScope::parse(CRED).expect("a well-formed scope");
    let regions = regions();
    let expected = ExpectedScope::new(SigService::S3, &regions);
    let verified = enforce_scope(&presented, sealed.clock(), &expected).expect("the scope agrees");
    assert_eq!(verified.date().as_str(), "20150830");
    assert_eq!(verified.region(), "us-east-1");
    assert_eq!(verified.service(), "s3");
}

/// Positive — c-sig-0306: an `sts`-scoped signature is accepted by an STS operation (s3s#418).
#[test]
fn c_sig_0306_an_sts_scope_is_accepted_by_an_sts_operation() {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let operation = OperationFloor::builtin("AssumeRole", SigService::Sts);
    let sealed = match SecurityFloor::default().admit(view, &operation, now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let presented = CredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request").expect("well formed");
    let regions = regions();
    let expected = ExpectedScope::new(SigService::Sts, &regions);
    assert!(enforce_scope(&presented, sealed.clock(), &expected).is_ok());
}

/// Positive — c-sig-0307: a request that presented nothing, against an operation that was
/// explicitly listed as anonymously reachable, is admitted as anonymous.
#[test]
fn c_sig_0307_a_request_with_no_credentials_is_anonymous() {
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("list-type=2"));
    let operation = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    assert!(operation.allows_anonymous(), "the posture report reads this predicate");
    assert!(matches!(
        SecurityFloor::default().admit(view, &operation, now()),
        Ok(Admission::Anonymous(_))
    ));
}

// ---------------------------------------------------------------------------
// Negative — H1 clock skew, on all three paths
// ---------------------------------------------------------------------------

/// Negative — c-sig-0320: a header-signed request more than fifteen minutes old is refused. This
/// is the s3s#616 regression: the window must not apply to presigned requests only.
#[test]
fn c_sig_0320_a_stale_header_signature_is_refused() {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let late = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 16 * 60);
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), late).err(),
        Some(AuthError::RequestTimeTooSkewed)
    );
}

/// Negative — c-sig-0321: and one more than fifteen minutes in the future is refused too.
#[test]
fn c_sig_0321_a_header_signature_too_far_ahead_is_refused() {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let early = RequestNow::from_unix_seconds(SIGNED_AT_UNIX - 16 * 60);
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), early).err(),
        Some(AuthError::RequestTimeTooSkewed)
    );
}

/// Negative — c-sig-0322: the POST-policy path is held to the same window as the other two.
#[test]
fn c_sig_0322_the_post_policy_path_is_held_to_the_same_window() {
    let fields = post_form(SIGNED_AT);
    let borrowed = form_view(&fields);
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&borrowed);
    let late = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 16 * 60);
    let operation = s3_object_op().allow_post_policy();
    assert_eq!(
        SecurityFloor::default().admit(view, &operation, late).err(),
        Some(AuthError::RequestTimeTooSkewed)
    );
    // ... and inside the window the same request is admitted, so the case is not vacuous.
    assert!(matches!(
        SecurityFloor::default().admit(view, &operation, now()),
        Ok(Admission::Sealed(_))
    ));
}

/// Negative — c-sig-0333: every check in one admission reads one `RequestNow`, so a clock that
/// jumps between two reads cannot make the skew check and the expiry check disagree.
#[test]
fn c_sig_0333_one_admission_reads_one_clock_snapshot() {
    /// A clock that jumps an hour on every read. If the floor sampled the time more than once,
    /// the second sample would land outside the window and the two decisions would disagree.
    struct JumpingClock {
        reads: core::cell::Cell<i64>,
    }
    impl RequestClock for JumpingClock {
        fn capture(&self) -> RequestNow {
            let read = self.reads.get();
            self.reads.set(read + 1);
            RequestNow::from_unix_seconds(SIGNED_AT_UNIX + read * 3600)
        }
    }
    let clock = JumpingClock {
        reads: core::cell::Cell::new(0),
    };
    let snapshot = clock.capture();
    assert_ne!(snapshot, clock.capture(), "the fixture clock really does jump");

    let query = presigned_query(SIGNED_AT, "3600");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    let floor = SecurityFloor::default();
    // The snapshot is a value the caller passes in, so the second admission is the first one
    // repeated rather than a second sample of a moving clock.
    assert!(matches!(floor.admit(view, &s3_object_op(), snapshot), Ok(Admission::Sealed(_))));
    assert!(matches!(floor.admit(view, &s3_object_op(), snapshot), Ok(Admission::Sealed(_))));
}

/// Negative — the configured window cannot be widened past the fifteen minutes AWS documents.
#[test]
fn c_sig_0334_the_skew_window_cannot_be_widened_past_the_ceiling() {
    let window = SkewWindow::new(Duration::from_secs(86_400), Duration::from_secs(86_400));
    assert_eq!(window.past(), SkewWindow::MAX);
    assert_eq!(window.future(), SkewWindow::MAX);
    // Narrowing is allowed; widening is not.
    let narrow = SkewWindow::new(Duration::from_secs(60), Duration::from_secs(60));
    assert_eq!(narrow.past(), Duration::from_secs(60));
}

// ---------------------------------------------------------------------------
// H1 and H2 together — a presigned URL's past bound is its lifetime (rustfs/gateway#723)
// ---------------------------------------------------------------------------

const HOUR: i64 = 3_600;

fn presigned_admission(expires: &str, now: RequestNow, floor: &SecurityFloor) -> Result<(), AuthError> {
    let query = presigned_query(SIGNED_AT, expires);
    let headers = HeaderMap::new();
    match floor.admit(WireView::new(&headers, RawQuery::new(&query)), &s3_object_op(), now)? {
        Admission::Sealed(sealed) => {
            // The receipt names the instants that were judged, whatever the outcome was.
            assert_eq!(sealed.clock().signed_at().as_str(), SIGNED_AT);
            assert_eq!(sealed.clock().now(), now);
            let expiry = sealed.expiry().expect("a presigned request has an expiry");
            let lifetime = i64::try_from(expiry.expires_in_seconds()).expect("inside the seven-day ceiling");
            assert_eq!(expiry.expires_at_unix_seconds(), SIGNED_AT_UNIX + lifetime);
            Ok(())
        }
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    }
}

fn at(offset: i64) -> RequestNow {
    RequestNow::from_unix_seconds(SIGNED_AT_UNIX + offset)
}

/// Positive — c-sig-0309: a presigned URL used two hours after it was signed, inside its 24-hour
/// lifetime, is admitted. Its past bound is `X-Amz-Expires`, not the skew window: the lifetime
/// starts at `X-Amz-Date`, and S3, MinIO and the s3s revision RustFS runs all accept this request.
/// It is mint minio-js's `presignedGetObject … requestDate:StartOfDay` step.
#[test]
fn c_sig_0309_an_unexpired_presigned_url_older_than_the_skew_window_is_admitted() {
    assert_eq!(presigned_admission("86400", at(2 * HOUR), &SecurityFloor::default()), Ok(()));
    // Sixteen minutes old is the smallest age the window alone would have refused.
    assert_eq!(presigned_admission("3600", at(16 * 60), &SecurityFloor::default()), Ok(()));
}

/// Positive — c-sig-0310: a seven-day URL is admitted on its last second, and a deployment that
/// narrowed the skew window has not shortened a presigned lifetime: the window bounds clock
/// disagreement, and a URL's age is not a clock disagreement.
#[test]
fn c_sig_0310_the_presigned_lifetime_runs_to_its_last_second() {
    let ceiling = MAX_PRESIGNED_EXPIRY_SECONDS.to_string();
    let last_second = at(i64::try_from(MAX_PRESIGNED_EXPIRY_SECONDS).expect("fits"));
    assert_eq!(presigned_admission(&ceiling, last_second, &SecurityFloor::default()), Ok(()));
    let narrowed = SecurityFloor::default().with_skew_window(SkewWindow::new(Duration::from_secs(60), Duration::from_secs(60)));
    assert_eq!(presigned_admission("3600", at(HOUR), &narrowed), Ok(()));
}

/// Negative — c-sig-0336: a presigned URL past its lifetime is refused as expired, from the
/// boundary second on, even when it is also far outside the skew window. The answer is
/// `RequestExpired` (`AccessDenied`, as on S3 and MinIO), never `RequestTimeTooSkewed`: the past
/// bound of a presigned URL is its lifetime.
#[test]
fn c_sig_0336_a_presigned_url_past_its_lifetime_is_expired_not_skewed() {
    let floor = SecurityFloor::default();
    assert_eq!(presigned_admission("3600", at(HOUR), &floor), Ok(()));
    assert_eq!(presigned_admission("3600", at(HOUR + 1), &floor), Err(AuthError::RequestExpired));
    let error = presigned_admission("3600", at(2 * HOUR), &floor);
    assert_eq!(error, Err(AuthError::RequestExpired));
    assert_eq!(error.expect_err("an error").code(), "AccessDenied");
}

/// Negative — c-sig-0337: the future bound still applies to a presigned URL. Stamped more than
/// fifteen minutes ahead it is refused whatever lifetime it claims, and a narrowed future window
/// narrows it. Otherwise a URL dated next week would be a credential that starts working on a day
/// of the signer's choosing, which S3 and MinIO both refuse.
#[test]
fn c_sig_0337_a_presigned_url_stamped_too_far_ahead_is_skewed() {
    let floor = SecurityFloor::default();
    assert_eq!(presigned_admission("604800", at(-900), &floor), Ok(()));
    assert_eq!(presigned_admission("604800", at(-901), &floor), Err(AuthError::RequestTimeTooSkewed));
    assert_eq!(presigned_admission("604800", at(-30 * 60), &floor), Err(AuthError::RequestTimeTooSkewed));
    let narrowed = SecurityFloor::default().with_skew_window(SkewWindow::new(Duration::from_secs(900), Duration::from_secs(60)));
    assert_eq!(presigned_admission("3600", at(-60), &narrowed), Ok(()));
    assert_eq!(presigned_admission("3600", at(-61), &narrowed), Err(AuthError::RequestTimeTooSkewed));
}

/// Negative — c-sig-0338: the exemption belongs to the presigned path alone. A header-signed
/// request sixteen minutes or two hours old is still refused by the skew window, and an
/// `X-Amz-Expires` in its query string buys it nothing: the query carries no signature, so the
/// request is not a presigned URL.
#[test]
fn c_sig_0338_a_stale_header_signature_is_skewed_whatever_its_query_says() {
    let headers = signed_headers(SIGNED_AT);
    for query in ["", "X-Amz-Expires=86400", "X-Amz-Expires=86400&X-Amz-Date=20150830T123600Z"] {
        for age in [16 * 60, 2 * HOUR] {
            let view = WireView::new(&headers, RawQuery::new(query));
            assert_eq!(
                SecurityFloor::default().admit(view, &s3_object_op(), at(age)).err(),
                Some(AuthError::RequestTimeTooSkewed),
                "query {query:?}, age {age}s"
            );
        }
    }
}

/// Negative — c-sig-0339: the seven-day ceiling is intact. The longest lifetime there is ends
/// seven days after `X-Amz-Date`, and a longer one is refused as a parameter error however
/// recently the URL was signed.
#[test]
fn c_sig_0339_the_seven_day_ceiling_still_bounds_the_past() {
    let floor = SecurityFloor::default();
    let ceiling = MAX_PRESIGNED_EXPIRY_SECONDS.to_string();
    let past_ceiling = at(i64::try_from(MAX_PRESIGNED_EXPIRY_SECONDS).expect("fits") + 1);
    assert_eq!(presigned_admission(&ceiling, past_ceiling, &floor), Err(AuthError::RequestExpired));
    assert_eq!(
        presigned_admission("604801", at(2 * HOUR), &floor),
        Err(AuthError::AuthorizationQueryParametersError)
    );
    assert_eq!(
        presigned_admission("604801", at(0), &floor),
        Err(AuthError::AuthorizationQueryParametersError)
    );
}

// ---------------------------------------------------------------------------
// Negative — H2 presigned expiry
// ---------------------------------------------------------------------------

fn presigned_expiry_error(expires: &str) -> Option<AuthError> {
    let query = presigned_query(SIGNED_AT, expires);
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    SecurityFloor::default().admit(view, &s3_object_op(), now()).err()
}

fn assert_expiry_is_refused(expires: &str) {
    assert_eq!(
        presigned_expiry_error(expires),
        Some(AuthError::AuthorizationQueryParametersError),
        "must refuse X-Amz-Expires={expires:?}"
    );
}

/// Negative — c-sig-0323: a value far above the seven-day ceiling is refused.
#[test]
fn c_sig_0323_expiry_over_the_ceiling_is_refused() {
    assert_expiry_is_refused("999999");
}

/// Negative — c-sig-0324: the ceiling plus one is refused.
#[test]
fn c_sig_0324_expiry_one_second_over_the_ceiling_is_refused() {
    assert_expiry_is_refused("604801");
}

/// Negative — c-sig-0325: zero is outside the accepted range.
#[test]
fn c_sig_0325_zero_expiry_is_refused() {
    assert_expiry_is_refused("0");
}

/// Negative — c-sig-0326: a negative value is not unsigned decimal.
#[test]
fn c_sig_0326_negative_expiry_is_refused() {
    assert_expiry_is_refused("-1");
}

/// Negative — c-sig-0327: an explicit positive sign is not unsigned decimal.
#[test]
fn c_sig_0327_signed_positive_expiry_is_refused() {
    assert_expiry_is_refused("+100");
}

/// Negative — c-sig-0328: fractional seconds are not accepted.
#[test]
fn c_sig_0328_fractional_expiry_is_refused() {
    assert_expiry_is_refused("1.5");
}

/// Negative — c-sig-0329: all other non-decimal spellings are refused.
#[test]
fn c_sig_0329_other_non_decimal_expiry_spellings_are_refused() {
    for expires in [
        "%2B7d",
        "1e3",                     // c-sig-0329
        "%20100",                  // c-sig-0329, a leading space
        "100%20",                  // c-sig-0329, a trailing space
        "",                        // c-sig-0329, present and empty
        "0x10",                    // c-sig-0329
        "١٠٠",                     // c-sig-0329, non-ASCII digits
        "99999999999999999999999", // c-sig-0329, wider than u64
    ] {
        assert_expiry_is_refused(expires);
    }
}

/// Negative — c-sig-0330: `X-Amz-Expires` twice is refused rather than resolved.
#[test]
fn c_sig_0330_a_repeated_expires_parameter_is_refused() {
    let query = format!("{}&X-Amz-Expires=60", presigned_query(SIGNED_AT, "3600"));
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

/// Negative — c-sig-0331: an expiry that would overflow the instant arithmetic is refused rather
/// than wrapping into "never expires". The widest timestamp `AmzDate` can spell is the boundary.
#[test]
fn c_sig_0331_an_expiry_that_would_overflow_is_refused() {
    let query = presigned_query("99991231T235959Z", "604800");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    // The far-future stamp is refused by the skew window, never by wrapping into the past.
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::RequestTimeTooSkewed)
    );
}

/// Negative — c-sig-0332: an expired presigned URL is refused (rustfs#4714).
#[test]
fn c_sig_0332_an_expired_presigned_url_is_refused() {
    let query = presigned_query(SIGNED_AT, "60");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    let later = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 61);
    let error = SecurityFloor::default().admit(view, &s3_object_op(), later).err();
    assert_eq!(error, Some(AuthError::RequestExpired));
    assert_eq!(error.expect("an error").code(), "AccessDenied");
}

/// Negative — a presigned request without `X-Amz-Expires` at all is refused, never treated as
/// unlimited.
#[test]
fn c_sig_0335_a_presigned_url_without_an_expiry_is_refused() {
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={CRED}&X-Amz-Date={SIGNED_AT}\
         &X-Amz-SignedHeaders=host&X-Amz-Signature={SIG_HEX}"
    );
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

// ---------------------------------------------------------------------------
// Negative — H5 scope cross-check
// ---------------------------------------------------------------------------

fn scope_rejection(credential: &str, expected_service: SigService) -> Option<ScopeRejection> {
    scope_verdict(credential, expected_service, false).err()
}

/// The region `enforce_scope` verified, or its rejection; `any_region` selects the ADR-0023 policy.
fn scope_verdict(credential: &str, expected_service: SigService, any_region: bool) -> Result<String, ScopeRejection> {
    scope_verdict_under(
        credential,
        expected_service,
        Policy {
            any_region,
            empty_region: false,
            parse: EmptyRegion::Refused,
        },
    )
}

/// The two opt-in region policies, `accepting_any_region` and `accepting_empty_region`, and how the
/// scope is parsed before they are asked.
#[derive(Clone, Copy, Debug)]
struct Policy {
    any_region: bool,
    empty_region: bool,
    /// `Admitted` isolates the scope check: the parser's own empty-region rule is `parse.rs`'s to
    /// test, and a scope check that refuses what a lenient parser let through is the property.
    parse: EmptyRegion,
}

const EMPTY_ONLY: Policy = Policy {
    any_region: false,
    empty_region: true,
    parse: EmptyRegion::Admitted,
};

/// The region `enforce_scope` verified under `policy`, or its rejection.
fn scope_verdict_under(credential: &str, expected_service: SigService, policy: Policy) -> Result<String, ScopeRejection> {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let operation = OperationFloor::builtin("Any", expected_service);
    let sealed = match SecurityFloor::default().admit(view, &operation, now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let presented = CredentialScope::parse_with(credential, policy.parse).expect("a well-formed scope");
    let regions = regions();
    let mut expected = ExpectedScope::new(expected_service, &regions);
    if policy.any_region {
        expected = expected.accepting_any_region();
    }
    if policy.empty_region {
        expected = expected.accepting_empty_region();
    }
    enforce_scope(&presented, sealed.clock(), &expected).map(|scope| scope.region().to_owned())
}

const EMPTY_REGION: &str = "AKIDEXAMPLE/20150830//s3/aws4_request";

/// Positive — the RustFS profile's empty-region policy verifies an empty scope region, as legacy
/// RustFS does, and the verified scope keeps it empty rather than substituting a configured region.
#[test]
fn empty_region_policy_verifies_an_empty_region() {
    assert_eq!(scope_verdict_under(EMPTY_REGION, SigService::S3, EMPTY_ONLY).as_deref(), Ok(""));
    let both = Policy {
        any_region: true,
        empty_region: true,
        parse: EmptyRegion::Admitted,
    };
    assert_eq!(scope_verdict_under(EMPTY_REGION, SigService::S3, both).as_deref(), Ok(""));
    assert_eq!(
        scope_verdict_under("AKIDEXAMPLE/20150830/rustfs-local/s3/aws4_request", SigService::S3, both).as_deref(),
        Ok("rustfs-local")
    );
}

/// Negative — without the empty-region policy an empty region is a region mismatch like any
/// other, even if a parser let it through, and ADR-0023's any-region grammar does not reach it on
/// its own; the default parser never reads it at all.
#[test]
fn n_an_empty_region_is_refused_without_the_empty_region_policy() {
    for any_region in [false, true] {
        let policy = Policy {
            any_region,
            empty_region: false,
            parse: EmptyRegion::Admitted,
        };
        let rejection = scope_verdict_under(EMPTY_REGION, SigService::S3, policy).expect_err("not admitted");
        assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"), "{any_region}");
    }
    assert!(CredentialScope::parse(EMPTY_REGION).is_err(), "the default parser refuses it");
}

/// Negative — the empty-region policy admits the empty region and nothing else: an unserved or
/// ungrammatical region is still refused, naming the region to use.
#[test]
fn n_empty_region_policy_admits_no_other_region() {
    for region in ["ap-south-1", "AP-SOUTH-1", "rustfs_local", "-"] {
        let credential = format!("AKIDEXAMPLE/20150830/{region}/s3/aws4_request");
        let rejection = scope_verdict_under(&credential, SigService::S3, EMPTY_ONLY).expect_err(region);
        assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"), "{region}");
    }
}

/// Negative — the empty-region policy widens the region check only: another day and another
/// service are still refused.
#[test]
fn n_empty_region_policy_still_enforces_the_date_and_the_service() {
    for (credential, service) in [
        ("AKIDEXAMPLE/20150831//s3/aws4_request", SigService::S3),
        ("AKIDEXAMPLE/20150830//sts/aws4_request", SigService::S3),
        (EMPTY_REGION, SigService::Sts),
    ] {
        let rejection = scope_verdict_under(credential, service, EMPTY_ONLY).expect_err(credential);
        assert_eq!(rejection.expected_region(), None, "{credential}");
    }
}

/// Positive — ADR-0023: under the any-region policy an unserved region in the configured-name
/// grammar is verified, and the verified scope is the client's region, not a configured one.
#[test]
fn any_region_policy_verifies_an_unserved_region_in_the_grammar() {
    for region in ["ap-south-1", "rustfs-local", "a"] {
        let credential = format!("AKIDEXAMPLE/20150830/{region}/s3/aws4_request");
        assert_eq!(scope_verdict(&credential, SigService::S3, true).as_deref(), Ok(region));
    }
}

/// Negative — ADR-0023: a region the scope parser accepts but the configured-name grammar does
/// not is still refused, naming the first configured region, so nothing a configured name could
/// not spell reaches a handler. (Over 64 bytes never gets this far: the parser refuses it.)
#[test]
fn n_any_region_policy_still_refuses_a_region_outside_the_grammar() {
    for region in ["AP-SOUTH-1", "rustfs_local", "eu.west.1", "us-east-1!"] {
        let credential = format!("AKIDEXAMPLE/20150830/{region}/s3/aws4_request");
        let rejection = scope_verdict(&credential, SigService::S3, true).expect_err(region);
        assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"), "{region}");
    }
}

/// Negative — ADR-0023 widens the region check only: another day and another service are still
/// refused under the policy.
#[test]
fn n_any_region_policy_still_enforces_the_date_and_the_service() {
    for (credential, service) in [
        ("AKIDEXAMPLE/20150831/ap-south-1/s3/aws4_request", SigService::S3),
        ("AKIDEXAMPLE/20150830/ap-south-1/sts/aws4_request", SigService::S3),
    ] {
        let rejection = scope_verdict(credential, service, true).expect_err(credential);
        assert_eq!(rejection.expected_region(), None, "{credential}");
    }
}

/// Negative — the policy is opt-in: without it the same unserved region is refused.
#[test]
fn n_without_the_policy_an_unserved_region_in_the_grammar_is_refused() {
    let rejection =
        scope_verdict("AKIDEXAMPLE/20150830/rustfs-local/s3/aws4_request", SigService::S3, false).expect_err("strict default");
    assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"));
}

/// Negative — c-sig-0340: a signature minted for STS cannot replay against S3.
#[test]
fn c_sig_0340_an_sts_scope_is_refused_for_an_s3_operation() {
    let rejection =
        scope_rejection("AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request", SigService::S3).expect("the service disagrees");
    assert_eq!(rejection.expected_region(), None);
}

/// Negative — c-sig-0341: a signature minted for S3 cannot replay against STS.
#[test]
fn c_sig_0341_an_s3_scope_is_refused_for_an_sts_operation() {
    let rejection =
        scope_rejection("AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request", SigService::Sts).expect("the service disagrees");
    assert_eq!(rejection.expected_region(), None);
}

/// Negative — c-sig-0342: a region outside the configured set is refused.
#[test]
fn c_sig_0342_an_unconfigured_region_is_refused() {
    let rejection =
        scope_rejection("AKIDEXAMPLE/20150830/ap-south-1/s3/aws4_request", SigService::S3).expect("the region is not configured");
    assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"));
}

/// Negative — c-sig-0343: a scope date that is not the day of the signed timestamp is refused.
#[test]
fn c_sig_0343_a_scope_date_from_another_day_is_refused() {
    let rejection =
        scope_rejection("AKIDEXAMPLE/20150831/us-east-1/s3/aws4_request", SigService::S3).expect("the date disagrees");
    assert_eq!(rejection.expected_region(), None);
}

/// Negative — c-sig-0344: the terminator is fixed, and a scope that does not end in it never
/// becomes a `CredentialScope` in the first place.
#[test]
fn c_sig_0344_a_wrong_terminator_never_parses() {
    for bad in [
        "AKIDEXAMPLE/20150830/us-east-1/s3/aws4-request",
        "AKIDEXAMPLE/20150830/us-east-1/s3/AWS4_REQUEST",
        "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request2",
    ] {
        assert!(CredentialScope::parse(bad).is_err(), "must refuse {bad}");
    }
}

/// Negative — an empty region set is refused at construction: a set nothing can match would turn
/// every request into a scope failure, which is the shape people "fix" by skipping the check.
#[test]
fn c_sig_0347_an_empty_region_set_is_refused() {
    assert!(RegionSet::new::<[&str; 0], &str>([]).is_err());
    assert!(RegionSet::new([""]).is_err());
}

/// Positive — the system clock is a `RequestClock`, so the production wiring is the same shape as
/// the fixtures above: capture once, pass the snapshot in.
#[test]
fn c_sig_0380_the_system_clock_produces_one_snapshot() {
    let first = SystemClock.capture();
    assert!(first.unix_seconds() > 1_700_000_000, "the system clock is past 2023");
}

/// The region `enforce_scope` verified under the any-spelling policy (rustfs/gateway#1075), or
/// its rejection.
fn spelling_verdict(credential: &str, expected_service: SigService) -> Result<String, ScopeRejection> {
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let operation = OperationFloor::builtin("Any", expected_service);
    let sealed = match SecurityFloor::default().admit(view, &operation, now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let presented = CredentialScope::parse(credential).expect("a well-formed scope");
    let regions = regions();
    let expected = ExpectedScope::new(expected_service, &regions).accepting_any_region_spelling();
    enforce_scope(&presented, sealed.clock(), &expected).map(|scope| scope.region().to_owned())
}

/// Positive — the any-spelling policy lets a region outside the grammar through the scope check,
/// verbatim, so the signature is checked over the region the client signed; refusing it
/// afterwards is the verifier's job (`RegionSet::is_region_name` says which ones).
#[test]
fn any_spelling_policy_admits_a_region_outside_the_grammar_verbatim() {
    for region in ["US-EAST-1", "rustfs_local", "eu.west.1", "ap-south-1"] {
        let credential = format!("AKIDEXAMPLE/20150830/{region}/s3/aws4_request");
        assert_eq!(spelling_verdict(&credential, SigService::S3).as_deref(), Ok(region), "{region}");
    }
    assert!(!RegionSet::is_region_name("US-EAST-1"));
    assert!(!RegionSet::is_region_name(""));
    assert!(RegionSet::is_region_name("ap-south-1"));
}

/// Negative — the any-spelling policy widens the region check only: an empty region still needs
/// its own policy, and another day and another service are still refused.
#[test]
fn n_any_spelling_policy_still_enforces_the_empty_region_the_date_and_the_service() {
    for (credential, service, region) in [
        ("AKIDEXAMPLE/20150831/US-EAST-1/s3/aws4_request", SigService::S3, None),
        ("AKIDEXAMPLE/20150830/US-EAST-1/sts/aws4_request", SigService::S3, None),
        ("AKIDEXAMPLE/20150830/US-EAST-1/s3/aws4_request", SigService::Sts, None),
    ] {
        let rejection = spelling_verdict(credential, service).expect_err(credential);
        assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), region, "{credential}");
    }
    let presented =
        CredentialScope::parse_with("AKIDEXAMPLE/20150830//s3/aws4_request", EmptyRegion::Admitted).expect("five fields");
    let regions = regions();
    let expected = ExpectedScope::new(SigService::S3, &regions).accepting_any_region_spelling();
    let headers = signed_headers(SIGNED_AT);
    let view = WireView::new(&headers, RawQuery::new(""));
    let sealed = match SecurityFloor::default().admit(view, &OperationFloor::builtin("Any", SigService::S3), now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed AWS admission, got {other:?}"),
    };
    let rejection = enforce_scope(&presented, sealed.clock(), &expected).expect_err("the empty region is not a spelling");
    assert_eq!(rejection.expected_region().map(ScopeRegion::as_str), Some("eu-west-1"));
}
