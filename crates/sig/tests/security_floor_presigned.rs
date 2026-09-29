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

//! Presigned admission widened to every standard operation (rustfs/gateway#1052,
//! rustfs/backlog#1677 R7).
//!
//! Responsible for: the default staying per operation; the widening admitting a presigned URL to
//! a standard operation that never opted in; the privileged fence holding under it; SigV2 presigned
//! URLs still following the SigV2 policy; the other slots untouched; and every rule of the
//! presigned path — duplicates, lifetime, expiry — still running on a widened admission.
//! NOT responsible for: the per-operation allow-list defaults and the privileged surface under the
//! default floor (`tests/security_floor_schemes.rs`), or the clock and expiry rules themselves
//! (`tests/security_floor.rs`).
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use http::header::HeaderMap;
use rustfs_gateway_sig::{
    Admission, AuthError, OperationFloor, PresignedPolicy, RawQuery, RequestNow, SchemeSlot, SecurityFloor, SigFamily,
    SigService, WireView,
};

use crate::security_floor_fixtures::*;

/// A standard operation that never opted in to presigned URLs.
fn standard_op() -> OperationFloor {
    OperationFloor::builtin("DeleteObject", SigService::S3)
}

fn widened() -> SecurityFloor {
    SecurityFloor::new().admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
}

fn presigned(query: &str, floor: &SecurityFloor, operation: &OperationFloor, now: RequestNow) -> Result<(), AuthError> {
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(query));
    floor.admit(view, operation, now).map(|_| ())
}

/// Negative — the default is per operation: a standard operation that did not opt in refuses a
/// presigned URL, and the posture predicate agrees.
#[test]
fn n_presigned_admission_is_per_operation_by_default() {
    assert_eq!(PresignedPolicy::default(), PresignedPolicy::PerOperation);
    assert_eq!(SecurityFloor::new().presigned_policy(), PresignedPolicy::PerOperation);
    assert_eq!(
        presigned(&presigned_query(SIGNED_AT, "3600"), &SecurityFloor::new(), &standard_op(), now()),
        Err(AuthError::AccessDenied)
    );
    assert!(!SecurityFloor::new().admits_presigned(&standard_op()));
    assert!(
        SecurityFloor::new().admits_presigned(&s3_object_op()),
        "an operation's own opt-in still counts"
    );
}

/// Positive — the widening admits a presigned URL to a standard operation that never opted in, as
/// a sealed AWS admission that still carries its expiry for the verifier.
#[test]
fn a_widened_floor_admits_a_presigned_url_to_a_standard_operation() {
    assert_eq!(widened().presigned_policy(), PresignedPolicy::EveryStandardOperation);
    let headers = HeaderMap::new();
    let query = presigned_query(SIGNED_AT, "3600");
    let view = WireView::new(&headers, RawQuery::new(&query));
    match widened().admit(view, &standard_op(), now()) {
        Ok(Admission::Sealed(sealed)) => assert!(sealed.expiry().is_some(), "a presigned admission carries its expiry"),
        other => panic!("expected a sealed presigned admission, got {other:?}"),
    }
    assert!(widened().admits_presigned(&standard_op()));
}

/// Negative — the privileged fence holds under the widening: an admin operation, a third-party
/// operation, and a standard operation marked privileged all refuse a presigned URL.
#[test]
fn n_a_widened_floor_still_refuses_presigned_on_a_privileged_operation() {
    for operation in [
        admin_op(),
        OperationFloor::custom("example:Unlisted", SigService::S3),
        standard_op().mark_privileged(),
    ] {
        assert_eq!(
            presigned(&presigned_query(SIGNED_AT, "3600"), &widened(), &operation, now()),
            Err(AuthError::AccessDenied),
            "{}",
            operation.name()
        );
        assert!(!widened().admits_presigned(&operation), "{}", operation.name());
    }
}

/// Negative — the widening does not turn SigV2 presigned URLs on: they still follow the SigV2
/// policy, refused by default and admitted only when a deployment enables them.
#[test]
fn n_a_widened_floor_leaves_sigv2_presigned_to_the_sigv2_policy() {
    // A well-formed SigV2 signature (twenty bytes, base64): the refusals below are the policy's.
    let query = format!(
        "AWSAccessKeyId=AKIDEXAMPLE&Expires={}&Signature=AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        SIGNED_AT_UNIX + 600
    );
    assert_eq!(presigned(&query, &widened(), &standard_op(), now()), Err(AuthError::AccessDenied));
    let both = widened().enable_sigv2_presigned_compatibility();
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert!(matches!(both.admit(view, &standard_op(), now()), Ok(Admission::SealedSigV2(_))));
    // And without the widening, the SigV2 switch alone still admits only an opted-in operation.
    assert_eq!(
        presigned(
            &query,
            &SecurityFloor::new().enable_sigv2_presigned_compatibility(),
            &standard_op(),
            now()
        ),
        Err(AuthError::AccessDenied)
    );
}

/// Negative — the widening widens the presigned slot only: anonymous and POST-policy admission keep
/// their own rules.
#[test]
fn n_a_widened_floor_widens_no_other_scheme() {
    let operation = standard_op();
    for slot in [SchemeSlot::Anonymous, SchemeSlot::PostPolicy] {
        assert_eq!(
            widened().enforce_scheme_allowed(&operation, slot, SigFamily::V4),
            Err(AuthError::AccessDenied),
            "{slot:?}"
        );
    }
    assert_eq!(widened().enforce_scheme_allowed(&operation, SchemeSlot::Presigned, SigFamily::V4), Ok(()));
    assert_eq!(widened().enforce_scheme_allowed(&operation, SchemeSlot::Header, SigFamily::V4), Ok(()));
}

/// Negative — every rule of the presigned path still runs on a widened admission: an expired URL,
/// a URL with no expiry, a lifetime over seven days and a repeated signature parameter are refused
/// exactly as on an operation that opted in.
#[test]
fn n_a_widened_admission_still_runs_every_presigned_rule() {
    let operation = standard_op();
    let later = RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 61);
    assert_eq!(
        presigned(&presigned_query(SIGNED_AT, "60"), &widened(), &operation, later),
        Err(AuthError::RequestExpired)
    );
    let no_expiry = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={CRED}&X-Amz-Date={SIGNED_AT}\
         &X-Amz-SignedHeaders=host&X-Amz-Signature={SIG_HEX}"
    );
    assert_eq!(
        presigned(&no_expiry, &widened(), &operation, now()),
        Err(AuthError::AuthorizationQueryParametersError)
    );
    assert_eq!(
        presigned(&presigned_query(SIGNED_AT, "604801"), &widened(), &operation, now()),
        Err(AuthError::AuthorizationQueryParametersError)
    );
    let repeated = format!("{}&X-Amz-Signature={SIG_HEX}", presigned_query(SIGNED_AT, "3600"));
    assert!(presigned(&repeated, &widened(), &operation, now()).is_err());
    // Each refusal above is the same one an opted-in operation gets.
    let opted_in = s3_object_op();
    assert_eq!(
        presigned(&presigned_query(SIGNED_AT, "60"), &SecurityFloor::new(), &opted_in, later),
        Err(AuthError::RequestExpired)
    );
    assert_eq!(
        presigned(&presigned_query(SIGNED_AT, "604801"), &SecurityFloor::new(), &opted_in, now()),
        Err(AuthError::AuthorizationQueryParametersError)
    );
}
