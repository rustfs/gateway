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

//! `OperationFloor::refuse_sigv2_under_every_policy` at `SecurityFloor::admit` (ADR-0052,
//! rustfs/gateway#1592).
//!
//! Responsible for: what the floor does with every SigV2 shape — header, presigned URL and POST
//! policy — on an operation that refuses SigV2, under every SigV2 policy and every floor reading;
//! that the refusal comes before the SigV2 credential is even parsed; that it answers what
//! `require_sigv4_under_every_policy` answers; that SigV4, anonymous, bearer and custom-scheme
//! admissions are unchanged; and the controls in the other direction, the same operations
//! without the rule, which admit SigV2.
//! NOT responsible for: credential lookup or the served answer (the facade and the goldens'
//! STS parity suite), or registration (`rustfs-gateway-core`'s registry).
//! Upstream: the `rustfs-gateway-sig` public API and `security_floor_fixtures`. Downstream:
//! `tests/integration.rs`, the only Cargo target that compiles this file.
//!
//! Negative cases outnumber positive ones.

use http::HeaderMap;
use rustfs_gateway_sig::sig_v2::SigV2Policy;
use rustfs_gateway_sig::{
    Admission, AuthError, CustomAuthScheme, CustomSchemeRegistry, OperationFloor, QueryBearerClaim, RawQuery, SecurityFloor,
    SigService, WireView,
};

use crate::security_floor_fixtures::{
    SIGNED_AT, SIGNED_AT_UNIX, form_view, header_map, now, post_form, presigned_query, signed_headers,
};

/// `SIGNED_AT` as SigV2's `Date` header spells it.
const SIGV2_DATE: &str = "Sun, 30 Aug 2015 12:36:00 GMT";
/// Twenty zero bytes in base64: a well-formed SigV2 signature the floor does not compare.
const SIGV2_SIGNATURE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// One issued key and one nobody issued. The floor never resolves either.
const KEYS: [&str; 2] = ["AKIDEXAMPLE", "AKIDNOSUCHKEY"];
const BEARER: QueryBearerClaim = QueryBearerClaim::new("token", ".zip");

/// The STS form endpoint's floor shape: standard, header-signed or anonymous, refusing SigV2.
fn sts_shaped() -> OperationFloor {
    OperationFloor::builtin("example:StsForm", SigService::Sts)
        .allow_anonymous_after_listing_in_the_posture_report()
        .refuse_sigv2_under_every_policy()
}

/// The same floor without the rule: the control that admits SigV2.
fn sts_shaped_control() -> OperationFloor {
    OperationFloor::builtin("example:StsForm", SigService::Sts).allow_anonymous_after_listing_in_the_posture_report()
}

/// An operation that accepts every shape, so a refusal is never its allow-list's.
fn every_shape(refusing: bool) -> OperationFloor {
    let floor = OperationFloor::builtin_presigned("example:Wide", SigService::S3)
        .allow_post_policy()
        .allow_anonymous_after_listing_in_the_posture_report();
    if refusing {
        floor.refuse_sigv2_under_every_policy()
    } else {
        floor
    }
}

/// Every floor a deployment can assemble that reads SigV2 at all, the RustFS profile's included.
fn sigv2_floors() -> Vec<(&'static str, SecurityFloor)> {
    vec![
        ("default (HeaderOnly)", SecurityFloor::new()),
        (
            "HeaderAndPresigned",
            SecurityFloor::new().with_sigv2_policy(SigV2Policy::HeaderAndPresigned),
        ),
        (
            "RustFS profile",
            SecurityFloor::new()
                .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                .enable_sigv2_presigned_compatibility()
                .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                .recognize_signatures_as_legacy_rustfs(),
        ),
    ]
}

fn sigv2_header(key: &str, signature: &str) -> HeaderMap {
    header_map(&[("date", SIGV2_DATE), ("authorization", &format!("AWS {key}:{signature}"))])
}

fn sigv2_query(key: &str, signature: &str) -> String {
    let signature = signature.replace('=', "%3D");
    format!("AWSAccessKeyId={key}&Expires={}&Signature={signature}", SIGNED_AT_UNIX + 600)
}

fn sigv2_form(key: &'static str) -> [(&'static str, &'static str); 3] {
    [
        ("AWSAccessKeyId", key),
        ("signature", SIGV2_SIGNATURE),
        ("policy", "eyJleHBpcmF0aW9uIjoiIn0="),
    ]
}

/// What `admit` answered, reduced to a comparable shape.
fn outcome(result: Result<Admission<'_>, AuthError>) -> Result<&'static str, AuthError> {
    result.map(|admission| match admission {
        Admission::Sealed(_) => "Sealed",
        Admission::SealedSigV2(_) => "SealedSigV2",
        Admission::Custom(_) => "Custom",
        Admission::Anonymous(_) => "Anonymous",
        Admission::Bearer(_) => "Bearer",
        _ => "other",
    })
}

/// The three SigV2 shapes for `key` with `signature`, as `admit` answers them on `operation`.
fn sigv2_outcomes(
    floor: &SecurityFloor,
    operation: &OperationFloor,
    key: &'static str,
    signature: &str,
) -> [Result<&'static str, AuthError>; 3] {
    let empty = HeaderMap::new();
    let header = sigv2_header(key, signature);
    let query = sigv2_query(key, signature);
    let form = sigv2_form(key);
    [
        outcome(floor.admit(WireView::new(&header, RawQuery::new("")), operation, now())),
        outcome(floor.admit(WireView::new(&empty, RawQuery::new(&query)), operation, now())),
        outcome(floor.admit(WireView::new(&empty, RawQuery::new("")).with_form_fields(&form), operation, now())),
    ]
}

/// Negative — on an operation that accepts every shape, a SigV2 header, presigned URL and POST
/// policy are each refused `AccessDenied` under every floor, for a known and an unknown key alike.
#[test]
fn n_every_sigv2_shape_is_refused_under_every_floor_for_any_key() {
    for (at, floor) in sigv2_floors() {
        for key in KEYS {
            assert_eq!(
                sigv2_outcomes(&floor, &every_shape(true), key, SIGV2_SIGNATURE),
                [Err(AuthError::AccessDenied); 3],
                "{at}: {key}"
            );
        }
    }
}

/// Negative — the STS-shaped floor refuses the SigV2 header and presigned URL under every floor,
/// the RustFS profile's included, where the presigned URL reaches a standard operation.
#[test]
fn n_the_sts_shaped_floor_refuses_sigv2_header_and_presigned_under_every_floor() {
    for (at, floor) in sigv2_floors() {
        let [header, presigned, _] = sigv2_outcomes(&floor, &sts_shaped(), KEYS[0], SIGV2_SIGNATURE);
        assert_eq!(header, Err(AuthError::AccessDenied), "{at}");
        assert_eq!(presigned, Err(AuthError::AccessDenied), "{at}");
    }
}

/// Negative — the refusal precedes the SigV2 credential parse: an unreadable signature is refused
/// `AccessDenied` too, where the control without the rule reaches the parser and answers its own
/// error. Which answer a request gets therefore says nothing about its credential.
#[test]
fn n_the_refusal_precedes_the_sigv2_credential_parse() {
    let floor = SecurityFloor::new().with_sigv2_policy(SigV2Policy::HeaderAndPresigned);
    let unreadable = "not-base64!";
    assert_eq!(
        sigv2_outcomes(&floor, &every_shape(true), KEYS[1], unreadable)[..2],
        [Err(AuthError::AccessDenied); 2]
    );
    let control = sigv2_outcomes(&floor, &every_shape(false), KEYS[1], unreadable);
    assert!(
        control[..2]
            .iter()
            .all(|answer| answer.is_err() && *answer != Err(AuthError::AccessDenied)),
        "{control:?}"
    );
}

/// Negative — the answer is the one `require_sigv4_under_every_policy` gives for SigV2, shape by
/// shape, so a caller cannot tell the two rules apart.
#[test]
fn n_the_answer_equals_the_sigv4_requirements_answer() {
    let sigv4_only = OperationFloor::builtin_presigned("example:Wide", SigService::S3)
        .allow_post_policy()
        .require_sigv4_under_every_policy();
    for (at, floor) in sigv2_floors() {
        assert_eq!(
            sigv2_outcomes(&floor, &every_shape(true), KEYS[0], SIGV2_SIGNATURE),
            sigv2_outcomes(&floor, &sigv4_only, KEYS[0], SIGV2_SIGNATURE),
            "{at}"
        );
    }
}

/// Negative — a SigV2 header that also carries the bearer claim's token is refused on a floor
/// that refuses SigV2 and declares the claim, as the zip download's does; the same request on
/// the claim-only floor is sealed for SigV2 verification, which is the control.
#[test]
fn n_a_sigv2_header_carrying_a_bearer_token_is_refused() {
    let refusing = OperationFloor::custom("example:Zip", SigService::S3)
        .refuse_sigv2_under_every_policy()
        .with_query_bearer_claim(BEARER);
    let control = OperationFloor::custom("example:Zip", SigService::S3).with_query_bearer_claim(BEARER);
    let header = sigv2_header(KEYS[0], SIGV2_SIGNATURE);
    for (at, floor) in sigv2_floors() {
        for query in ["", "token=t"] {
            let view = WireView::new(&header, RawQuery::new(query));
            assert_eq!(
                outcome(floor.admit(view, &refusing, now())),
                Err(AuthError::AccessDenied),
                "{at}: {query}"
            );
            assert_eq!(outcome(floor.admit(view, &control, now())), Ok("SealedSigV2"), "{at}: {query}");
        }
    }
}

/// Negative — the rule does not weaken `require_sigv4_under_every_policy`, in either order: an
/// anonymous request and a bearer token stay refused when both rules are declared.
#[test]
fn n_combining_with_the_sigv4_requirement_keeps_the_stronger_rule() {
    let empty = HeaderMap::new();
    let base =
        OperationFloor::builtin_presigned("example:Both", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();
    for both in [
        base.require_sigv4_under_every_policy().refuse_sigv2_under_every_policy(),
        base.refuse_sigv2_under_every_policy().require_sigv4_under_every_policy(),
    ] {
        assert!(both.requires_sigv4_under_every_policy() && both.refuses_sigv2_under_every_policy());
        for (at, floor) in sigv2_floors() {
            let view = WireView::new(&empty, RawQuery::new(""));
            assert_eq!(outcome(floor.admit(view, &both, now())), Err(AuthError::AccessDenied), "{at}");
        }
    }
}

/// Positive — the controls in the other direction: the same operations without the rule admit
/// every SigV2 shape their floor and policy admit, so the refusals above are the rule's.
#[test]
fn without_the_rule_the_same_operations_admit_sigv2() {
    let floor = SecurityFloor::new().with_sigv2_policy(SigV2Policy::HeaderAndPresigned);
    assert_eq!(
        sigv2_outcomes(&floor, &every_shape(false), KEYS[1], SIGV2_SIGNATURE),
        [Ok("SealedSigV2"); 3]
    );
    for (at, floor) in sigv2_floors() {
        let [header, ..] = sigv2_outcomes(&floor, &sts_shaped_control(), KEYS[0], SIGV2_SIGNATURE);
        assert_eq!(header, Ok("SealedSigV2"), "{at}");
    }
}

/// Positive — SigV4 is unchanged: a header signature, a presigned URL and a POST policy are
/// sealed for SigV4 verification on the rule's floor, under every floor.
#[test]
fn sigv4_header_presigned_and_post_policy_are_still_admitted() {
    let headers = signed_headers(SIGNED_AT);
    let empty = HeaderMap::new();
    let query = presigned_query(SIGNED_AT, "600");
    let fields = post_form(SIGNED_AT);
    let form = form_view(&fields);
    for (at, floor) in sigv2_floors() {
        let operation = every_shape(true);
        assert_eq!(
            outcome(floor.admit(WireView::new(&headers, RawQuery::new("")), &operation, now())),
            Ok("Sealed"),
            "{at}"
        );
        assert_eq!(
            outcome(floor.admit(WireView::new(&empty, RawQuery::new(&query)), &operation, now())),
            Ok("Sealed"),
            "{at}"
        );
        assert_eq!(
            outcome(floor.admit(WireView::new(&empty, RawQuery::new("")).with_form_fields(&form), &operation, now())),
            Ok("Sealed"),
            "{at}"
        );
        let sts = WireView::new(&headers, RawQuery::new(""));
        assert_eq!(outcome(floor.admit(sts, &sts_shaped(), now())), Ok("Sealed"), "{at}");
    }
}

/// Positive — what carries no AWS marker is unchanged: an anonymous request on the STS-shaped
/// floor, a bearer token on a claim-carrying one, and a registered custom scheme.
#[test]
fn anonymous_bearer_and_custom_admissions_are_unchanged() {
    let empty = HeaderMap::new();
    for (at, floor) in sigv2_floors() {
        let view = WireView::new(&empty, RawQuery::new(""));
        assert_eq!(outcome(floor.admit(view, &sts_shaped(), now())), Ok("Anonymous"), "{at}");
        let bearer = OperationFloor::custom("example:Zip", SigService::S3)
            .refuse_sigv2_under_every_policy()
            .with_query_bearer_claim(BEARER);
        let view = WireView::new(&empty, RawQuery::new("token=t"));
        assert_eq!(outcome(floor.admit(view, &bearer, now())), Ok("Bearer"), "{at}");
    }
    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal prefix"))
        .expect("the first registration cannot conflict");
    let custom = header_map(&[("x-vendor-auth-token", "opaque")]);
    let view = WireView::new(&custom, RawQuery::new(""));
    assert_eq!(
        outcome(
            SecurityFloor::new()
                .with_custom_schemes(registry)
                .admit(view, &sts_shaped(), now())
        ),
        Ok("Custom")
    );
}
