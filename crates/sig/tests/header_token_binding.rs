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

//! What binds a header token claim to its host (ADR-0053, rustfs/gateway#1586).
//!
//! Responsible for: the refused aliases of a claim — their grammar, and that a request carrying
//! one is refused whatever else it carries; the binding of the reported identity to the value
//! the host established in the request's own state, and to no other; and the origin the kernel
//! marks on the reported name.
//! NOT responsible for: admission of the claimed header itself, or what a verification yields
//! (`header_token.rs`); the facade's wiring (`rustfs-gateway`'s `tests/header_token.rs`).
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use http::header::HeaderMap;
use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_sig::{
    AuthError, HeaderTokenClaim, HeaderTokenRefused, HeaderTokenVerifier, Identity, IdentityOrigin, OperationFloor, RequestNow,
    SecurityFloor, SigService,
};

use crate::header_token::{
    Accepts, Established, HEADER, NamesWhatWasEstablished, PRINCIPAL, TOKEN, admission_of, admit, claim, server_state, shape,
    standard_op, with_token,
};
use crate::security_floor_fixtures::*;

const ALIAS: &str = "x-storage-token";
/// An access key id, as a signed request names one.
const ACCESS_KEY: &str = "AKIDEXAMPLE";

fn aliased_claim() -> HeaderTokenClaim {
    claim().refusing_aliases(&[ALIAS, "x-subject-token"]).expect("legal aliases")
}

fn aliased_floor() -> SecurityFloor {
    SecurityFloor::new().with_header_token_claim(aliased_claim())
}

fn anonymous_op() -> OperationFloor {
    standard_op().allow_anonymous_after_listing_in_the_posture_report()
}

// ---------------------------------------------------------------------------
// Refused aliases
// ---------------------------------------------------------------------------

/// Positive — a claim lists the aliases it refuses, and keeps naming its own header.
#[test]
fn a_claim_names_the_aliases_it_refuses() {
    let aliased = aliased_claim();
    assert_eq!(aliased.header(), HEADER);
    assert_eq!(aliased.refused_aliases(), [ALIAS, "x-subject-token"]);
    assert!(claim().refused_aliases().is_empty());
    assert!(claim().refusing_aliases(&[]).is_ok(), "no alias is a legal list");
}

/// Negative — an alias is held to the claim's own grammar, and cannot be the claimed header: a
/// claim that refused its own header would refuse every token.
#[test]
fn n_an_alias_outside_the_grammar_or_equal_to_the_claimed_header_is_no_claim() {
    let lists: [&'static [&'static str]; 9] = [
        &[HEADER],
        &[ALIAS, HEADER],
        &["X-Storage-Token"],
        &["storage-token"],
        &["authorization"],
        &["x-amz-security-token"],
        &["x-forwarded-for"],
        &[ALIAS, ""],
        &["x-storage-token "],
    ];
    for aliases in lists {
        assert!(claim().refusing_aliases(aliases).is_err(), "{aliases:?}");
    }
}

/// Negative — a request that carries a refused alias is refused `AccessDenied`, alone, beside a
/// valid signature, beside the claimed token, with an empty value, in any case and on any
/// operation. The same request under a claim that lists no alias keeps its own answer, which is
/// what makes each refusal the alias's doing.
#[test]
fn n_a_refused_alias_refuses_the_request_whatever_else_it_carries() {
    let plain = SecurityFloor::new().with_header_token_claim(claim());
    let signed = signed_headers(SIGNED_AT);
    let mut signed_with_alias = signed.clone();
    signed_with_alias.insert(ALIAS, http::HeaderValue::from_static(TOKEN));
    let cases: [(&str, HeaderMap, OperationFloor, &str); 7] = [
        ("alone, anonymous operation", header_map(&[(ALIAS, TOKEN)]), anonymous_op(), "anonymous"),
        ("in another case", header_map(&[("X-Storage-Token", TOKEN)]), anonymous_op(), "anonymous"),
        ("empty", header_map(&[(ALIAS, "")]), anonymous_op(), "anonymous"),
        ("the second alias", header_map(&[("x-subject-token", TOKEN)]), anonymous_op(), "anonymous"),
        ("beside a valid signature", signed_with_alias, standard_op(), "sealed"),
        ("beside the claimed token", with_token(&[(ALIAS, TOKEN)]), standard_op(), "header-token"),
        (
            "beside the claimed token, same value",
            with_token(&[(ALIAS, "another")]),
            anonymous_op(),
            "header-token",
        ),
    ];
    let aliased = aliased_floor();
    for (name, headers, operation, without_the_rule) in &cases {
        let refused = admit(&aliased, headers, "", None, operation);
        assert_eq!(shape(&refused), "refused:AccessDenied", "{name}");
        assert!(aliased_claim().presented(headers), "{name}");
        assert_eq!(
            shape(&admit(&plain, headers, "", None, operation)),
            *without_the_rule,
            "{name}: the control"
        );
    }
    // A privileged operation refuses it too, and not with any other answer.
    let alias_alone = header_map(&[(ALIAS, TOKEN)]);
    assert_eq!(shape(&admit(&aliased, &alias_alone, "", None, &admin_op())), "refused:AccessDenied");
}

/// Positive — listing aliases changes nothing for a request that carries none of them: the
/// claimed token is admitted, and every other request is decided as under a claim with no alias.
#[test]
fn a_claim_with_aliases_leaves_every_other_request_alone() {
    let plain = SecurityFloor::new().with_header_token_claim(claim());
    let token = with_token(&[]);
    assert_eq!(shape(&admit(&aliased_floor(), &token, "", None, &standard_op())), "header-token");
    let near_misses = header_map(&[("x-storage-token2", TOKEN), ("x-storage", TOKEN), ("storage-token", TOKEN)]);
    for (name, headers, operation) in [
        ("nothing", HeaderMap::new(), anonymous_op()),
        ("nothing, header-only", HeaderMap::new(), standard_op()),
        ("signed", signed_headers(SIGNED_AT), standard_op()),
        ("names that resemble an alias", near_misses, anonymous_op()),
    ] {
        assert!(!aliased_claim().presented(&headers), "{name}");
        assert_eq!(
            shape(&admit(&aliased_floor(), &headers, "", None, &operation)),
            shape(&admit(&plain, &headers, "", None, &operation)),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// The identity is the one this request carries
// ---------------------------------------------------------------------------

/// Negative — a request in which the host established nothing is refused without the verifier
/// being asked, even by a verifier that would vouch for anyone. A request that holds a value is
/// the control: the same verifier is asked once.
#[test]
fn n_a_request_that_holds_nothing_established_never_reaches_the_verifier() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = with_token(&[]);
    let anyone = Accepts::default();

    for nothing in [server_state(None), TransportExtensions::default()] {
        let verdict = admission_of(&floor, &headers, &standard_op()).verify(&anyone, &nothing);
        assert_eq!(verdict.rejection(), Some(AuthError::AccessDenied));
        assert!(!verdict.is_anonymous() && verdict.identity().is_none());
    }
    assert_eq!(
        anyone.0.load(Ordering::SeqCst),
        0,
        "the verifier was asked about a request that carried nothing"
    );

    let verdict = admission_of(&floor, &headers, &standard_op()).verify(&anyone, &server_state(Some(Established("x"))));
    assert_eq!(verdict.identity().map(Identity::access_key_id), Some(PRINCIPAL));
    assert_eq!(anyone.0.load(Ordering::SeqCst), 1);
}

/// Positive and negative — one verifier, asked about two requests in turn and in either order,
/// names for each the identity that request carries and never the other's.
#[test]
fn one_verifier_names_for_each_request_what_that_request_carries() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = with_token(&[]);
    let verifier = NamesWhatWasEstablished::default();
    let alice = server_state(Some(Established("ALICE")));
    let bob = server_state(Some(Established("BOB")));
    let nobody = server_state(None);
    let name = |state: &TransportExtensions| {
        let verdict = admission_of(&floor, &headers, &standard_op()).verify(&verifier, state);
        verdict.identity().map(|identity| identity.access_key_id().to_owned())
    };
    for _ in 0..3 {
        assert_eq!(name(&alice).as_deref(), Some("ALICE"));
        assert_eq!(name(&nobody), None, "the request after Alice's carries nothing and is nobody");
        assert_eq!(name(&bob).as_deref(), Some("BOB"));
        assert_eq!(name(&nobody), None);
        assert_eq!(name(&bob).as_deref(), Some("BOB"));
        assert_eq!(name(&alice).as_deref(), Some("ALICE"));
    }
}

// ---------------------------------------------------------------------------
// Beside the SigV2 refusal of ADR-0052
// ---------------------------------------------------------------------------

/// Positive and negative — an operation that refuses SigV2 under every policy still admits a
/// header token, which is no SigV2 request; and the token beside any SigV2 credential is the
/// claim's own refusal on that operation and on one that admits SigV2, decided before the SigV2
/// rule is reached. Without the token the same SigV2 requests keep that rule's answers, which
/// are sealed for a verifier on the operation that admits SigV2: the control that the rule, and
/// not the claim, tells the two operations apart.
#[test]
fn a_header_token_is_unaffected_by_the_sigv2_refusal_and_refuses_sigv2_beside_it() {
    let refusing = standard_op().refuse_sigv2_under_every_policy();
    assert!(refusing.refuses_sigv2_under_every_policy() && !standard_op().refuses_sigv2_under_every_policy());
    let sigv2_header: &[(&str, &str)] = &[
        ("authorization", "AWS AKIDEXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg="),
        ("date", "Sun, 30 Aug 2015 12:36:00 GMT"),
    ];
    let sigv2_query = "AWSAccessKeyId=AKIDEXAMPLE&Expires=1440938460&Signature=frJIUN8DYpKDtOLCwo%2F%2FyllqDzg%3D";
    for (floor_name, compat) in [("default", false), ("sigv2-compatible", true)] {
        let base = if compat {
            SecurityFloor::new().enable_sigv2_presigned_compatibility()
        } else {
            SecurityFloor::new()
        };
        let floor = base.clone().with_header_token_claim(claim());
        let token = with_token(&[]);
        for operation in [&refusing, &standard_op()] {
            assert_eq!(shape(&admit(&floor, &token, "", None, operation)), "header-token", "{floor_name}");
            assert!(floor.admits_header_token(operation), "{floor_name}");
            let both = with_token(sigv2_header);
            assert_eq!(shape(&admit(&floor, &both, "", None, operation)), "refused:AccessDenied", "{floor_name}");
            assert_eq!(
                shape(&admit(&floor, &token, sigv2_query, None, operation)),
                "refused:AccessDenied",
                "{floor_name}"
            );
        }
        // The controls, without the token: the claimed floor answers as an unclaimed one does.
        let alone = header_map(sigv2_header);
        let none = HeaderMap::new();
        for operation in [&refusing, &standard_op()] {
            for (headers, query) in [(&alone, ""), (&none, sigv2_query)] {
                assert_eq!(
                    shape(&admit(&floor, headers, query, None, operation)),
                    shape(&admit(&base, headers, query, None, operation)),
                    "{floor_name}: {query:?}"
                );
            }
        }
        assert_eq!(shape(&admit(&floor, &alone, "", None, &refusing)), "refused:AccessDenied", "{floor_name}");
        assert_eq!(shape(&admit(&floor, &alone, "", None, &standard_op())), "sealed-sigv2", "{floor_name}");
    }
}

// ---------------------------------------------------------------------------
// The origin of the reported name
// ---------------------------------------------------------------------------

/// Positive and negative — the kernel marks the reported name as host-reported, whatever the
/// verifier built, and that name is not the access key that shares its spelling: not equal to
/// it, and not found under it in a store keyed on `Identity`.
#[test]
fn a_reported_name_is_marked_and_is_not_the_access_key_of_the_same_spelling() {
    /// Reports a name spelled exactly like an access key, built the only way host code can.
    struct ReportsAnAccessKeySpelling;

    impl HeaderTokenVerifier for ReportsAnAccessKeySpelling {
        type Established = Established;

        fn identity(&self, established: &Established, _now: RequestNow) -> Result<Identity, HeaderTokenRefused> {
            let identity = Identity::new(established.0).map_err(|_| HeaderTokenRefused)?;
            assert_eq!(identity.origin(), IdentityOrigin::AccessKey, "host code cannot build a marked name");
            Ok(identity)
        }
    }

    let access_key = Identity::new(ACCESS_KEY).expect("a legal access key");
    assert_eq!(access_key.origin(), IdentityOrigin::AccessKey);

    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let verdict = admission_of(&floor, &with_token(&[]), &standard_op())
        .verify(&ReportsAnAccessKeySpelling, &server_state(Some(Established(ACCESS_KEY))));
    let reported = verdict.identity().expect("a header-token verdict");
    assert_eq!(reported.access_key_id(), ACCESS_KEY, "the spelling is the same");
    assert_eq!(reported.origin(), IdentityOrigin::HostToken);
    assert_eq!(
        verdict.header_token_receipt().map(|receipt| receipt.identity().origin()),
        Some(IdentityOrigin::HostToken)
    );
    assert_ne!(reported, &access_key, "a host-reported name equals no access key");

    let granted: HashSet<Identity> = HashSet::from([access_key.clone()]);
    assert!(granted.contains(&access_key), "the control: the access key finds its own entry");
    assert!(!granted.contains(reported), "the reported name found the access key's entry");
    assert!(format!("{reported:?}").contains("HostToken"), "an audit rendering tells the two apart");
}

/// Negative — no other verdict's principal is marked host-reported: a signed request's is an
/// access key.
#[test]
fn n_a_signed_principal_is_never_marked_host_reported() {
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let headers = signed_headers(SIGNED_AT);
    let operation = OperationFloor::builtin("PutObject", SigService::S3);
    assert_eq!(shape(&admit(&floor, &headers, "", None, &operation)), "sealed");
    for name in [ACCESS_KEY, PRINCIPAL] {
        assert_eq!(Identity::new(name).map(|identity| identity.origin()), Ok(IdentityOrigin::AccessKey));
    }
}
