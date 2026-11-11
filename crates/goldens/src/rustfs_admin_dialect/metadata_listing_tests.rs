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

//! RustFS's two metadata listings (rustfs/gateway#1588) through the assembled service, on the
//! default floor and on the RustFS profile's, which delegates anonymous requests to the
//! authorizer and admits a presigned URL on every standard operation.
//!
//! Responsible for: a signed listing asked exactly its listing action on the bucket, for the
//! caller, before its handler; an unsigned listing refused without asking on the default floor
//! and asked as an anonymous caller on the profile floor, as a standard listing is (ADR-0050), and
//! refused before the handler when the authorizer — the bucket policy — does not allow it, or
//! allows only another action; a presigned listing refused without asking on the default floor
//! and asked on the profile floor; `metadata=true` appended to a SigV4 presigned standard listing
//! refused without asking; the SigV2 property, both directions, presigned and header-signed (an
//! appended `metadata=true` is outside SigV2's signed keys and selects the metadata listing for the
//! signer wherever that SigV2 form is admitted, ADR-0050); and a trailing-slash bucket path.
//! NOT responsible for: routing without a service (the dialect crate's `metadata_listing`), the
//! admin router's eight rows (`super::extension_tests`), or the harness (`super`).
//! Upstream: `super`, `super::extension_tests`. Downstream: nothing.

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use rustfs_gateway::SecurityFloor;
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionRouteRecord};
use rustfs_gateway_sig::{RawQuery, RequestNow, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

use super::extension_tests::{
    presign_at, presigned, query, refused_before_the_handler, refused_without_asking, route_question, signed, unsigned,
    unsigned_at,
};
use super::lambda_tests::rfc1123;
use super::{BUCKET, Exchange, assemble_on, rustfs_profile_floor, wire};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST, SECRET_KEY};

/// The metadata route's two listing operations, versions first, as the dialect declares them.
pub(super) const LISTINGS: [&str; 2] = ["rustfs:ListObjectVersionsWithMetadata", "rustfs:ListObjectsV2WithMetadata"];

/// The two listing records.
fn listings() -> Vec<&'static ExtensionRouteRecord> {
    let records: Vec<&ExtensionRouteRecord> = EXTENSION_ROUTES
        .iter()
        .filter(|record| LISTINGS.contains(&record.operation))
        .collect();
    assert_eq!(records.len(), 2);
    records
}

/// The listing action `record` is authorised by, and the other listing's.
fn actions(record: &ExtensionRouteRecord) -> (&'static str, &'static str) {
    match record.action {
        "s3:ListBucket" => ("s3:ListBucket", "s3:ListBucketVersions"),
        "s3:ListBucketVersions" => ("s3:ListBucketVersions", "s3:ListBucket"),
        other => panic!("{}: not a listing action {other:?}", record.operation),
    }
}

/// The two floors: the default and the RustFS profile's.
fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default floor", SecurityFloor::new()),
        ("RustFS profile floor", rustfs_profile_floor()),
    ]
}

/// Positive — a signed listing is asked exactly its listing action on the bucket for the caller and
/// reaches its handler with that bucket, on both floors.
#[test]
fn a_signed_listing_is_asked_its_listing_action_on_the_bucket() {
    for (at, floor) in floors() {
        for record in listings() {
            let (action, _) = actions(record);
            let assembled = assemble_on(floor.clone(), move |_, asked| asked == action);
            let exchange = assembled.exchange(signed(record));
            assert_eq!(exchange.status, 200, "{at} {}: {}", record.operation, exchange.body);
            assert_eq!(exchange.reached, [record.operation], "{at}");
            let asked = route_question(&exchange, record);
            assert_eq!((asked.action.as_str(), asked.caller.as_deref()), (action, Some(ACCESS_KEY)), "{at}");
            assert_eq!((asked.bucket.as_deref(), asked.key.as_deref()), (Some(BUCKET), None), "{at}");
            assert_eq!(exchange.handed[0].bucket.as_deref(), Some(BUCKET), "{at}");
            assert!(!exchange.handed[0].holds_secret, "{at}");
        }
    }
}

/// Positive — on the RustFS profile's floor an unsigned listing is asked its listing action as an
/// anonymous caller, and reaches its handler when the bucket policy allows it, as a standard
/// listing does (RustFS's metadata route keeps the caller anonymous for its bucket policy check).
#[test]
fn an_unsigned_listing_is_the_authorizers_on_the_profile_floor() {
    for record in listings() {
        let (action, _) = actions(record);
        let assembled = assemble_on(rustfs_profile_floor(), move |_, asked| asked == action);
        let exchange = assembled.exchange(unsigned(record));
        assert_eq!(exchange.status, 200, "{}: {}", record.operation, exchange.body);
        assert_eq!(exchange.reached, [record.operation]);
        let asked = route_question(&exchange, record);
        assert_eq!((asked.action.as_str(), asked.caller.as_deref()), (action, None), "{}", record.operation);
        assert_eq!(asked.bucket.as_deref(), Some(BUCKET), "{}", record.operation);
    }
}

/// Negative — an unsigned listing is refused without asking on the default floor, which delegates
/// no anonymous request, even with an authorizer that allows everything.
#[test]
fn n_an_unsigned_listing_is_refused_without_asking_on_the_default_floor() {
    let assembled = assemble_on(SecurityFloor::new(), |_, _| true);
    for record in listings() {
        refused_without_asking(&assembled.exchange(unsigned(record)), record.operation);
    }
}

/// Negative — an anonymous listing the bucket policy does not allow is refused before the handler
/// on the profile floor, after asking exactly its listing action.
#[test]
fn n_an_unsigned_listing_without_a_policy_is_refused_before_its_handler() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| false);
    for record in listings() {
        let exchange = assembled.exchange(unsigned(record));
        refused_before_the_handler(&exchange, record.operation);
        assert_eq!(route_question(&exchange, record).action, actions(record).0, "{}", record.operation);
    }
}

/// Negative — a policy that allows only the other listing action, or every action but this one,
/// does not authorise the listing, signed or anonymous.
#[test]
fn n_another_action_does_not_authorise_a_listing() {
    for record in listings() {
        let (action, other) = actions(record);
        for (at, assembled) in [
            (
                "only the other listing",
                assemble_on(rustfs_profile_floor(), move |_, asked| asked == other),
            ),
            ("everything else", assemble_on(rustfs_profile_floor(), move |_, asked| asked != action)),
        ] {
            for request in [signed(record), unsigned(record)] {
                let exchange = assembled.exchange(request);
                refused_before_the_handler(&exchange, &format!("{at} {}", record.operation));
                assert_eq!(route_question(&exchange, record).action, action, "{at}");
            }
        }
    }
}

/// Negative — a signed listing whose action is denied is refused before its handler on both floors.
#[test]
fn n_a_signed_listing_whose_action_is_denied_is_refused_before_its_handler() {
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| false);
        for record in listings() {
            let exchange = assembled.exchange(signed(record));
            refused_before_the_handler(&exchange, at);
            assert_eq!(route_question(&exchange, record).action, actions(record).0, "{at}");
        }
    }
}

/// Positive and negative — a presigned listing is refused without asking on the default floor,
/// which admits presigned URLs per operation only, and asked on the profile floor, which admits
/// them on every standard operation: exactly where a presigned standard listing is admitted.
#[test]
fn a_presigned_listing_is_admitted_exactly_where_a_standard_one_is() {
    let refusing = assemble_on(SecurityFloor::new(), |_, _| true);
    let admitting = assemble_on(rustfs_profile_floor(), |_, _| true);
    for record in listings() {
        refused_without_asking(&refusing.exchange(presigned(record)), record.operation);
        let exchange = admitting.exchange(presigned(record));
        assert_eq!(exchange.status, 200, "{}: {}", record.operation, exchange.body);
        let asked = route_question(&exchange, record);
        assert_eq!((asked.action.as_str(), asked.caller.as_deref()), (actions(record).0, Some(ACCESS_KEY)));
    }
}

/// Negative — `metadata=true` appended to a SigV4 presigned standard listing URL after it was
/// signed is outside the signature, because SigV4 signs every query pair: the request routes to
/// the metadata listing and is refused without asking, so a shared SigV4 listing URL cannot be
/// widened into one that discloses user metadata. A SigV2 URL can be; see the SigV2 tests below.
#[test]
fn n_metadata_true_appended_to_a_presigned_listing_is_refused_without_asking() {
    let assembled = assemble_on(rustfs_profile_floor(), |_, _| true);
    for record in listings() {
        let standard = query(record).replace("&metadata=true", "");
        let now = RequestNow::capture().unix_seconds();
        let signed = presign_at(&Method::GET, &format!("/{BUCKET}"), &standard, now, 900);
        let uri = format!("{}&metadata=true", signed.uri());
        let mut appended = unsigned_at("GET", &uri);
        *appended.headers_mut() = signed.headers().clone();
        refused_without_asking(&assembled.exchange(appended), record.operation);
    }
}

/// `GET /{bucket}?{query}` presigned with SigV2 by the shared credential, valid for ten minutes,
/// with `extra` appended to the URL after signing.
fn sigv2_presigned(query: &str, extra: &str) -> Request<Bytes> {
    let path = format!("/{BUCKET}");
    let expires = RequestNow::capture().unix_seconds() + 600;
    let signed_query = format!("{query}&AWSAccessKeyId={ACCESS_KEY}&Expires={expires}");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_str(PATH_HOST).expect("a host"));
    let raw = RawQuery::new(&signed_query);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &Method::GET, &path, &raw, &headers, None);
    let signature = SigV2Signer::new(ACCESS_KEY, SECRET_KEY.as_bytes())
        .expect("a signer")
        .presigned_signature(&spec)
        .expect("a signable request");
    let escaped = signature.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
    unsigned_at("GET", &format!("{path}?{signed_query}&Signature={escaped}{extra}"))
}

/// `GET /{bucket}?{query}` header-signed with SigV2 by the shared credential, now, with `extra`
/// appended to the URL after signing: a captured header-signed request rewritten inside the
/// clock-skew window.
fn sigv2_header_signed(query: &str, extra: &str) -> Request<Bytes> {
    let path = format!("/{BUCKET}");
    let mut request = unsigned_at("GET", &format!("{path}?{query}"));
    let date = rfc1123(RequestNow::capture().unix_seconds());
    request
        .headers_mut()
        .insert(http::header::DATE, HeaderValue::from_str(&date).expect("a date"));
    let raw = RawQuery::new(query);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, &path, &raw, request.headers(), None);
    let authorization = SigV2Signer::new(ACCESS_KEY, SECRET_KEY.as_bytes())
        .expect("a signer")
        .authorization(&spec)
        .expect("a signable request");
    let mut rewritten = unsigned_at("GET", &format!("{path}?{query}{extra}"));
    *rewritten.headers_mut() = request.headers().clone();
    rewritten
        .headers_mut()
        .insert(http::header::AUTHORIZATION, HeaderValue::from_str(&authorization).expect("a credential"));
    rewritten
}

/// Asserts the exchange reached `operation` and asked exactly the listing action on the bucket
/// for the signing caller: never another action and never anonymous.
fn asked_as_the_signer(exchange: &Exchange, operation: &str, action: &str, at: &str) {
    assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
    assert_eq!(exchange.reached, [operation], "{at}");
    let asked = exchange
        .asked
        .iter()
        .find(|asked| asked.stage == "route")
        .unwrap_or_else(|| panic!("{at}: no route question"));
    assert_eq!(
        (
            asked.operation.as_str(),
            asked.action.as_str(),
            asked.caller.as_deref(),
            asked.bucket.as_deref()
        ),
        (operation, action, Some(ACCESS_KEY), Some(BUCKET)),
        "{at}"
    );
}

/// Positive and negative — a SigV2 presigned listing is refused without asking on the default
/// floor, which accepts no SigV2 presigned URL, and asked its listing action for the presigning
/// caller on the RustFS profile's floor, which accepts them on every standard operation: exactly
/// where a SigV2 presigned standard listing is admitted (`SecurityFloor::enforce_scheme_allowed`
/// asks the same four questions of both floors). RustFS's metadata route takes the credential
/// s3s verified, SigV2 presigned included, and refuses no signature family itself (ADR-0050).
#[test]
fn a_sigv2_presigned_listing_is_admitted_exactly_where_a_standard_one_is() {
    let refusing = assemble_on(SecurityFloor::new(), |_, _| true);
    let admitting = assemble_on(rustfs_profile_floor(), |_, _| true);
    for record in listings() {
        let request = || sigv2_presigned(&query(record), "");
        refused_without_asking(&refusing.exchange(request()), record.operation);
        asked_as_the_signer(&admitting.exchange(request()), record.operation, actions(record).0, "profile");
    }
}

/// Positive and negative — SigV2 signs only its fixed sub-resource keys, and neither `metadata` nor
/// `list-type` is one. So `metadata=true` appended to a SigV2 presigned listing URL is covered by
/// nothing the signature covers: on the RustFS profile's floor the request becomes the metadata
/// listing, asked the listing action on the same bucket for the presigner, and the holder of the
/// URL obtains every object's user metadata, which the presigner never signed for (ADR-0050; the
/// SigV2 refusal planned after rustfs/gateway#1592 removes it). On the default floor, which accepts
/// no SigV2 presigned URL, the same request is refused without asking.
#[test]
fn metadata_true_appended_to_a_sigv2_presigned_listing_is_admitted_only_where_sigv2_presigned_is() {
    let refusing = assemble_on(SecurityFloor::new(), |_, _| true);
    let admitting = assemble_on(rustfs_profile_floor(), |_, _| true);
    for (signed, operation, action) in [
        ("list-type=2", LISTINGS[1], "s3:ListBucket"),
        ("versions", LISTINGS[0], "s3:ListBucketVersions"),
    ] {
        let request = || sigv2_presigned(signed, "&metadata=true");
        asked_as_the_signer(&admitting.exchange(request()), operation, action, signed);
        refused_without_asking(&refusing.exchange(request()), signed);
    }
}

/// Positive — the header form of the same edit: a captured SigV2 header-signed listing, rewritten
/// with `metadata=true` inside the clock-skew window, still verifies, because the header string to
/// sign covers the same sub-resource keys only. SigV2 header authentication is accepted by the
/// default floor (`SigV2Policy::HeaderOnly`, `docs/security-model.md`) as well as by the RustFS
/// profile's, so on both the request becomes the metadata listing, asked the listing action for the
/// signer (ADR-0050; removed by the SigV2 refusal planned after rustfs/gateway#1592).
#[test]
fn metadata_true_appended_to_a_sigv2_header_signed_listing_is_the_signers_metadata_listing() {
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| true);
        for (signed, operation, action) in [
            ("list-type=2", LISTINGS[1], "s3:ListBucket"),
            ("versions", LISTINGS[0], "s3:ListBucketVersions"),
        ] {
            let request = sigv2_header_signed(signed, "&metadata=true");
            asked_as_the_signer(&assembled.exchange(request), operation, action, &format!("{at} {signed}"));
        }
    }
}

/// Negative — the header-signed edit is still bounded by what SigV2 does sign: adding the signed
/// `versions` key after signing, or a forged `Authorization`, is refused without asking on both
/// floors.
#[test]
fn n_a_sigv2_header_signed_listing_with_a_signed_key_added_is_refused_without_asking() {
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| true);
        let added = sigv2_header_signed("list-type=2", "&versions&metadata=true");
        refused_without_asking(&assembled.exchange(added), &format!("{at}: versions added"));
        let mut forged = sigv2_header_signed("list-type=2", "&metadata=true");
        forged.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("AWS {ACCESS_KEY}:AAAA")).expect("a value"),
        );
        refused_without_asking(&assembled.exchange(forged), &format!("{at}: forged"));
    }
}

/// Positive and negative — through the service, one trailing slash still addresses the bucket, so
/// `/{bucket}/?list-type=2&metadata=true` is the metadata listing, as on RustFS. Two slashes
/// address an object, whose operation this assembly does not register: `501` before any handler,
/// never the listing. RustFS trims every slash and would serve the listing there; that difference
/// is in the pull request's ledger.
#[test]
fn a_trailing_slash_bucket_path_is_the_listing_and_a_double_slash_is_an_object() {
    let assembled = assemble_on(SecurityFloor::new(), |_, _| true);
    let request = |path: &str| wire(&ContextRequest::get(PATH_HOST, path, "list-type=2&metadata=true").signed(super::REGION));
    asked_as_the_signer(
        &assembled.exchange(request(&format!("/{BUCKET}/"))),
        LISTINGS[1],
        "s3:ListBucket",
        "one trailing slash",
    );
    let double = assembled.exchange(request(&format!("/{BUCKET}//")));
    assert_eq!(double.status, 501, "{}", double.body);
    assert!(double.reached.is_empty() && double.asked.is_empty(), "{double:?}");
}
