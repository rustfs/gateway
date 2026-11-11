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
//! and asked on the profile floor; and a `metadata=true` appended to a presigned standard listing
//! URL after it was signed refused without asking.
//! NOT responsible for: routing without a service (the dialect crate's `metadata_listing`), the
//! admin router's eight rows (`super::extension_tests`), or the harness (`super`).
//! Upstream: `super`, `super::extension_tests`. Downstream: nothing.

use http::Method;
use rustfs_gateway::SecurityFloor;
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionRouteRecord};
use rustfs_gateway_sig::RequestNow;

use super::extension_tests::{
    presign_at, presigned, query, refused_before_the_handler, refused_without_asking, route_question, signed, unsigned,
    unsigned_at,
};
use super::{BUCKET, assemble_on, rustfs_profile_floor};
use crate::operation_diff::s3s_0_17_0::context::ACCESS_KEY;

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

/// Negative — `metadata=true` appended to a presigned standard listing URL after it was signed is
/// outside the signature: the request routes to the metadata listing and is refused without
/// asking, so a shared listing URL cannot be widened into one that discloses user metadata.
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
