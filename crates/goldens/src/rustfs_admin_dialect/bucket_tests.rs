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

//! The order-5 bucket bindings through the assembled service (ADR-0030): a `{bucket}` template
//! parameter or a `bucket` query parameter is the bucket every question and the handler see, an
//! invalid one is refused exactly as `/{bucket}` is, a missing or repeated query bucket is refused
//! before authentication, a denial names the bucket, and the trailing-slash heal row is reached
//! by exactly its path.
//!
//! Responsible for: the assertions on every bucket-bound row of the generated dialect.
//! NOT responsible for: the harness (`super`), what every row is authorised by (`tests.rs`, which
//! also checks each row's bucket), or the hand-written proof of the mechanism itself
//! (`rustfs_admin_proof`).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use rustfs_gateway_core::dialect::BucketParam;
use rustfs_gateway_dialect_rustfs_admin::{ROUTES, RouteRecord};

use super::{
    BUCKET, Exchange, assemble, bucket_query_param, concrete, expected_bucket, in_lanes, signed, signed_with, templates, wire,
    with_segment,
};

/// Names S3 refuses as `/{bucket}`: too short, an uppercase letter and an underscore, an escaped
/// spelling, an IP address, adjacent dots, a leading hyphen, and 64 characters.
fn invalid_buckets() -> Vec<String> {
    vec![
        "ab".to_owned(),
        "Bad_Bucket".to_owned(),
        "%70hotos".to_owned(),
        "192.168.1.1".to_owned(),
        "a..b".to_owned(),
        "-photos".to_owned(),
        "a".repeat(64),
    ]
}

/// Every record whose bucket is a template parameter, with the index of that segment in each of
/// its templates.
fn path_bound() -> Vec<(&'static RouteRecord, &'static str, usize)> {
    ROUTES
        .iter()
        .filter(|record| matches!(record.bucket, Some(BucketParam::Path(_))))
        .flat_map(|record| {
            templates(record).into_iter().map(move |template| {
                let index = template
                    .split('/')
                    .position(|segment| segment == "{bucket}" || segment == "{warehouse}")
                    .expect("a bound template carries {bucket} or {warehouse}");
                (record, template, index)
            })
        })
        .collect()
}

/// Every record whose bucket is a query parameter, with each of its templates.
fn query_bound() -> Vec<(&'static RouteRecord, &'static str)> {
    ROUTES
        .iter()
        .filter(|record| bucket_query_param(record).is_some())
        .flat_map(|record| templates(record).into_iter().map(move |template| (record, template)))
        .collect()
}

fn refused_before_authorising(exchange: &Exchange, at: &str, code: &str) {
    assert_eq!(exchange.status, 400, "{at}: {}", exchange.body);
    // A HEAD response carries no body to read the code from.
    assert!(
        at.starts_with("HEAD ") || exchange.body.contains(&format!("<Code>{code}</Code>")),
        "{at}: {}",
        exchange.body
    );
    assert!(exchange.reached.is_empty(), "{at}: a handler ran");
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
}

/// Positive — the recorded dialect binds exactly twenty-one `{bucket}` and 49 `{warehouse}` template
/// buckets and two query buckets, each on two rows, all of orders 5 and 6.
#[test]
fn the_bound_rows_are_the_order_five_and_six_ones() {
    let by_path = path_bound();
    let by_query = query_bound();
    assert_eq!((by_path.len(), by_query.len()), (140, 4));
    assert!(by_path.iter().all(|(record, ..)| matches!(record.order, 5 | 6)));
    assert_eq!(by_path.iter().filter(|(record, ..)| record.order == 6).count(), 98);
    assert!(by_query.iter().all(|(record, _)| record.order == 5));
    let queried: Vec<&str> = by_query.iter().map(|(_, template)| *template).collect();
    assert_eq!(
        queried,
        [
            "/rustfs/admin/v3/get-bucket-quota",
            "/minio/admin/v3/get-bucket-quota",
            "/rustfs/admin/v3/set-bucket-quota",
            "/minio/admin/v3/set-bucket-quota",
        ]
    );
}

/// Negative — a template bucket S3 would refuse as `/{bucket}` is refused here with the same
/// `400 InvalidBucketName`, an escaped spelling included, before the authorizer is asked or a
/// handler runs; canonical row and alias alike.
#[test]
fn n_an_invalid_template_bucket_is_refused_as_s3_refuses_it() {
    let cases: Vec<_> = path_bound()
        .into_iter()
        .flat_map(|(record, template, index)| {
            invalid_buckets()
                .into_iter()
                .map(move |bucket| (record, with_segment(template, Some(index), &bucket), bucket))
        })
        .collect();
    assert_eq!(cases.len(), 140 * 7);
    in_lanes(
        |_, _| true,
        &cases,
        |assembled, (record, path, bucket)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(wire(&signed(record, path)));
            refused_before_authorising(&exchange, &at, "InvalidBucketName");
            assert!(!exchange.body.contains(bucket.as_str()) || bucket.len() < 8, "{at}: {}", exchange.body);
        },
    );
}

/// Negative — a query bucket S3 would refuse as `/{bucket}` is refused the same way, before the
/// authorizer is asked; and an absent or empty `bucket` is a `400 InvalidArgument` naming the
/// parameter, where RustFS refuses only an empty one, after authorisation (ADR-0026 (e),
/// ADR-0030). A repeated `bucket` cannot be signed today, so it fails closed at the signature
/// like a repeated account (ADR-0026 (d)); `n_a_repeated_query_bucket_cannot_be_signed_today`.
#[test]
fn n_a_missing_or_invalid_query_bucket_is_refused_before_authorising() {
    let invalid: Vec<_> = query_bound()
        .into_iter()
        .flat_map(|(record, template)| {
            invalid_buckets()
                .into_iter()
                .map(move |bucket| (record, concrete(template), format!("bucket={bucket}"), "InvalidBucketName"))
        })
        .collect();
    let malformed: Vec<_> = query_bound()
        .into_iter()
        .flat_map(|(record, template)| {
            [String::new(), "bucket=".to_owned()]
                .into_iter()
                .map(move |query| (record, concrete(template), query, "InvalidArgument"))
        })
        .collect();
    let cases: Vec<_> = invalid.into_iter().chain(malformed).collect();
    assert_eq!(cases.len(), 4 * 7 + 4 * 2);
    in_lanes(
        |_, _| true,
        &cases,
        |assembled, (record, path, query, code)| {
            let at = format!("{} {path}?{query}", record.method);
            let exchange = assembled.exchange(wire(&signed_with(record, path, query)));
            refused_before_authorising(&exchange, &at, code);
            if *code == "InvalidArgument" {
                assert!(exchange.body.contains("bucket"), "{at}: {}", exchange.body);
            }
        },
    );
}

/// Negative — a signed request cannot repeat `bucket` today: SigV4 canonicalisation refuses the
/// duplicate before anything reads it, so naming two buckets fails closed at the signature, as a
/// repeated account does (ADR-0026 (d)). The gateway never sees a first-of-two bucket, where RustFS
/// reads the first.
#[test]
fn n_a_repeated_query_bucket_cannot_be_signed_today() {
    for (record, template) in query_bound() {
        let path = concrete(template);
        for query in [
            format!("bucket={BUCKET}&bucket={BUCKET}"),
            format!("bucket={BUCKET}&bucket=other-1"),
        ] {
            let request = signed_with(record, &path, &query);
            let refused = request.wire_headers(rustfs_gateway_sig::RequestNow::capture());
            assert!(refused.is_err(), "{} {path}?{query}: signed a repeated bucket", record.method);
        }
    }
}

/// Negative — a caller denied the action on the bound bucket is refused before the handler, and
/// the route question named that bucket, so a deployment's policy can decide per bucket; for the
/// table catalog, per warehouse (ADR-0031 (c)).
#[test]
fn n_a_denial_on_the_bound_bucket_names_the_bucket() {
    let cases: Vec<_> = path_bound()
        .into_iter()
        .map(|(record, template, _)| (record, concrete(template)))
        .chain(
            query_bound()
                .into_iter()
                .map(|(record, template)| (record, concrete(template))),
        )
        .collect();
    assert_eq!(cases.len(), 144);
    in_lanes(
        |_, _| false,
        &cases,
        |assembled, (record, path)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(wire(&signed(record, path)));
            assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
            assert!(exchange.reached.is_empty(), "{at}: a handler ran");
            let route: Vec<_> = exchange.asked.iter().filter(|asked| asked.stage == "route").collect();
            assert!(!route.is_empty(), "{at}: the authorizer was not asked");
            let bucket = expected_bucket(record);
            assert!(route.iter().all(|asked| asked.bucket == bucket && asked.key.is_none()), "{at}: {route:?}");
        },
    );
}

/// Positive and negative — RustFS registers `POST heal/` with its trailing `/`: exactly that path
/// reaches the operation, about no bucket; the path without the `/` names no operation inside the
/// claim, as in RustFS; and a bucket after it is the bound `heal/{bucket}` row (ADR-0030).
#[test]
fn the_trailing_slash_heal_row_is_reached_by_exactly_its_path() {
    let heal = ROUTES
        .iter()
        .find(|record| record.operation == "rustfs:PostV3Heal")
        .expect("the heal row");
    let by_bucket = ROUTES
        .iter()
        .find(|record| record.operation == "rustfs:PostV3HealByBucket")
        .expect("the heal-by-bucket row");
    let assembled = assemble(|_, _| true);
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        let exact = assembled.exchange(wire(&signed(heal, &format!("{prefix}/v3/heal/"))));
        assert_eq!(exact.status, 200, "{prefix}: {}", exact.body);
        assert_eq!(exact.reached, ["rustfs:PostV3Heal"], "{prefix}");
        assert_eq!(exact.handed[0].bucket, None, "{prefix}");
        assert!(exact.asked.iter().all(|asked| asked.bucket.is_none()), "{prefix}: {:?}", exact.asked);

        let without = assembled.exchange(wire(&signed(heal, &format!("{prefix}/v3/heal"))));
        assert_eq!(without.status, 501, "{prefix}: {}", without.body);
        assert_eq!(without.reached, ["rustfs:AdminFallback"], "{prefix}");
        super::fallback_tests::assert_general_fallback_policy(&without, prefix);

        let doubled = assembled.exchange(wire(&signed(heal, &format!("{prefix}/v3/heal//"))));
        assert_eq!(doubled.status, 501, "{prefix}: {}", doubled.body);
        assert_eq!(doubled.reached, ["rustfs:AdminFallback"], "{prefix}");
        super::fallback_tests::assert_general_fallback_policy(&doubled, prefix);

        let bucket = assembled.exchange(wire(&signed(by_bucket, &format!("{prefix}/v3/heal/{BUCKET}"))));
        assert_eq!(bucket.status, 200, "{prefix}: {}", bucket.body);
        assert_eq!(bucket.reached, ["rustfs:PostV3HealByBucket"], "{prefix}");
        assert_eq!(bucket.handed[0].bucket.as_deref(), Some(BUCKET), "{prefix}");
    }
}
