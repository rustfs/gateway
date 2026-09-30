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

//! The dialect refreshed from RustFS main (ADR-0037), through the assembled service: the routes
//! RustFS main added are authorised by the actions RustFS gives them, the one it removed is served
//! by nothing, and the heal catch-all hands its handler every rest RustFS's router matches,
//! decoded once, refusing only what does not decode or matches nothing (ADR-0036).
//!
//! Responsible for: those assertions. NOT responsible for: every row's generic facts (`tests.rs`),
//! the bucket bindings (`bucket_tests.rs`), or routing without a service (the dialect crate's own
//! tests).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use rustfs_gateway_dialect_rustfs_admin::{ROUTES, RouteRecord};

use super::{Exchange, assemble, declared, is_catch_all, signed, templates, wire, with_segment};

const HEAL: &str = "rustfs:PostV3HealByBucketByPrefix";

fn record(operation: &str) -> &'static RouteRecord {
    ROUTES
        .iter()
        .find(|record| record.operation == operation)
        .unwrap_or_else(|| panic!("{operation} is declared"))
}

/// Every row of `record` with its catch-all spelled `rest` and its bucket `bucket-1`.
fn with_rest(record: &RouteRecord, rest: &str) -> Vec<String> {
    templates(record)
        .into_iter()
        .map(|template| {
            let index = template.split('/').position(is_catch_all).expect("a catch-all row");
            with_segment(template, Some(index), rest)
        })
        .collect()
}

fn refused_before_asking(exchange: &Exchange, at: &str, status: u16) {
    assert_eq!(exchange.status, status, "{at}: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran");
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
}

/// Positive — the heal catch-all takes the rest of the path, however many segments, dot segments,
/// encoded separators, empty segments and control characters it holds, as RustFS's router matches
/// it; the handler is handed it decoded once beside the bound bucket, and the authorizer is asked
/// `admin:Heal` about that bucket, canonical row and alias alike (ADR-0036).
#[test]
fn the_heal_catch_all_hands_its_handler_every_rest_decoded_once() {
    let heal = record(HEAL);
    let assembled = assemble(declared);
    for (rest, value) in [
        ("prefix-1", "prefix-1"),
        ("a/b/c", "a/b/c"),
        ("a%2Fb/c%20d", "a/b/c d"),
        ("%2e%2e/x", "../x"),
        ("x//y", "x//y"),
        ("/x", "/x"),
        ("x/", "x/"),
        ("a%01b", "a\u{1}b"),
        ("100%25", "100%"),
        ("%E4%BD%A0", "\u{4f60}"),
    ] {
        for path in with_rest(heal, rest) {
            let at = format!("POST {path}");
            let exchange = assembled.exchange(wire(&signed(heal, &path)));
            assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
            assert_eq!(exchange.reached, [HEAL], "{at}");
            let handed = &exchange.handed[0];
            assert_eq!(
                handed.params,
                [
                    ("bucket".to_owned(), "bucket-1".to_owned()),
                    ("prefix".to_owned(), value.to_owned())
                ],
                "{at}"
            );
            assert_eq!(handed.bucket.as_deref(), Some("bucket-1"), "{at}");
            assert!(!handed.holds_secret, "{at}");
            assert!(!exchange.asked.is_empty(), "{at}");
            for asked in &exchange.asked {
                assert_eq!((asked.action.as_str(), asked.bucket.as_deref()), ("admin:Heal", Some("bucket-1")), "{at}");
            }
        }
    }
}

/// Negative — the heal catch-all refuses before the authorizer is asked exactly what RustFS's
/// router matches nothing for or what does not decode: an empty rest is the claim's `501`; a rest
/// that is not UTF-8 is a `400 InvalidArgument` naming `prefix` without echoing it; and the bucket
/// beside it keeps the S3 name rules (`400 InvalidBucketName`) and the one-segment rule (`501`).
#[test]
fn n_the_heal_catch_all_refuses_only_an_empty_rest_or_what_does_not_decode() {
    let heal = record(HEAL);
    let assembled = assemble(declared);
    for path in with_rest(heal, "") {
        refused_before_asking(&assembled.exchange(wire(&signed(heal, &path))), &format!("POST {path}"), 501);
    }
    for raw in ["%ff", "ok/%c3%28", "%ED%A0%80"] {
        for path in with_rest(heal, raw) {
            let at = format!("POST {path}");
            let exchange = assembled.exchange(wire(&signed(heal, &path)));
            refused_before_asking(&exchange, &at, 400);
            assert!(exchange.body.contains("<Code>InvalidArgument</Code>"), "{at}: {}", exchange.body);
            assert!(exchange.body.contains("prefix"), "{at}: {}", exchange.body);
            assert!(!exchange.body.contains(raw), "{at}: the value is echoed: {}", exchange.body);
        }
    }
    for template in templates(heal) {
        let bucket = template
            .split('/')
            .position(|segment| segment == "{bucket}")
            .expect("a bound bucket");
        for (raw, status) in [("Bad_Bucket", 400), ("%2e%2e", 501), ("a%2Fb", 501)] {
            let path = with_segment(template, Some(bucket), raw);
            let at = format!("POST {path}");
            let exchange = assembled.exchange(wire(&signed(heal, &path)));
            refused_before_asking(&exchange, &at, status);
            if status == 400 {
                assert!(exchange.body.contains("<Code>InvalidBucketName</Code>"), "{at}: {}", exchange.body);
            }
        }
    }
}

/// Positive and negative — every route RustFS main added is served, on each of its rows, and asked
/// exactly the action RustFS's route policy gives it, about its bound bucket or none; the
/// `v3/metrics` route RustFS renamed to `v3/realtime` is served by nothing, canonical and alias
/// alike, and answered by the claim before the authorizer is asked (ADR-0037).
#[test]
fn the_routes_rustfs_main_added_are_served_and_the_one_it_removed_is_not() {
    let assembled = assemble(declared);
    for (operation, action, bucket) in [
        ("rustfs:GetV3IntegrityReadiness", "admin:ServerInfo", None),
        ("rustfs:GetV3IntegrityByBucketInventory", "admin:InspectData", Some("bucket-1")),
        ("rustfs:PostV3IntegrityByBucketJobs", "admin:StartBatchJob", Some("bucket-1")),
        ("rustfs:GetV3IntegrityByBucketJobsByJobId", "admin:DescribeBatchJob", Some("bucket-1")),
        (
            "rustfs:PostV3IntegrityByBucketJobsByJobIdControl",
            "admin:StartBatchJob",
            Some("bucket-1"),
        ),
        ("rustfs:GetV3Realtime", "admin:GetMetrics", None),
        ("rustfs:GetV3TargetByTargetTypeByTargetNameSubscriptions", "admin:GetBucketTarget", None),
        (
            "rustfs:PostIcebergByWarehouseCatalogWarehouseIndexBackfill",
            "admin:MigrateTableCatalog",
            Some("warehouse-1"),
        ),
    ] {
        let record = record(operation);
        for template in templates(record) {
            let path = with_segment(template, None, "");
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(wire(&signed(record, &path)));
            assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
            assert_eq!(exchange.reached, [operation], "{at}");
            let asked: Vec<(&str, Option<&str>)> = exchange
                .asked
                .iter()
                .filter(|asked| asked.stage == "route")
                .map(|asked| (asked.action.as_str(), asked.bucket.as_deref()))
                .collect();
            assert_eq!(asked, [(action, bucket)], "{at}");
        }
    }
    let realtime = record("rustfs:GetV3Realtime");
    for path in ["/rustfs/admin/v3/metrics", "/minio/admin/v3/metrics"] {
        refused_before_asking(&assembled.exchange(wire(&signed(realtime, path))), &format!("GET {path}"), 501);
    }
}
