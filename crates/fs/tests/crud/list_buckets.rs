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

//! Signed production-service evidence for `ListBuckets` (rustfs/gateway#721).
//!
//! Responsible for: the byte-ordered bucket census, the configured owner, prefix and region
//! filters, `max-buckets` paging with a minted cursor, and the refusals of a foreign cursor and an
//! out-of-range page size.
//! NOT responsible for: the cursor's wire-form rules, which the framework applies before the
//! handler runs.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

fn names(body: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(body).expect("a UTF-8 listing");
    text.split("<Name>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</Name>").map(|(name, _)| name.to_owned()))
        .collect()
}

async fn list(service: &S3Service, target: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

async fn fixture(root: &TestRoot) -> S3Service {
    let (_, service) = service(root);
    for bucket in ["photos", "archive", "photo-drafts", "logs"] {
        create_bucket(&service, bucket).await;
    }
    service
}

/// Positive — every bucket is listed once, in byte order, with a creation date.
#[tokio::test]
async fn every_bucket_is_listed_in_byte_order() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    let listed = list(&service, "/").await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert_eq!(names(listed.body()), ["archive", "logs", "photo-drafts", "photos"]);
    let text = String::from_utf8_lossy(listed.body());
    assert!(text.contains("<ListAllMyBucketsResult"), "{text}");
    assert_eq!(text.matches("<CreationDate>").count(), 4, "{text}");
    assert!(
        element(listed.body(), "ContinuationToken").is_none(),
        "a complete listing carries no cursor"
    );
}

/// Positive — the configured data-root owner is reported, escaped by the encoder.
#[tokio::test]
async fn the_configured_owner_is_reported() {
    let root = TestRoot::new();
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(rustfs_gateway::FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root")
            .with_owner("owner-id", "Owner & Co"),
    );
    let (_, service) = service_with_backend(backend);
    create_bucket(&service, "owned").await;
    let listed = list(&service, "/").await;
    assert_eq!(element(listed.body(), "ID").as_deref(), Some("owner-id"));
    assert_eq!(element(listed.body(), "DisplayName").as_deref(), Some("Owner &amp; Co"));
}

/// Negative — a deleted bucket is not listed, and an empty root lists nothing.
#[tokio::test]
async fn a_deleted_bucket_is_not_listed() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    assert!(names(list(&service, "/").await.body()).is_empty());
    create_bucket(&service, "short-lived").await;
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/short-lived", Bytes::new()))
            .await
            .status(),
        204
    );
    assert!(names(list(&service, "/").await.body()).is_empty());
}

/// Negative — a prefix keeps only the buckets it begins, and echoes itself.
#[tokio::test]
async fn a_prefix_filters_the_census() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    let listed = list(&service, "/?prefix=photo").await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert_eq!(names(listed.body()), ["photo-drafts", "photos"]);
    assert_eq!(element(listed.body(), "Prefix").as_deref(), Some("photo"));
}

/// Negative — a region filter naming another region matches nothing; the served one matches all.
#[tokio::test]
async fn a_foreign_region_filter_matches_nothing() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    assert!(names(list(&service, "/?bucket-region=eu-west-1").await.body()).is_empty());
    assert_eq!(names(list(&service, "/?bucket-region=us-east-1").await.body()).len(), 4);
}

/// Positive — `max-buckets` pages the census, and the minted cursor resumes after the last entry.
#[tokio::test]
async fn max_buckets_pages_with_a_minted_cursor() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    let first = list(&service, "/?max-buckets=3").await;
    assert_eq!(first.status(), 200, "{}", String::from_utf8_lossy(first.body()));
    assert_eq!(names(first.body()), ["archive", "logs", "photo-drafts"]);
    let token = element(first.body(), "ContinuationToken").expect("a truncated page carries a cursor");
    assert!(!token.contains("photo"), "the cursor is opaque, not a bucket name");
    let second = list(&service, &format!("/?max-buckets=3&continuation-token={token}")).await;
    assert_eq!(second.status(), 200, "{}", String::from_utf8_lossy(second.body()));
    assert_eq!(names(second.body()), ["photos"]);
    assert!(element(second.body(), "ContinuationToken").is_none());
}

/// Negative — a cursor this listing never minted is refused rather than read as a position.
#[tokio::test]
async fn a_foreign_cursor_is_refused() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    let refused = list(&service, "/?continuation-token=photos").await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — a cursor minted under one prefix does not resume a listing under another.
#[tokio::test]
async fn a_cursor_is_scoped_to_its_prefix() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    let first = list(&service, "/?max-buckets=1&prefix=photo").await;
    let token = element(first.body(), "ContinuationToken").expect("a truncated page carries a cursor");
    let refused = list(&service, &format!("/?max-buckets=1&continuation-token={token}")).await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
}

/// Negative — a page size outside 1..=10000 is refused.
#[tokio::test]
async fn an_out_of_range_page_size_is_refused() {
    let root = TestRoot::new();
    let service = fixture(&root).await;
    for size in ["0", "10001", "-1"] {
        let refused = list(&service, &format!("/?max-buckets={size}")).await;
        assert_eq!(refused.status(), 400, "{size}: {}", String::from_utf8_lossy(refused.body()));
    }
}
