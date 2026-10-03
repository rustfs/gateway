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

//! `x-amz-expiration` on `PutObject`, `HeadObject` and `GetObject`, as AWS and legacy RustFS
//! answer it (rustfs/gateway#999; s3-tests `test_lifecycle_expiration_header_put`, `_head`,
//! `_tags_head`).
//!
//! Responsible for: the earliest-due enabled rule selecting the object — by prefix, tag, `And` or
//! size, a rule's `Date` as written, its `Days` added to the write time and rounded up to the next
//! UTC midnight in real days whatever the debug interval, the first rule on a tie — named with its
//! date and id; tags set after the write counted by a later read; and nothing answered for no rule,
//! a disabled or non-expiring rule, a noncurrent version, a copy or a completion response, or a
//! lifecycle record that cannot be read, which never fails the write.
//! NOT responsible for: when objects are expired (`lifecycle_expiration.rs`), or the configuration
//! grammar (`lifecycle.rs`).
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use std::time::Duration;

use super::lifecycle_expiration::put_policy;
use super::*;

const PRECEDENCE: &str = "<LifecycleConfiguration><Rule><Expiration><Days>3</Days></Expiration><ID>rule-a</ID><Filter><Prefix>exp/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>1</Days></Expiration><ID>rule-b</ID><Filter><Prefix>exp/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>2</Days></Expiration><ID>rule-t</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>1</Days></Expiration><ID>z-first</ID><Filter><Prefix>tie/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>1</Days></Expiration><ID>a-second</ID><Filter><Prefix>tie/</Prefix></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const PRECEDENCE_MD5: &str = "XXeRn6veXVU2DQvYgW6tvw==";
const KINDS: &str = "<LifecycleConfiguration><Rule><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration><ID>date-rule</ID><Filter><Prefix>d/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Date>2026-01-03T00:00:00Z</Date></Expiration><ID>early-date</ID><Filter><Prefix>mix/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>5</Days></Expiration><ID>late-days</ID><Filter><Prefix>mix/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>1</Days></Expiration><ID>off</ID><Filter><Prefix>off/</Prefix></Filter><Status>Disabled</Status></Rule><Rule><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration><ID>edm</ID><Filter><Prefix>edm/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration><ID>noncurrent</ID><Filter><Prefix>nc/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Days>2</Days></Expiration><ID>size-rule</ID><Filter><And><Prefix>sz/</Prefix><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan></And></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const KINDS_MD5: &str = "uF/v1WpD0rzUsRMIyWTxMg==";
const EVERYTHING: &str = "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration><ID>v-rule</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const EVERYTHING_MD5: &str = "drchG9WL2tkDWLKAFdPoMg==";
const DATED_EARLY: &str = "<LifecycleConfiguration><Rule><Expiration><Date>1970-01-01T00:00:00Z</Date></Expiration><ID>epoch</ID><Filter><Prefix>e/</Prefix></Filter><Status>Enabled</Status></Rule><Rule><Expiration><Date>2000-01-01T00:00:00Z</Date></Expiration><ID>past</ID><Filter><Prefix>p/</Prefix></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const DATED_EARLY_MD5: &str = "Pk4RoV5UatCAOdjei/IGYA==";

/// The fixture clock is 2026-01-02T03:04:05Z: one day later, rounded up to midnight.
const ONE_DAY: &str = "Sun, 04 Jan 2026 00:00:00 GMT";
const TWO_DAYS: &str = "Mon, 05 Jan 2026 00:00:00 GMT";

fn expected(date: &str, rule: &str) -> Option<String> {
    Some(format!("expiry-date=\"{date}\", rule-id=\"{rule}\""))
}

fn expiration(response: &rustfs_gateway::WireResponse) -> Option<String> {
    header(response, "x-amz-expiration").map(|value| value.to_str().expect("an ASCII header").to_owned())
}

async fn send(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: &str,
    pairs: &[(&'static str, &str)],
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, http::HeaderValue::from_str(value).expect("a fixture header value"));
    }
    let response = exchange(
        service,
        signed_with_headers(method, target, Bytes::copy_from_slice(body.as_bytes()), headers),
    )
    .await;
    assert!(
        response.status().is_success(),
        "{target}: {} {}",
        response.status(),
        String::from_utf8_lossy(response.body())
    );
    response
}

/// What `PutObject`, then `HeadObject` and `GetObject`, answer for `target`.
async fn answers(service: &S3Service, target: &str, body: &str, pairs: &[(&'static str, &str)]) -> [Option<String>; 3] {
    let put = send(service, http::Method::PUT, target, body, pairs).await;
    [
        expiration(&put),
        expiration(&send(service, http::Method::HEAD, target, "", &[]).await),
        expiration(&send(service, http::Method::GET, target, "", &[]).await),
    ]
}

async fn configured(service: &S3Service, bucket: &str, document: &'static str, md5: &'static str) {
    create_bucket(service, bucket).await;
    put_policy(service, bucket, document, md5).await;
}

/// Positive — s3-tests `test_lifecycle_expiration_header_put` and `_head`: two rules select the key
/// and the earlier one is named, on the write and on both reads.
#[tokio::test]
async fn the_earliest_rule_is_answered_on_put_head_and_get() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "earliest", PRECEDENCE, PRECEDENCE_MD5).await;
    let answered = answers(&service, "/earliest/exp/one", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected(ONE_DAY, "rule-b")));
}

/// Positive — s3-tests `test_lifecycle_expiration_header_tags_head`: a tag rule applies when the
/// write carries the tag, and to a key tagged after its write once the tags are there.
#[tokio::test]
async fn a_tag_rule_applies_once_the_tag_is_there() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "tagged", PRECEDENCE, PRECEDENCE_MD5).await;
    let answered = answers(&service, "/tagged/with-tag", "body", &[("x-amz-tagging", "k=v")]).await;
    assert_eq!(answered, [(); 3].map(|()| expected(TWO_DAYS, "rule-t")));

    assert_eq!(answers(&service, "/tagged/later", "body", &[]).await, [None, None, None]);
    let document = "<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    send(
        &service,
        http::Method::PUT,
        "/tagged/later?tagging",
        document,
        &[("content-md5", "EbdZDxVT2OADmYhaGBi6mA==")],
    )
    .await;
    for method in [http::Method::HEAD, http::Method::GET] {
        let read = send(&service, method.clone(), "/tagged/later", "", &[]).await;
        assert_eq!(expiration(&read), expected(TWO_DAYS, "rule-t"), "{method}");
    }
}

/// Positive — a `Date` rule names its date as written, and an earlier date beats a later `Days`.
#[tokio::test]
async fn a_date_rule_names_its_date() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "dated", KINDS, KINDS_MD5).await;
    let answered = answers(&service, "/dated/d/key", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected("Tue, 01 Jan 2030 00:00:00 GMT", "date-rule")));
    let answered = answers(&service, "/dated/mix/key", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected("Sat, 03 Jan 2026 00:00:00 GMT", "early-date")));
}

/// Positive — in a versioned bucket every write answers, and so does a read of the current version,
/// by name or not.
#[tokio::test]
async fn a_versioned_buckets_current_version_answers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "versioned", EVERYTHING, EVERYTHING_MD5).await;
    let enabled = super::multipart_versioning::set_versioning(&service, "versioned", "Enabled").await;
    assert_eq!(enabled.status(), 200);
    send(&service, http::Method::PUT, "/versioned/key", "one", &[]).await;
    let second = send(&service, http::Method::PUT, "/versioned/key", "two", &[]).await;
    assert_eq!(expiration(&second), expected(ONE_DAY, "v-rule"));
    let current = header(&second, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("ASCII")
        .to_owned();
    for target in ["/versioned/key".to_owned(), format!("/versioned/key?versionId={current}")] {
        let head = send(&service, http::Method::HEAD, &target, "", &[]).await;
        assert_eq!(expiration(&head), expected(ONE_DAY, "v-rule"), "{target}");
    }
}

/// Negative — a key no rule selects, and a bucket without a configuration, answer nothing.
#[tokio::test]
async fn n_nothing_is_answered_without_a_selecting_rule() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "unselected", PRECEDENCE, PRECEDENCE_MD5).await;
    assert_eq!(answers(&service, "/unselected/other/key", "body", &[]).await, [None, None, None]);
    create_bucket(&service, "unconfigured").await;
    assert_eq!(answers(&service, "/unconfigured/exp/key", "body", &[]).await, [None, None, None]);
}

/// Negative — a disabled rule, a rule that expires only delete markers, and a rule that expires
/// only noncurrent versions answer nothing.
#[tokio::test]
async fn n_disabled_and_non_expiring_rules_answer_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "inert", KINDS, KINDS_MD5).await;
    for prefix in ["off", "edm", "nc"] {
        let answered = answers(&service, &format!("/inert/{prefix}/key"), "body", &[]).await;
        assert_eq!(answered, [None, None, None], "{prefix}");
    }
}

/// Negative — a size filter is honoured: an object at or under the bound is not selected.
#[tokio::test]
async fn n_a_size_filter_is_honoured() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "sized", KINDS, KINDS_MD5).await;
    assert_eq!(answers(&service, "/sized/sz/small", &"x".repeat(100), &[]).await, [None, None, None]);
    let answered = answers(&service, "/sized/sz/large", &"x".repeat(101), &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected(TWO_DAYS, "size-rule")));
}

/// Negative — a later rule due on the same day does not replace the first one.
#[tokio::test]
async fn n_a_later_rule_due_the_same_day_does_not_win() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "tied", PRECEDENCE, PRECEDENCE_MD5).await;
    let answered = answers(&service, "/tied/tie/key", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected(ONE_DAY, "z-first")));
}

/// Negative — a noncurrent version answers nothing, by `HEAD` or `GET`.
#[tokio::test]
async fn n_a_noncurrent_version_answers_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "noncurrent", EVERYTHING, EVERYTHING_MD5).await;
    let enabled = super::multipart_versioning::set_versioning(&service, "noncurrent", "Enabled").await;
    assert_eq!(enabled.status(), 200);
    let first = send(&service, http::Method::PUT, "/noncurrent/key", "one", &[]).await;
    let first = header(&first, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("ASCII")
        .to_owned();
    send(&service, http::Method::PUT, "/noncurrent/key", "two", &[]).await;
    for method in [http::Method::HEAD, http::Method::GET] {
        let read = send(&service, method.clone(), &format!("/noncurrent/key?versionId={first}"), "", &[]).await;
        assert_eq!(expiration(&read), None, "{method}");
    }
}

/// Negative — a copy and a completion answer nothing themselves, as legacy RustFS's do; a read of
/// what they wrote does.
#[tokio::test]
async fn n_copy_and_completion_responses_answer_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "written", PRECEDENCE, PRECEDENCE_MD5).await;
    send(&service, http::Method::PUT, "/written/source", "source", &[]).await;
    let copied = send(
        &service,
        http::Method::PUT,
        "/written/tie/copy",
        "",
        &[("x-amz-copy-source", "/written/source")],
    )
    .await;
    assert_eq!(expiration(&copied), None);

    let created = send(&service, http::Method::POST, "/written/tie/multipart?uploads", "", &[]).await;
    let upload_id = element(created.body(), "UploadId").expect("an upload id");
    let part = send(
        &service,
        http::Method::PUT,
        &format!("/written/tie/multipart?partNumber=1&uploadId={upload_id}"),
        "part",
        &[],
    )
    .await;
    let e_tag = header(&part, "etag").expect("a part tag").to_str().expect("ASCII").to_owned();
    let document =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{e_tag}</ETag></Part></CompleteMultipartUpload>");
    let completed = send(
        &service,
        http::Method::POST,
        &format!("/written/tie/multipart?uploadId={upload_id}"),
        &document,
        &[],
    )
    .await;
    assert_eq!(expiration(&completed), None);

    for target in ["/written/tie/copy", "/written/tie/multipart"] {
        let head = send(&service, http::Method::HEAD, target, "", &[]).await;
        assert_eq!(expiration(&head), expected(ONE_DAY, "z-first"), "{target}");
    }
}

/// Negative — the debug interval, which shortens a lifecycle day for the sweep, does not shorten
/// the answered date: a day is still 86400 seconds there, as the s3-tests helper measures it.
#[tokio::test]
async fn n_the_debug_interval_does_not_shorten_the_answered_date() {
    let root = TestRoot::new();
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .with_lifecycle_debug_interval(Duration::from_secs(10))
        .expect("a non-zero debug interval");
    let (_, service) = service_with_backend(Arc::new(backend));
    configured(&service, "debug", PRECEDENCE, PRECEDENCE_MD5).await;
    let answered = answers(&service, "/debug/exp/key", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected(ONE_DAY, "rule-b")));
}

/// Negative — a lifecycle record that cannot be read never fails the write or the read: the header
/// is advisory, so it is left out and the object is stored and served.
#[tokio::test]
async fn n_an_unreadable_lifecycle_record_is_answered_as_no_header() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "unreadable", PRECEDENCE, PRECEDENCE_MD5).await;
    let record = root.0.join(format!("b-{}", hex::encode("unreadable"))).join("lifecycle");
    std::fs::write(&record, b"not a lifecycle record").expect("the corrupt record fixture is writable");
    assert_eq!(answers(&service, "/unreadable/exp/key", "body", &[]).await, [None, None, None]);
    let read = send(&service, http::Method::GET, "/unreadable/exp/key", "", &[]).await;
    assert_eq!(read.body().as_ref(), b"body");
}

/// Negative — a rule dated at the epoch answers nothing, as legacy RustFS reads that date as no
/// expiration; a rule dated in the past otherwise answers its date.
#[tokio::test]
async fn n_a_rule_dated_at_the_epoch_answers_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    configured(&service, "early", DATED_EARLY, DATED_EARLY_MD5).await;
    assert_eq!(answers(&service, "/early/e/key", "body", &[]).await, [None, None, None]);
    let answered = answers(&service, "/early/p/key", "body", &[]).await;
    assert_eq!(answered, [(); 3].map(|()| expected("Sat, 01 Jan 2000 00:00:00 GMT", "past")));
}
