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

//! `x-amz-expiration` answered by the RustFS-profile launcher as the s3-tests suite runs it
//! (rustfs/gateway#999; `test_lifecycle_expiration_header_put` and `_head`).
//!
//! Responsible for: proving the served assembly answers the header on a write and a read, in real
//! days although the launcher runs with `--lc-debug-interval 10`, as the s3-tests job starts it.
//! NOT responsible for: rule selection and precedence, which
//! `crates/fs/tests/crud/expiration_header.rs` pins against the backend alone.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a legacy RustFS build (rustfs/rustfs `528a36814`): a `Days` 1 rule
//! answers `expiry-date` one day after the write rounded up to the next UTC midnight, with the
//! rule's id, on `PutObject`, `HeadObject` and `GetObject`.

use super::*;

const RULE: &str = "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration><ID>rule1</ID><Filter><Prefix>days1/</Prefix></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const RULE_MD5: &str = "2ddM+TxV7CXRSat06M79mQ==";
const DAY: i64 = 24 * 60 * 60;

fn header_text(response: &WireResponse, name: &str) -> Option<String> {
    response
        .headers()
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == name).then(|| value.to_str().ok().map(ToOwned::to_owned)))
        .flatten()
}

/// Positive — the write and the read name the rule and the midnight after one real day.
#[tokio::test]
async fn the_header_counts_real_days_under_the_debug_interval() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &["--lc-debug-interval", "10"]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/expiring", Bytes::new()))
            .await
            .status(),
        200
    );
    let policy = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/expiring?lifecycle",
        Bytes::from_static(RULE.as_bytes()),
        &[("content-md5", RULE_MD5)],
    );
    let configured = exchange(&service, policy).await;
    assert_eq!(configured.status(), 200, "{}", body_of(&configured));

    let written = exchange(&service, as_main(http::Method::PUT, "/expiring/days1/foo", Bytes::from_static(b"body"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let head = exchange(&service, as_main(http::Method::HEAD, "/expiring/days1/foo", Bytes::new())).await;
    let modified = header_text(&head, "last-modified").expect("a modification time");
    let modified = Timestamp::parse(&modified, TimestampFormat::HttpDate)
        .expect("an HTTP date")
        .secs();
    // One real day after the write, rounded up to the next UTC midnight.
    let after = modified + DAY;
    let due = if after.rem_euclid(DAY) == 0 {
        after
    } else {
        after - after.rem_euclid(DAY) + DAY
    };
    let date = Timestamp::from_secs(due)
        .render(TimestampFormat::HttpDate)
        .expect("a renderable date");
    let expected = format!("expiry-date=\"{date}\", rule-id=\"rule1\"");
    assert_eq!(header_text(&written, "x-amz-expiration").as_deref(), Some(expected.as_str()));
    assert_eq!(header_text(&head, "x-amz-expiration").as_deref(), Some(expected.as_str()));
}
