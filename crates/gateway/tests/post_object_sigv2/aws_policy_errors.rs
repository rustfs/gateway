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

//! How the RustFS profile refuses a SigV2 browser form under the selected contract
//! (rustfs/gateway#1444).
//!
//! Responsible for: an expiration whose date and time are not joined by the `T` designator being
//! `400 InvalidPolicyDocument`, and every policy violation — a field failing its condition, a field
//! a condition names but the form lacks, a policy for another bucket, a field no condition names —
//! being `403 AccessDenied` "Invalid according to Policy", with nothing stored either way; each
//! beside the passing form it differs from.
//! NOT responsible for: the size range (`EntityTooSmall`/`EntityTooLarge`), expiry, or signatures.
//! Upstream: the POST form profile. Downstream: the gateway integration target.
//!
//! Evidence: the five cases mirror Ceph s3-tests `test_post_object_invalid_date_format`,
//! `_missing_policy_condition`, `_request_missing_policy_specified_field`, `_wrong_bucket` and
//! `_invalid_request_field_value` at the commit `ci/s3tests/pins.env` pins. Legacy RustFS answers
//! the first `204` and the others `400 InvalidPolicyDocument`; the decision on rustfs/gateway#1444
//! selects the status behavior instead, and rustfs/backlog#2684 records the difference. The AWS
//! error code for malformed policy expiration has not been measured.

use super::*;

const CONDITION_FAILED: &str = "<Message>Invalid according to Policy: Policy Condition failed</Message>";
const EXTRA_FIELD: &str = "<Message>Invalid according to Policy: Extra input fields</Message>";

/// A policy expiring an hour after the fixture's signing instant, with `conditions` verbatim.
fn conditions_policy(conditions: &str) -> String {
    encode_policy_document(&format!(r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{conditions}]}}"#))
}

async fn post_signed(policy: &str, extra: &[(&'static str, &'static str)]) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    let signature = signed_policy(policy);
    let mut form = fields(policy, &signature);
    form.extend_from_slice(extra);
    post(true, &form, "hello").await
}

fn assert_policy_refusal(
    case: &str,
    (status, response, stored): &(StatusCode, String, Option<(String, Vec<u8>)>),
    message: &str,
) {
    assert_eq!(*status, StatusCode::FORBIDDEN, "{case}: {response}");
    assert!(response.contains("<Code>AccessDenied</Code>"), "{case}: {response}");
    assert!(response.contains(message), "{case}: {response}");
    assert_eq!(*stored, None, "{case}");
}

fn assert_stored(case: &str, (status, response, stored): &(StatusCode, String, Option<(String, Vec<u8>)>)) {
    assert_eq!(*status, StatusCode::NO_CONTENT, "{case}: {response}");
    assert_eq!(*stored, Some(("upload".to_owned(), b"hello".to_vec())), "{case}");
}

/// Negative — Ceph's `test_post_object_invalid_date_format`: Python's `str(datetime)` joins date
/// and time with a space and appends a numeric offset. The expiration is malformed, so the form is
/// `400 InvalidPolicyDocument`; the same instant joined by `T` stores the file.
#[tokio::test]
async fn n_an_expiration_without_the_time_designator_is_an_invalid_policy_document() {
    let spelled = |expiration: &str| {
        encode_policy_document(&format!(
            r#"{{"expiration":"{expiration}","conditions":[{{"bucket":"example-bucket"}},{{"key":"upload"}}]}}"#
        ))
    };
    let (status, response, stored) = post_signed(&spelled("2026-01-02 04:04:05.123456+00:00"), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("<Code>InvalidPolicyDocument</Code>"), "{response}");
    assert_eq!(stored, None);
    assert_stored("designator", &post_signed(&spelled("2026-01-02T04:04:05.123456+00:00"), &[]).await);
}

/// Negative — Ceph's `test_post_object_missing_policy_condition`: the policy names no bucket and
/// its only key condition is not met, so the form is refused `403`; a met key condition stores it.
#[tokio::test]
async fn n_a_key_failing_its_condition_is_access_denied() {
    let refused = post_signed(&conditions_policy(r#"["starts-with","$key","\\$foo"]"#), &[]).await;
    assert_policy_refusal("unmet key prefix", &refused, CONDITION_FAILED);
    assert_stored(
        "met key prefix",
        &post_signed(&conditions_policy(r#"{"bucket":"example-bucket"},["starts-with","$key","up"]"#), &[]).await,
    );
}

/// Negative — Ceph's `test_post_object_request_missing_policy_specified_field`: a condition names
/// `x-amz-meta-foo` and the form does not carry it, so the form is refused `403`; carrying a value
/// the condition admits stores it.
#[tokio::test]
async fn n_a_field_the_policy_names_but_the_form_lacks_is_access_denied() {
    let policy = conditions_policy(r#"{"bucket":"example-bucket"},{"key":"upload"},["starts-with","$x-amz-meta-foo","bar"]"#);
    assert_policy_refusal("absent field", &post_signed(&policy, &[]).await, CONDITION_FAILED);
    assert_stored("present field", &post_signed(&policy, &[("x-amz-meta-foo", "barclamp")]).await);
}

/// Negative — Ceph's `test_post_object_wrong_bucket`: a policy and `bucket` field for one bucket,
/// posted to another, is refused `403`; posted to its own bucket it stores the file.
#[tokio::test]
async fn n_a_policy_for_another_bucket_is_access_denied() {
    let other = conditions_policy(r#"{"bucket":"other-bucket"},{"key":"upload"}"#);
    assert_policy_refusal(
        "other bucket",
        &post_signed(&other, &[("bucket", "other-bucket")]).await,
        CONDITION_FAILED,
    );
    let own = conditions_policy(r#"{"bucket":"example-bucket"},{"key":"upload"}"#);
    assert_stored("own bucket", &post_signed(&own, &[("bucket", "example-bucket")]).await);
}

/// Negative — Ceph's `test_post_object_invalid_request_field_value`: `x-amz-meta-foo` must equal
/// the empty string and the form sends `barclamp`, so it is refused `403`; the empty value stores it.
#[tokio::test]
async fn n_a_field_value_failing_its_condition_is_access_denied() {
    let policy = conditions_policy(r#"{"bucket":"example-bucket"},{"key":"upload"},["eq","$x-amz-meta-foo",""]"#);
    assert_policy_refusal(
        "unequal value",
        &post_signed(&policy, &[("x-amz-meta-foo", "barclamp")]).await,
        CONDITION_FAILED,
    );
    assert_stored("equal value", &post_signed(&policy, &[("x-amz-meta-foo", "")]).await);
}

/// Negative — a field no condition names is refused `403 AccessDenied` as an extra input field,
/// after every condition; named by a condition, the same field stores the file.
#[tokio::test]
async fn n_a_field_no_condition_names_is_access_denied_as_an_extra_input() {
    let unnamed = conditions_policy(r#"{"bucket":"example-bucket"},{"key":"upload"}"#);
    assert_policy_refusal("unnamed field", &post_signed(&unnamed, &[("x-amz-meta-foo", "bar")]).await, EXTRA_FIELD);
    let named = conditions_policy(r#"{"bucket":"example-bucket"},{"key":"upload"},{"x-amz-meta-foo":"bar"}"#);
    assert_stored("named field", &post_signed(&named, &[("x-amz-meta-foo", "bar")]).await);
}
