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

//! A signed POST policy with more conditions than the gateway's own JSON element ceiling, under
//! the RustFS profile (rustfs/gateway#1173).
//!
//! Responsible for: a policy legacy RustFS reads — its conditions bounded only by the policy
//! field's 1 MiB — reaching authentication and storage, the generic ceiling still refusing it, and
//! a signature over another document still refused.
//! NOT responsible for: the policy's byte ceilings (`policy_bytes.rs`), depth, or condition
//! semantics.
//! Upstream: the POST form profile. Downstream: the gateway integration target.
//!
//! Evidence: legacy RustFS decodes a POST policy's JSON with no ceiling of its own on the number of
//! conditions, so a policy is bounded only by the `policy` field's 1 MiB form ceiling
//! (`rustfs/src/server/http.rs:166-173` at rustfs/rustfs@95268a3b9 leaves the form limits at their
//! defaults); every condition is then checked against the form.

use super::*;

/// A policy for `upload` with `extra` more `starts-with $key ""` conditions, each of which the
/// form satisfies.
fn policy_with_conditions(extra: usize) -> String {
    let repeated = vec![r#"["starts-with","$key",""]"#; extra].join(",");
    encode_policy_document(&format!(
        r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{{"bucket":"example-bucket"}},{{"key":"upload"}},["content-length-range",1,16],{repeated}]}}"#
    ))
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — a policy of 300 conditions, well past 256 JSON elements, is read and the file
/// stored under the RustFS profile.
#[tokio::test]
async fn legacy_policies_with_many_conditions_reach_storage() {
    let policy = policy_with_conditions(300);
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — the generic profile keeps its element ceiling and stores nothing.
#[tokio::test]
async fn n_generic_policies_keep_the_element_ceiling() {
    let policy = policy_with_conditions(300);
    let signature = signed_policy(&policy);
    let (status, response, stored) = post_with_credentials(
        true,
        &fields(&policy, &signature),
        "hello",
        Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
        false,
    )
    .await;
    assert!(status.is_client_error(), "{status}: {response}");
    assert_eq!(stored, None, "{response}");
}

/// Negative — a long policy signed as another document is still refused and stores nothing.
#[tokio::test]
async fn n_many_conditions_do_not_bypass_verification() {
    let policy = policy_with_conditions(300);
    let signature = signed_policy(&policy_with_conditions(299));
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(stored, None, "{response}");
}

/// Negative — a condition the form does not satisfy is still refused among many.
#[tokio::test]
async fn n_an_unmet_condition_among_many_is_still_refused() {
    let repeated = vec![r#"["starts-with","$key",""]"#; 300].join(",");
    let policy = encode_policy_document(&format!(
        r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{{"bucket":"example-bucket"}},{{"key":"other"}},["content-length-range",1,16],{repeated}]}}"#
    ));
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert!(status.is_client_error(), "{status}: {response}");
    assert_eq!(stored, None, "{response}");
}
