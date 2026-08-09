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

//! Wire-level authorization-oracle regression.
//!
//! Responsible for: proving two refused targets are indistinguishable. NOT responsible for:
//! decision settlement or audit contents beyond the positive control. Upstream: the parent
//! `authz_contract` instruments. Downstream: nothing.

use super::*;

/// c-azc-0017. Negative — a private bucket's existence cannot be inferred from an authorization refusal.
#[tokio::test]
async fn n_two_refusals_about_two_targets_are_the_same_response() {
    let recorder = Arc::new(Recorder::default());
    let service = base()
        .register::<rustfs_gateway::dto::ListObjectsV2, _>(Arc::new(Listing))
        .authorizer(decide_with(|_| Decision::Deny))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let alpha = exchange_wire(&service, list_objects("alpha")).await;
    let zulu = exchange_wire(&service, list_objects("zulu-a-bucket-that-is-not-there")).await;
    let audited: Vec<Option<String>> = recorder.events().into_iter().map(|event| event.bucket).collect();
    assert_eq!(audited, [Some("alpha".to_owned()), Some("zulu-a-bucket-that-is-not-there".to_owned())]);
    assert!(recorder.events().iter().all(|event| event.key.is_none()));
    assert_eq!(alpha.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(alpha.status(), zulu.status());
    assert_eq!(
        redact(&String::from_utf8_lossy(alpha.body())),
        redact(&String::from_utf8_lossy(zulu.body()))
    );
    let alpha_names: Vec<String> = alpha.headers().iter().map(|(name, _)| name.as_str().to_owned()).collect();
    let zulu_names: Vec<String> = zulu.headers().iter().map(|(name, _)| name.as_str().to_owned()).collect();
    assert_eq!(alpha_names, zulu_names);
    assert!(
        redact(&String::from_utf8_lossy(alpha.body())).contains("<Message>the request is not allowed</Message>"),
        "{}",
        String::from_utf8_lossy(alpha.body())
    );
}

fn list_objects(bucket: &str) -> http::Request<Bytes> {
    support::signed(http::Method::GET, &format!("/{bucket}?list-type=2"))
}
