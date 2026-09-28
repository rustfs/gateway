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

//! Bucket tagging through the production registry (rustfs/gateway#1004).
//!
//! Responsible for: the tag set stored, read back across a restart and replaced, `NoSuchTagSet`
//! for an untagged bucket, the idempotent `204` delete, the shared tag-set refusals storing
//! nothing, and the missing-bucket refusals.
//! NOT responsible for: the tag rules themselves (`crates/core` `tagging`) or object tags
//! (`object_tagging`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

const HELLO: &str = "<Tagging><TagSet><Tag><Key>Hello</Key><Value>World</Value></Tag></TagSet></Tagging>";
const HELLO_MD5: &str = "TzkV01qB/xRddBc/Z4AJHg==";
const EMPTY_KEY: &str = "<Tagging><TagSet><Tag><Key></Key><Value>x</Value></Tag></TagSet></Tagging>";
const EMPTY_KEY_MD5: &str = "yPZjtCPqU6n7fQS/jYLHKQ==";
const DUP: &str =
    "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>a</Key><Value>2</Value></Tag></TagSet></Tagging>";
const DUP_MD5: &str = "07HsqaMhB5qGnMnwmjveEw==";
const TOO_MANY: &str = "<Tagging><TagSet><Tag><Key>k0</Key><Value>v</Value></Tag><Tag><Key>k1</Key><Value>v</Value></Tag><Tag><Key>k2</Key><Value>v</Value></Tag><Tag><Key>k3</Key><Value>v</Value></Tag><Tag><Key>k4</Key><Value>v</Value></Tag><Tag><Key>k5</Key><Value>v</Value></Tag><Tag><Key>k6</Key><Value>v</Value></Tag><Tag><Key>k7</Key><Value>v</Value></Tag><Tag><Key>k8</Key><Value>v</Value></Tag><Tag><Key>k9</Key><Value>v</Value></Tag><Tag><Key>k10</Key><Value>v</Value></Tag><Tag><Key>k11</Key><Value>v</Value></Tag><Tag><Key>k12</Key><Value>v</Value></Tag><Tag><Key>k13</Key><Value>v</Value></Tag><Tag><Key>k14</Key><Value>v</Value></Tag><Tag><Key>k15</Key><Value>v</Value></Tag><Tag><Key>k16</Key><Value>v</Value></Tag><Tag><Key>k17</Key><Value>v</Value></Tag><Tag><Key>k18</Key><Value>v</Value></Tag><Tag><Key>k19</Key><Value>v</Value></Tag><Tag><Key>k20</Key><Value>v</Value></Tag><Tag><Key>k21</Key><Value>v</Value></Tag><Tag><Key>k22</Key><Value>v</Value></Tag><Tag><Key>k23</Key><Value>v</Value></Tag><Tag><Key>k24</Key><Value>v</Value></Tag><Tag><Key>k25</Key><Value>v</Value></Tag><Tag><Key>k26</Key><Value>v</Value></Tag><Tag><Key>k27</Key><Value>v</Value></Tag><Tag><Key>k28</Key><Value>v</Value></Tag><Tag><Key>k29</Key><Value>v</Value></Tag><Tag><Key>k30</Key><Value>v</Value></Tag><Tag><Key>k31</Key><Value>v</Value></Tag><Tag><Key>k32</Key><Value>v</Value></Tag><Tag><Key>k33</Key><Value>v</Value></Tag><Tag><Key>k34</Key><Value>v</Value></Tag><Tag><Key>k35</Key><Value>v</Value></Tag><Tag><Key>k36</Key><Value>v</Value></Tag><Tag><Key>k37</Key><Value>v</Value></Tag><Tag><Key>k38</Key><Value>v</Value></Tag><Tag><Key>k39</Key><Value>v</Value></Tag><Tag><Key>k40</Key><Value>v</Value></Tag><Tag><Key>k41</Key><Value>v</Value></Tag><Tag><Key>k42</Key><Value>v</Value></Tag><Tag><Key>k43</Key><Value>v</Value></Tag><Tag><Key>k44</Key><Value>v</Value></Tag><Tag><Key>k45</Key><Value>v</Value></Tag><Tag><Key>k46</Key><Value>v</Value></Tag><Tag><Key>k47</Key><Value>v</Value></Tag><Tag><Key>k48</Key><Value>v</Value></Tag><Tag><Key>k49</Key><Value>v</Value></Tag><Tag><Key>k50</Key><Value>v</Value></Tag></TagSet></Tagging>";
const TOO_MANY_MD5: &str = "jo3fccpZbusvjd7kxeh3nQ==";

async fn put(service: &S3Service, target: &str, body: &'static str, md5: &str) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_str(md5).expect("a header value"));
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(body.as_bytes()), headers),
    )
    .await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn assert_untagged(response: &WireResponse) {
    assert_eq!(response.status(), 404, "{}", text(response));
    assert!(text(response).contains("<Code>NoSuchTagSet</Code>"), "{}", text(response));
}

/// Positive — the tag set is stored, survives a restart, and a delete leaves the bucket untagged
/// with the same quiet `204` whether or not a set was there.
#[tokio::test]
async fn a_bucket_tag_set_is_stored_read_back_and_deleted() {
    let root = TestRoot::new();
    let (_, first) = service(&root);
    create_bucket(&first, "tagged").await;
    assert_untagged(&get(&first, "/tagged?tagging").await);
    let written = put(&first, "/tagged?tagging", HELLO, HELLO_MD5).await;
    assert!(matches!(written.status().as_u16(), 200 | 204), "{}", text(&written));
    drop(first);

    let (_, service) = service(&root);
    let read = get(&service, "/tagged?tagging").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(element(read.body(), "Key").as_deref(), Some("Hello"));
    assert_eq!(element(read.body(), "Value").as_deref(), Some("World"));
    for _ in 0..2 {
        let deleted = exchange(&service, signed(http::Method::DELETE, "/tagged?tagging", Bytes::new())).await;
        assert_eq!(deleted.status(), 204, "{}", text(&deleted));
    }
    assert_untagged(&get(&service, "/tagged?tagging").await);
}

/// Negative — a set the shared rules refuse (empty key, repeated key, more than fifty tags) is
/// `InvalidTag` and nothing is stored.
#[tokio::test]
async fn n_refused_tag_sets_store_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "tagged").await;
    for (body, md5) in [(EMPTY_KEY, EMPTY_KEY_MD5), (DUP, DUP_MD5), (TOO_MANY, TOO_MANY_MD5)] {
        let refused = put(&service, "/tagged?tagging", body, md5).await;
        assert_eq!(refused.status(), 400, "{}", text(&refused));
        assert!(text(&refused).contains("<Code>InvalidTag</Code>"), "{}", text(&refused));
        assert_untagged(&get(&service, "/tagged?tagging").await);
    }
}

/// Negative — every operation on a missing bucket is `NoSuchBucket`; the set leaves with its
/// bucket.
#[tokio::test]
async fn n_missing_and_recreated_buckets() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    for response in [
        put(&service, "/ghost?tagging", HELLO, HELLO_MD5).await,
        get(&service, "/ghost?tagging").await,
        exchange(&service, signed(http::Method::DELETE, "/ghost?tagging", Bytes::new())).await,
    ] {
        assert_eq!(response.status(), 404, "{}", text(&response));
        assert!(text(&response).contains("<Code>NoSuchBucket</Code>"), "{}", text(&response));
    }
    create_bucket(&service, "again").await;
    assert!(matches!(
        put(&service, "/again?tagging", HELLO, HELLO_MD5).await.status().as_u16(),
        200 | 204
    ));
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/again", Bytes::new()))
            .await
            .status(),
        204
    );
    create_bucket(&service, "again").await;
    assert_untagged(&get(&service, "/again?tagging").await);
}
