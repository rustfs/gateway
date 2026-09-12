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
//! Responsible for: proving that a refusal about a bucket that exists and a refusal about a bucket
//! that does not are indistinguishable, against a store where the difference is real and observable.
//! NOT responsible for: decision settlement or audit contents beyond the positive control. Upstream:
//! the parent `authz_contract` instruments. Downstream: nothing.
//!
//! # Why the store has to know which buckets exist
//!
//! Two refusals about two names that nothing distinguishes prove only that the framework answers
//! two names alike. An observer stuck on one answer, or a fixture that never consulted existence,
//! satisfies that. So the store here holds one bucket and truly lacks the other, an allowed request
//! shows the store answering the two differently, and only then does the refused pair have a
//! difference to hide.

use super::*;

use rustfs_gateway::{BucketName, BucketOwnerError, BucketOwnerSource, HandlerErrorContext};

/// The bucket the store holds.
const PRESENT: &str = "alpha";
/// A bucket the store does not hold.
const ABSENT: &str = "zulu-a-bucket-that-is-not-there";
/// The account the store names as the owner of every bucket it holds.
const OWNER: &str = "111122223333";

/// Which of the store's two reading surfaces the framework used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    /// The `ListObjectsV2` handler.
    List,
    /// The `BucketOwnerSource` lookup the route stage may make.
    Owner,
}

/// A bucket store with real existence state that records every read made of it.
///
/// It is both the handler and the bucket-owner source, which are the two ways this framework reads
/// bucket state on behalf of a request. A read through either one is a read that could learn
/// whether the bucket exists.
struct Store {
    buckets: &'static [&'static str],
    reads: Mutex<Vec<(Surface, String)>>,
}

impl Store {
    fn holding(buckets: &'static [&'static str]) -> Self {
        Self {
            buckets,
            reads: Mutex::new(Vec::new()),
        }
    }

    /// Records one read and answers whether the bucket exists.
    fn read(&self, surface: Surface, bucket: &str) -> bool {
        self.reads.lock().expect("not poisoned").push((surface, bucket.to_owned()));
        self.buckets.contains(&bucket)
    }

    /// Returns every read since the last call, and forgets them.
    fn take_reads(&self) -> Vec<(Surface, String)> {
        std::mem::take(&mut *self.reads.lock().expect("not poisoned"))
    }

    fn list(
        &self,
        request: &rustfs_gateway::Req<rustfs_gateway::dto::ListObjectsV2>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::ListObjectsV2> {
        if self.read(Surface::List, request.input().bucket.as_str()) {
            Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::ListObjectsV2Output::default()))
        } else {
            Err(HandlerErrorContext::missing_bucket().into())
        }
    }
}

impl rustfs_gateway::Handler<rustfs_gateway::dto::ListObjectsV2> for Store {
    async fn call(
        &self,
        request: rustfs_gateway::Req<rustfs_gateway::dto::ListObjectsV2>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::ListObjectsV2> {
        self.list(&request)
    }

    async fn call_with_context(
        &self,
        request: rustfs_gateway::Req<rustfs_gateway::dto::ListObjectsV2>,
        _context: rustfs_gateway::HandlerContext,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::ListObjectsV2> {
        self.list(&request)
    }
}

impl BucketOwnerSource for Store {
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        let exists = self.read(Surface::Owner, bucket.as_str());
        Box::pin(async move {
            if exists {
                Ok(Arc::from(OWNER))
            } else {
                Err(BucketOwnerError::unavailable())
            }
        })
    }
}

/// A service whose every bucket read goes to `store`.
fn over(store: &Arc<Store>) -> ServiceBuilder {
    base()
        .register::<rustfs_gateway::dto::ListObjectsV2, _>(Arc::clone(store))
        .bucket_owner_source(Arc::clone(store))
}

/// c-azc-0017. Negative — a private bucket's existence cannot be inferred from an authorization refusal.
#[tokio::test]
async fn n_two_refusals_about_two_targets_are_the_same_response() {
    let store = Arc::new(Store::holding(&[PRESENT]));

    // Positive control: allowed, the store answers the two buckets differently, and it is read
    // through both surfaces the refused pair below must not touch. Without this, every assertion
    // after it would hold against a store with no existence state and an observer with one answer.
    let allowed = over(&store)
        .authorizer(allow_when(|_| true))
        .build()
        .expect("a complete assembly");
    let listed = exchange_wire(&allowed, list_objects(PRESENT)).await;
    let missing = exchange_wire(&allowed, list_objects(ABSENT)).await;
    assert_eq!(listed.status(), http::StatusCode::OK, "{}", text(&listed));
    assert_eq!(missing.status(), http::StatusCode::NOT_FOUND, "{}", text(&missing));
    assert_eq!(code(&missing).as_deref(), Some("NoSuchBucket"), "{}", text(&missing));
    assert_eq!(
        store.take_reads(),
        [(Surface::List, PRESENT.to_owned()), (Surface::List, ABSENT.to_owned())]
    );
    let owned = support::signed_with(
        http::Method::GET,
        &format!("/{PRESENT}?list-type=2"),
        &[("x-amz-expected-bucket-owner", OWNER)],
    );
    let owned = exchange_wire(&allowed, owned).await;
    assert_eq!(owned.status(), http::StatusCode::OK, "{}", text(&owned));
    assert_eq!(
        store.take_reads(),
        [(Surface::Owner, PRESENT.to_owned()), (Surface::List, PRESENT.to_owned())]
    );

    // The refused pair, over the same store.
    let recorder = Arc::new(Recorder::default());
    let refused = over(&store)
        .authorizer(decide_with(|_| Decision::Deny))
        .authz_audit(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let present = exchange_wire(&refused, list_objects(PRESENT)).await;
    let absent = exchange_wire(&refused, list_objects(ABSENT)).await;
    let audited: Vec<Option<String>> = recorder.events().into_iter().map(|event| event.bucket).collect();
    assert_eq!(audited, [Some(PRESENT.to_owned()), Some(ABSENT.to_owned())]);
    assert!(recorder.events().iter().all(|event| event.key.is_none()));
    assert_eq!(present.status(), http::StatusCode::FORBIDDEN, "{}", text(&present));
    assert_eq!(present.status(), absent.status(), "{}", text(&absent));
    assert_eq!(code(&present).as_deref(), Some("AccessDenied"), "{}", text(&present));
    assert_eq!(code(&present), code(&absent), "{}", text(&absent));
    assert_eq!(redact(&text(&present)), redact(&text(&absent)));
    assert_eq!(header_names(&present), header_names(&absent));
    assert!(
        redact(&text(&present)).contains("<Message>the request is not allowed</Message>"),
        "{}",
        text(&present)
    );
    let reads = store.take_reads();
    for bucket in [PRESENT, ABSENT] {
        let count = reads.iter().filter(|(_, read)| read == bucket).count();
        assert_eq!(count, 0, "a refused request read `{bucket}` from the store: {reads:?}");
    }
}

fn list_objects(bucket: &str) -> http::Request<Bytes> {
    support::signed(http::Method::GET, &format!("/{bucket}?list-type=2"))
}

fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn code(response: &rustfs_gateway::WireResponse) -> Option<String> {
    support::element_text(&text(response), "Code").map(str::to_owned)
}

fn header_names(response: &rustfs_gateway::WireResponse) -> Vec<String> {
    response.headers().iter().map(|(name, _)| name.as_str().to_owned()).collect()
}
