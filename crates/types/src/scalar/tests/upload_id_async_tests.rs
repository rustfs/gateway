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

//! The asynchronous upload-id exchange, whose lookup returns a future and may fail.
//!
//! Responsible for: proving the asynchronous exchange keeps every guarantee of the synchronous
//! one (shape before storage, one lookup, byte-for-byte ownership, one refusal) and returns a
//! lookup failure on its own channel rather than as a refusal or an absent record.
//! NOT responsible for: the synchronous exchange's own tests, query decoding, or any runtime;
//! futures are driven by a hand-rolled poll loop with a no-op waker.
//! Upstream: the upload-id scalar. Downstream: nothing.

use std::cell::Cell;
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use crate::{BucketName, ObjectKey, RecordedUpload, UploadIdClaim, UploadRejection, resolve_upload, resolve_upload_async};

#[derive(Debug, PartialEq, Eq)]
struct Recorded {
    bucket: &'static str,
    key: &'static str,
}

impl RecordedUpload for Recorded {
    fn bucket(&self) -> &str {
        self.bucket
    }

    fn key(&self) -> &str {
        self.key
    }
}

/// The caller's own storage failure, distinct from every refusal.
#[derive(Debug, PartialEq, Eq)]
struct StoreDown;

const MINE: Recorded = Recorded {
    bucket: "example-bucket",
    key: "object-key",
};

fn bucket() -> BucketName {
    BucketName::new("example-bucket").expect("the test bucket is valid")
}

fn key() -> ObjectKey {
    ObjectKey::new("object-key").expect("the test key is valid")
}

/// Drives a future to completion without a runtime; the futures here wake themselves.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..16 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the test future did not complete");
}

/// Pending once before yielding its value, so the exchange is proved to survive a real suspension.
struct Later<T>(Option<T>, bool);

impl<T: Unpin> Future for Later<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if !self.1 {
            self.1 = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(self.0.take().expect("polled after completion"))
    }
}

fn later<T>(value: T) -> Later<T> {
    Later(Some(value), false)
}

type Outcome<'a> = Result<Result<(crate::ResolvedUploadId<'a>, Recorded), UploadRejection>, StoreDown>;

/// Runs the asynchronous exchange against one answer, counting lookups and recording the id seen.
fn exchange<'a>(
    claim: &'a UploadIdClaim,
    answer: Result<Option<Recorded>, StoreDown>,
    calls: &Cell<usize>,
    seen: &Cell<Option<&'a str>>,
) -> Outcome<'a> {
    block_on(resolve_upload_async(claim, &bucket(), &key(), |id| {
        calls.set(calls.get() + 1);
        seen.set(Some(id));
        later(answer)
    }))
}

fn refusal_for(raw: &str, answer: Result<Option<Recorded>, StoreDown>) -> (UploadRejection, usize) {
    let claim = UploadIdClaim::from_wire(raw);
    let calls = Cell::new(0);
    let seen = Cell::new(None);
    let refusal = match exchange(&claim, answer, &calls, &seen) {
        Ok(Err(refusal)) => refusal,
        Ok(Ok(_)) => panic!("{raw:?} was resolved"),
        Err(StoreDown) => panic!("{raw:?} surfaced a store failure"),
    };
    (refusal, calls.get())
}

fn absent_refusal() -> UploadRejection {
    refusal_for("upload-0001", Ok(None)).0
}

#[test]
fn async_a_matching_owner_yields_the_id_and_the_record_after_one_lookup() {
    let claim = UploadIdClaim::from_wire("upload-0001");
    let calls = Cell::new(0);
    let seen = Cell::new(None);
    let (resolved, record) = exchange(&claim, Ok(Some(MINE)), &calls, &seen)
        .expect("the store answered")
        .expect("the recorded owner matches the request");

    assert_eq!(resolved.id(), "upload-0001");
    assert_eq!(record, MINE);
    assert_eq!(calls.get(), 1, "a well-shaped id is looked up exactly once");
    assert_eq!(seen.get(), Some("upload-0001"), "the lookup sees the id byte for byte");
}

#[test]
fn n_async_an_impossible_shape_never_reaches_the_lookup() {
    let expected = absent_refusal();
    for raw in ["", "/upload-0001", "upload\n0001", "upload\u{7f}0001", "a/../b", ".."] {
        // Every answer a store could give is offered, and none may be consulted.
        for answer in [Ok(Some(MINE)), Ok(None), Err(StoreDown)] {
            let (refusal, calls) = refusal_for(raw, answer);
            assert_eq!(calls, 0, "{raw:?} must be refused before storage is consulted");
            assert_eq!(refusal, expected, "{raw:?} is refused like an absent upload");
        }
    }
}

#[test]
fn n_async_an_absent_record_is_refused_after_one_lookup() {
    let (refusal, calls) = refusal_for("upload-0001", Ok(None));

    assert_eq!(calls, 1);
    assert_eq!(refusal.code().as_str(), "NoSuchUpload");
    assert!(!refusal.reason().contains("upload-0001"), "the refusal never echoes the id");
}

#[test]
fn n_async_a_record_in_another_bucket_is_the_same_refusal() {
    let expected = absent_refusal();
    for bucket in ["another-bucket", "Example-bucket", "example-bucket ", "example-bucke"] {
        let (refusal, calls) = refusal_for("upload-0001", Ok(Some(Recorded { bucket, key: MINE.key })));
        assert_eq!(calls, 1);
        assert_eq!(refusal, expected, "a record in {bucket:?} must be indistinguishable from absence");
    }
}

#[test]
fn n_async_a_record_for_another_key_is_the_same_refusal() {
    let expected = absent_refusal();
    for key in ["another-key", "Object-key", "object-key/", "/object-key", "object-ke"] {
        let (refusal, calls) = refusal_for(
            "upload-0001",
            Ok(Some(Recorded {
                bucket: MINE.bucket,
                key,
            })),
        );
        assert_eq!(calls, 1);
        assert_eq!(refusal, expected, "a record for {key:?} must be indistinguishable from absence");
    }
}

#[test]
fn n_async_a_lookup_failure_is_the_callers_error_not_a_refusal() {
    let claim = UploadIdClaim::from_wire("upload-0001");
    let calls = Cell::new(0);
    let seen = Cell::new(None);
    let outcome = exchange(&claim, Err(StoreDown), &calls, &seen);

    assert!(
        matches!(outcome, Err(StoreDown)),
        "a store failure is neither a refusal nor an absent record"
    );
    assert_eq!(calls.get(), 1, "a failed lookup is not retried");
}

#[test]
fn n_sync_and_async_refuse_every_failure_alike() {
    let owned_elsewhere = || Recorded {
        bucket: MINE.bucket,
        key: "another-key",
    };
    for raw in ["", "a/../b", "upload-0001"] {
        let claim = UploadIdClaim::from_wire(raw);
        let sync = resolve_upload(&claim, &bucket(), &key(), |_| Some(owned_elsewhere()))
            .err()
            .expect("the sync exchange refuses");
        let (refusal, _) = refusal_for(raw, Ok(Some(owned_elsewhere())));
        assert_eq!(refusal, sync, "{raw:?} must be refused identically on both paths");
    }
}
