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

//! Production multipart minimum-part-size evidence for the filesystem reference backend.
//!
//! Responsible for: proving non-final parts are at least 5 MiB, rejection publishes nothing, and
//! the original upload remains retryable. NOT responsible for: checksum negotiation, lifecycle,
//! or upload-id allocation. Upstream: multipart persistence and publication. Downstream: the crate
//! verification gate.

use super::*;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(super) const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
const FRAME_SIZE: usize = 512 * 1024;

pub(super) struct FramedBody {
    frames: VecDeque<Bytes>,
    remaining: u64,
}

impl FramedBody {
    pub(super) fn new(mut bytes: Bytes) -> Self {
        let remaining = bytes.len() as u64;
        let mut frames = VecDeque::new();
        while !bytes.is_empty() {
            let take = bytes.len().min(FRAME_SIZE);
            frames.push_back(bytes.split_to(take));
        }
        Self { frames, remaining }
    }
}

impl http_body::Body for FramedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let frame = self.frames.pop_front();
        if let Some(bytes) = &frame {
            self.remaining -= bytes.len() as u64;
        }
        Poll::Ready(frame.map(http_body::Frame::data).map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining)
    }
}

fn filled(byte: u8, len: usize) -> Bytes {
    Bytes::from(vec![byte; len])
}

pub(super) async fn upload_owned(
    service: &S3Service,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part: i32,
    body: Bytes,
) -> String {
    let request = signed(
        http::Method::PUT,
        &format!("/{bucket}/{key}?partNumber={part}&uploadId={upload_id}"),
        body.clone(),
    );
    let (parts, _) = request.into_parts();
    let response = collect(service.call(http::Request::from_parts(parts, FramedBody::new(body))).await)
        .await
        .expect("a finite response");
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    header(&response, "etag")
        .expect("a part entity tag")
        .to_str()
        .expect("an ASCII entity tag")
        .to_owned()
}

/// Negative — an undersized first part cannot publish and can be replaced for a retry.
#[tokio::test]
async fn n_undersized_first_part_is_rejected_without_retiring_the_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-small-first").await;
    let upload_id = initiate(&service, "mpu-small-first", "key").await;
    let small = upload_part(&service, "mpu-small-first", "key", &upload_id, 1, b"small").await;
    let last = upload_part(&service, "mpu-small-first", "key", &upload_id, 2, b"last").await;

    let rejected = complete(&service, "mpu-small-first", "key", &upload_id, &[(1, &small), (2, &last)]).await;
    assert_eq!(rejected.status(), 400, "{}", String::from_utf8_lossy(rejected.body()));
    assert!(String::from_utf8_lossy(rejected.body()).contains("<Code>EntityTooSmall</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/mpu-small-first/key", Bytes::new()))
            .await
            .status(),
        404
    );
    let replacement = upload_owned(&service, "mpu-small-first", "key", &upload_id, 1, filled(b'a', MIN_PART_SIZE)).await;
    let retried = complete(&service, "mpu-small-first", "key", &upload_id, &[(1, &replacement), (2, &last)]).await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — every non-final part is checked, not only the first one.
#[tokio::test]
async fn n_undersized_middle_part_is_rejected() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-small-middle").await;
    let upload_id = initiate(&service, "mpu-small-middle", "key").await;
    let first = upload_owned(&service, "mpu-small-middle", "key", &upload_id, 1, filled(b'a', MIN_PART_SIZE)).await;
    let middle = upload_part(&service, "mpu-small-middle", "key", &upload_id, 2, b"middle").await;
    let last = upload_part(&service, "mpu-small-middle", "key", &upload_id, 3, b"last").await;

    let rejected = complete(&service, "mpu-small-middle", "key", &upload_id, &[(1, &first), (2, &middle), (3, &last)]).await;
    assert_eq!(rejected.status(), 400, "{}", String::from_utf8_lossy(rejected.body()));
    assert!(String::from_utf8_lossy(rejected.body()).contains("<Code>EntityTooSmall</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/mpu-small-middle/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — a rejected completion creates no version record and retains the active upload.
#[tokio::test]
async fn n_undersized_completion_creates_no_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-small-version").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&service, "mpu-small-version", "Enabled")
            .await
            .status(),
        200
    );
    let upload_id = initiate(&service, "mpu-small-version", "key").await;
    let first = upload_part(&service, "mpu-small-version", "key", &upload_id, 1, b"small").await;
    let last = upload_part(&service, "mpu-small-version", "key", &upload_id, 2, b"last").await;

    let rejected = complete(&service, "mpu-small-version", "key", &upload_id, &[(1, &first), (2, &last)]).await;
    assert_eq!(rejected.status(), 400, "{}", String::from_utf8_lossy(rejected.body()));
    let versions = exchange(&service, signed(http::Method::GET, "/mpu-small-version?versions", Bytes::new())).await;
    assert!(!String::from_utf8_lossy(versions.body()).contains("<Version>"));
    let uploads = exchange(&service, signed(http::Method::GET, "/mpu-small-version?uploads", Bytes::new())).await;
    assert!(String::from_utf8_lossy(uploads.body()).contains(&upload_id));
}

/// Positive — the exact 5 MiB boundary is accepted and the final part may be smaller.
#[tokio::test]
async fn exact_minimum_non_final_part_and_small_final_part_complete() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-minimum").await;
    let upload_id = initiate(&service, "mpu-minimum", "key").await;
    let first = upload_owned(&service, "mpu-minimum", "key", &upload_id, 1, filled(b'a', MIN_PART_SIZE)).await;
    let last = upload_part(&service, "mpu-minimum", "key", &upload_id, 2, b"tail").await;

    let completed = complete(&service, "mpu-minimum", "key", &upload_id, &[(1, &first), (2, &last)]).await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    let fetched = exchange(&service, signed(http::Method::GET, "/mpu-minimum/key", Bytes::new())).await;
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.body().len(), MIN_PART_SIZE + 4);
    assert_eq!(&fetched.body()[..4], b"aaaa");
    assert_eq!(&fetched.body()[MIN_PART_SIZE..], b"tail");
}
