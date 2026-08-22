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

//! Shared generated-operation fixtures for committed-response tests.
//!
//! Responsible for: building signed `CopyObject` requests and a backend that commits before its
//! terminal output is known. NOT responsible for: wire timing or body collection assertions.
//! Upstream: `super` signing helpers. Downstream: pipeline and monomorphic integration tests.

use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway::{
    Handler, HandlerErrorContext, HandlerResult, HeadPart, MissingObject, Req, ResourceVisibility, Resp, ServiceBuilder,
    dto::{CopyObject, CopyObjectOutput},
};

/// How the generated `CopyObject` committed-response fixture ends.
#[derive(Clone, Copy)]
pub enum CopyCommit {
    /// The detached work returns the generated success document.
    Answer,
    /// The detached work reports that its source key disappeared.
    Fail,
}

struct CopyCommitBackend(CopyCommit);

impl Handler<CopyObject> for CopyCommitBackend {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let outcome = self.0;
        let head = HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head");
        Ok(Resp::commit(
            head,
            Box::pin(async move {
                match outcome {
                    CopyCommit::Answer => Ok(CopyObjectOutput::default()),
                    CopyCommit::Fail => {
                        Err(HandlerErrorContext::missing_object(MissingObject::Key, ResourceVisibility::Visible).into())
                    }
                }
            }),
        ))
    }
}

/// A builder reaching the real generated operation that permits an error after `200`.
#[must_use]
pub fn copy_commit_builder(outcome: CopyCommit) -> ServiceBuilder {
    super::wired_at_signed_time().register::<CopyObject, _>(Arc::new(CopyCommitBackend(outcome)))
}

/// A signed, body-less `CopyObject` request accepted by [`copy_commit_builder`].
#[must_use]
pub fn copy_commit_request() -> http::Request<Bytes> {
    super::signed_with(http::Method::PUT, "/destination/key", &[("x-amz-copy-source", "/source/key")])
}
