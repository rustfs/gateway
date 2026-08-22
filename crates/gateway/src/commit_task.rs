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

//! Detached ownership for work whose response head has already committed.
//!
//! Responsible for: spawning committed work independently of its response body and delivering the
//! terminal document to that body's one-shot receiver.
//! NOT responsible for: polling a payload stream, rendering terminal documents, or deciding when
//! response-head finalization permits the task to start.
//! Upstream: `crate::commit`. Downstream: the Tokio runtime captured by the facade call.

use bytes::Bytes;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_types::ErrorCode;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

/// The terminal document and observer verdict produced by committed work.
pub(crate) struct CommitTaskResult {
    document: Bytes,
    error: Option<ErrorCode>,
}

impl CommitTaskResult {
    /// Builds a successful terminal result.
    pub(crate) fn answer(document: Bytes) -> Self {
        Self { document, error: None }
    }

    /// Builds a late refusal whose code must reach the observer.
    pub(crate) fn refusal(document: Bytes, error: Option<ErrorCode>) -> Self {
        Self { document, error }
    }
}

/// Work held inert until every response-head mutation has finished.
pub(crate) struct PendingCommit {
    runtime: Handle,
    sender: oneshot::Sender<Bytes>,
    task: BoxFuture<'static, CommitTaskResult>,
}

impl PendingCommit {
    /// Captures the runtime, result channel, and still-unpolled work.
    pub(crate) fn new(runtime: Handle, sender: oneshot::Sender<Bytes>, task: BoxFuture<'static, CommitTaskResult>) -> Self {
        Self { runtime, sender, task }
    }

    /// Starts work independently of the response body's ownership.
    pub(crate) fn start(self, complete: Box<dyn FnOnce(Option<ErrorCode>) + Send>) {
        self.runtime.spawn(async move {
            let result = self.task.await;
            complete(result.error);
            let _ = self.sender.send(result.document);
        });
    }
}
