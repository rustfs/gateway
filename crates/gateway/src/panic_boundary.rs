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

//! The panic boundary around deployment-provided asynchronous work.
//!
//! Responsible for: catching both future construction and polling panics.
//! NOT responsible for: deciding which failures permit or refuse a request.
//! Upstream: a boxed deployment future. Downstream: `crate::service` failure settlement.

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::task::Poll;

use rustfs_gateway_core::BoxFuture;

pub(crate) async fn catch_boxed_future<'a, T, F>(build: F) -> Result<T, ()>
where
    F: FnOnce() -> BoxFuture<'a, T>,
{
    let Ok(mut future) = std::panic::catch_unwind(AssertUnwindSafe(build)) else {
        return Err(());
    };
    poll_fn(
        move |context| match std::panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        },
    )
    .await
}
