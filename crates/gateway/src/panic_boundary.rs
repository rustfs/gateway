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

//! The panic boundary around deployment-provided work.
//!
//! Responsible for: catching both future construction and polling panics, and panics in the
//! synchronous report callbacks that run after an answer is settled — the authorization audit sink
//! and the request observer — so that neither can change what the caller receives.
//! NOT responsible for: deciding which failures permit or refuse a request.
//! Upstream: a boxed deployment future, or a report callback. Downstream: `crate::service` failure
//! settlement, `crate::ext::authz_audit`, `crate::ext::observer`.

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

/// Runs one report callback so that a panic in it cannot reach the answer it reports on.
///
/// A panic is reported as one fixed line naming `callback`, and nothing from the payload, which
/// is deployment text. The payload is then released under a second boundary: a payload whose
/// destructor panics would otherwise unwind out of here after all. That second payload is leaked
/// rather than dropped, because its destructor may panic too and nothing bounds how often.
pub(crate) fn contain_report(callback: &'static str, report: impl FnOnce()) {
    let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(report)) else {
        return;
    };
    tracing::error!(
        target: crate::logging::TARGET,
        event = crate::logging::EVENT_REPORT_PANICKED,
        component = crate::logging::COMPONENT,
        subsystem = crate::logging::SUBSYSTEM_REPORT,
        result = "contained",
        callback,
        "{callback} panicked; the response was not changed"
    );
    if let Err(secondary) = std::panic::catch_unwind(AssertUnwindSafe(move || drop(payload))) {
        std::mem::forget(secondary);
    }
}
