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

//! A `PUT` with a query, which the RustFS admin dialect's account-naming routes send
//! (`add-user?accessKey=…`), and a bodiless `HEAD`, which the table catalog's existence probes
//! send.
//!
//! Responsible for: [`ContextRequest::put_with_query`] and [`ContextRequest::head`]. They live in a
//! child module because the parent is at its file-size ceiling, and a child can build a request
//! the way the parent does.
//! NOT responsible for: signing or sending it (the parent).
//! Upstream: `super::ContextRequest`. Downstream: `crate::rustfs_admin_dialect`.

use http::Method;

use super::ContextRequest;

impl ContextRequest {
    /// A bodiless `HEAD` of `path?query` on `host`.
    pub(crate) fn head(host: &str, path: &str, query: &str) -> Self {
        Self::new(Method::HEAD, host, path, query, b"")
    }

    /// A `PUT` of `body` to `path?query` on `host`.
    #[allow(
        dead_code,
        reason = "only the RustFS admin dialect sends one, through the s3s_f3e17541 compilation"
    )]
    pub(crate) fn put_with_query(host: &str, path: &str, query: &str, body: &[u8]) -> Self {
        Self::new(Method::PUT, host, path, query, body)
    }
}
