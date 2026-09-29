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

//! Request builders shared by the acceptance suites.
//!
//! Responsible for: assembling `http::Request` heads, including the shapes a well-behaved client
//! library refuses to produce — duplicated `Host`, non-UTF-8 header bytes, an absolute-form
//! target that disagrees with its `Host` header.
//! NOT responsible for: assertions, which stay in the suite that makes them.
//! Upstream: `http`. Downstream: every test file in this directory.
// Each test binary compiles this module separately and uses a subset of it, so the unused-item
// and unreachable-pub lints fire on helpers another binary does use.
#![allow(dead_code, unreachable_pub)]

pub mod form;
pub mod ingest;

use http::{HeaderValue, Request, Version, header::HOST};
use rustfs_gateway_http::{Limits, WireReject, WireRequest};

/// The body every acceptance test uses; acceptance never reads one.
pub type TestBody = &'static str;

/// A request builder pre-set to the common origin-form shape.
pub fn origin_form(path_and_query: &str) -> Request<TestBody> {
    #[allow(clippy::expect_used)] // test fixture: a malformed literal here is a bug in the test
    Request::builder()
        .method("GET")
        .uri(path_and_query)
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request")
}

/// Accepts a request under the default limits.
pub fn accept(request: Request<TestBody>) -> Result<WireRequest<TestBody>, WireReject> {
    WireRequest::accept(request, &Limits::default())
}

/// Accepts a request under caller-chosen limits.
pub fn accept_with(request: Request<TestBody>, limits: &Limits) -> Result<WireRequest<TestBody>, WireReject> {
    WireRequest::accept(request, limits)
}

/// A header value built from raw bytes, including bytes that are not UTF-8.
pub fn raw_value(bytes: &[u8]) -> HeaderValue {
    #[allow(clippy::expect_used)] // test fixture
    HeaderValue::from_bytes(bytes).expect("header value the http crate accepts")
}

/// An HTTP/2 request whose `:authority` and `host` header are set independently.
pub fn h2(authority: Option<&str>, host_header: Option<&str>) -> Request<TestBody> {
    let mut builder = Request::builder().method("GET").version(Version::HTTP_2);
    builder = match authority {
        Some(value) => builder.uri(format!("https://{value}/object.txt")),
        None => builder.uri("/object.txt"),
    };
    if let Some(value) = host_header {
        builder = builder.header(HOST, value);
    }
    #[allow(clippy::expect_used)] // test fixture
    builder.body("").expect("valid fixture request")
}

/// An HTTP/1.1 request with an absolute-form request target plus a `Host` header.
pub fn absolute_form(target: &str, host_header: &str) -> Request<TestBody> {
    #[allow(clippy::expect_used)] // test fixture
    Request::builder()
        .method("GET")
        .version(Version::HTTP_11)
        .uri(target)
        .header(HOST, host_header)
        .body("")
        .expect("valid fixture request")
}

/// The libtest name of a test in the calling module, as `--exact` on this binary must spell it.
///
/// Every source under `tests/` is a module of one consolidated target (rustfs/gateway#277), so a
/// probe that re-runs the current binary must name `<module>::<test>`, not `<test>`; and the same
/// helper keeps a source correct if it is ever linked on its own again, where `module_path!()` is
/// the crate name alone and the test name carries no prefix.
#[macro_export]
macro_rules! probe_test_name {
    ($local:expr) => {
        $crate::support::probe_test_name(module_path!(), $local)
    };
}

pub fn probe_test_name(module_path: &str, local: &str) -> String {
    match module_path.split_once("::") {
        Some((_, rest)) => format!("{rest}::{local}"),
        None => local.to_owned(),
    }
}

#[cfg(test)]
mod probe_name_tests {
    use super::probe_test_name;

    #[test]
    fn a_consolidated_module_qualifies_the_test_and_a_standalone_target_does_not() {
        assert_eq!(
            probe_test_name("integration::ingest_chunk_rules", "rss_probe"),
            "ingest_chunk_rules::rss_probe"
        );
        assert_eq!(probe_test_name("integration::a::b", "t"), "a::b::t");
        assert_eq!(probe_test_name("ingest_chunk_rules", "rss_probe"), "rss_probe");
        assert_ne!(probe_test_name("integration::ingest_chunk_rules", "rss_probe"), "rss_probe");
    }
}
