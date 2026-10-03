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

//! The `Content-Encoding` a request view hands on once the `aws-chunked` framing is removed
//! (rustfs/gateway#813).
//!
//! Responsible for: pinning `without_aws_chunked` — the framing token removed wherever it stands
//! and however it is cased, every other coding kept in its spelling and order.
//! NOT responsible for: decoding a chunked body (`rustfs-gateway-stream`).
//! Upstream: `super` (`crate::codec::view`). Downstream: nothing.

use super::without_aws_chunked;

/// Negative — the framing token is removed wherever it stands and however it is cased, the
/// other codings keep their spelling and order, and a token-only value is absent
/// (rustfs/gateway#813).
#[test]
fn n_aws_chunked_is_removed_and_nothing_else_is() {
    assert_eq!(without_aws_chunked("gzip, aws-chunked").as_deref(), Some("gzip"));
    assert_eq!(without_aws_chunked("aws-chunked,gzip").as_deref(), Some("gzip"));
    assert_eq!(without_aws_chunked("br, AWS-Chunked, gzip").as_deref(), Some("br, gzip"));
    assert_eq!(without_aws_chunked("aws-chunked").as_deref(), None);
    assert_eq!(without_aws_chunked(" aws-chunked , ").as_deref(), None);
    assert_eq!(without_aws_chunked("gzip").as_deref(), Some("gzip"));
    assert_eq!(without_aws_chunked("x-aws-chunked").as_deref(), Some("x-aws-chunked"));
}
