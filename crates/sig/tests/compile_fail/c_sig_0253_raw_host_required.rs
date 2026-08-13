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

//! `c-sig-0253`: a resolver's normalized target cannot enter canonical signing.
//!
//! Responsible for: proving `CanonicalRequestSpec` accepts only the wire-owned `RawHost`.
//! NOT responsible for: host resolution or runtime signature comparison.
//! Upstream: a resolver-derived target. Downstream: canonical request construction.

use http::{HeaderMap, Method};
use rustfs_gateway_sig::{CanonicalRequestSpec, PayloadMode, RawQuery, SignedHeaderSet, UriPathCandidates};

struct ResolvedTarget(String);

fn main() {
    let headers = HeaderMap::new();
    let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).unwrap();
    let paths = UriPathCandidates::new("/").unwrap();
    let query = RawQuery::new("");
    let resolved = ResolvedTarget("example.com".to_owned());
    let _ = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &query,
        &headers,
        &signed,
        &resolved,
        PayloadMode::Empty.canonical_payload_token(),
    );
}
