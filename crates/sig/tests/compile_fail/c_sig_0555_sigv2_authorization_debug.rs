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

//! `c-sig-0555`: a parsed SigV2 credential cannot be printed.
//!
//! Responsible for: proving `SigV2Authorization` has no `Debug`, so the presented signature cannot
//! reach a log line, a panic message or a `tracing` span.
//! NOT responsible for: redacting the access key id, which is a public identifier.
//! Upstream: `rustfs_gateway_sig::sig_v2::parse_authorization`. Downstream: every logging site.

use rustfs_gateway_sig::sig_v2::parse_authorization;

fn main() {
    let parsed = parse_authorization("AWS key:AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    println!("{parsed:?}");
}
