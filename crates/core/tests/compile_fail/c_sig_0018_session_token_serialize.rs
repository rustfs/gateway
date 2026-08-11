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

//! `c-sig-0018`: a session token cannot cross a real serde serialization boundary.
//!
//! Responsible for: proving `SessionToken` does not implement the actual `serde::Serialize` trait.
//! NOT responsible for: runtime token storage or redaction.
//! Upstream: `rustfs_gateway_sig::SessionToken`. Downstream: serialization callers.

use rustfs_gateway_sig::SessionToken;

fn main() {
    let token = SessionToken::new("secret").unwrap();
    let _ = serde_json::to_string(&token);
}
