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

//! `c-sig-0122`: secret bytes cannot be rendered through `Display`.
//!
//! Responsible for: proving a formatting macro cannot expose `SecretBytes`.
//! NOT responsible for: log capture at the request boundary.
//! Upstream: `rustfs_gateway_sig::SecretBytes`. Downstream: logging callers.

use rustfs_gateway_sig::SecretBytes;

fn main() {
    let secret = SecretBytes::new(b"secret");
    let _ = format!("{secret}");
}
