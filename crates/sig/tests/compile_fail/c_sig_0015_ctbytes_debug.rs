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

//! `c-sig-0015`: fixed-width signature bytes cannot be debug-printed.
//!
//! Responsible for: proving `CtBytes<32>` has no `Debug` implementation.
//! NOT responsible for: runtime logging policy.
//! Upstream: `rustfs_gateway_sig::CtBytes`. Downstream: logging callers.

use rustfs_gateway_sig::CtBytes;

fn main() {
    let bytes = CtBytes::<32>::from_array([0; 32]);
    println!("{bytes:?}");
}
