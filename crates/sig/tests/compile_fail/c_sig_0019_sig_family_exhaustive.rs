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

//! `c-sig-0019`: downstream matches over signature families require a fallback.
//!
//! Responsible for: proving `SigFamily` remains non-exhaustive outside its crate.
//! NOT responsible for: runtime algorithm selection.
//! Upstream: `rustfs_gateway_sig::SigFamily`. Downstream: authentication callers.

use rustfs_gateway_sig::SigFamily;

fn main() {
    let family = SigFamily::V4;
    let _ = match family {
        SigFamily::V2 => "v2",
        SigFamily::V4 => "v4",
        SigFamily::V4a => "v4a",
    };
}
