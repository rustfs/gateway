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

//! Compile-time guard: `RenameSource` cannot be resolved without an `AuthorizedRead` proof.
//!
//! Responsible for: proving `RenameSource::resolve` rejects callers that do not hold a proof.
//! NOT responsible for: runtime authorization verdicts or rename source normalization.
//! Upstream: `rustfs_gateway_core::ops::rename_object::RenameSource`. Downstream: trybuild gate.

use rustfs_gateway_core::ops::rename_object::RenameSource;

fn expose(source: &RenameSource) {
    let _ = source.resolve();
}

fn main() {}
