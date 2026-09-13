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

//! Compile-time proof that a named subject cannot be forged (ADR-0025).
//!
//! Responsible for: showing only `SubjectRule::extract` produces a `SubjectName`, so the account an
//! authorizer judged is the one the query named, decoded once.
//! NOT responsible for: the extraction rules, which the unit tests hold.
//! Upstream: `rustfs_gateway_core::SubjectName`. Downstream: the trybuild harness.

use rustfs_gateway_core::{Subject, SubjectName};

fn main() {
    let _ = Subject::Named(SubjectName(Box::from("root")));
}
