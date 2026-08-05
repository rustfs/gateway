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

//! Code generator turning the s3gate IR into Rust sources.
//!
//! Responsible for: emitting `generated/**`, `spec/operations/*.toml`, `OPERATIONS.md`.
//! NOT responsible for: parsing Smithy (that is `s3gate-model`), runtime behaviour.
//! Upstream: `s3gate-model`. Downstream: the checked-in generated sources.
#![forbid(unsafe_code)]
