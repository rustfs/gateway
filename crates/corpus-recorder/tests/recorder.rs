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

//! Responsible for: the recorder's whole contract — the runtime gate, what reaches disk, what
//! the inner service sees, and that a build without the feature carries none of it.
//! Not responsible for: the corpus crate's own gate rules, which its own tests own.
//! Upstream: `rustfs_gateway_corpus_recorder` with `corpus-record` on (the crate lists itself as
//! a dev-dependency with the feature, so `cargo test --workspace` runs this target).
//! Downstream: nothing; this is a leaf test target.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "recorder/support.rs"]
mod support;

#[path = "recorder/gate.rs"]
mod gate;

#[path = "recorder/capture.rs"]
mod capture;

#[path = "recorder/signed_chunks.rs"]
mod signed_chunks;

#[path = "recorder/symbols.rs"]
mod symbols;
