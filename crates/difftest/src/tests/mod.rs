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

//! The decode diff's own tests.
//!
//! Responsible for: judging the request matrix (`matrix.rs`) and the output matrix
//! (`encoding.rs`) the library's `samples` module holds, the negative
//! controls that break the gateway side on purpose (`controls.rs`), the register's refusals
//! (`register.rs`), and the member census against the generated DTO (`census.rs`).
//! NOT responsible for: anything the library does not do.
//! Upstream: the library. Downstream: none.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]

mod census;
mod controls;
mod encode_controls;
mod encoding;
mod fuzz;
mod matrix;
mod register;
mod runner;
mod rustfs_profile;
mod rustfs_selection;
mod seam;
mod seam_answers;
mod seam_outputs;
mod seam_overrides;
mod shadow;
