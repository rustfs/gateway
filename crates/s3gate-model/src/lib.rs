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

//! Smithy model parsing and the frozen s3gate IR.
//!
//! Responsible for: loading the pinned AWS Smithy model, stripping the traits that carry no wire
//! meaning, reading the hand-written overlays, and lowering both into IR documents shaped by
//! `spec/ir.schema.json`.
//! NOT responsible for: emitting Rust code or Markdown (that is `s3gate-codegen`), and no runtime
//! behaviour whatsoever.
//! Upstream: the pinned `model/` directory, including `model/overlays/`. Downstream: `s3gate-codegen`.
//!
//! Build-time only — never appears in a runtime dependency tree.
//!
//! ```text
//! model/s3.json ──strip──▶ smithy::Model ──┐
//!                                          ├──▶ lower::lower ──▶ ir::OperationIr
//! overlays/*.toml ──▶ overlay::Overlay ────┘
//! ```
//!
//! The crate carries no third-party dependency beyond `thiserror`: the workspace dependency set is
//! pinned and has no serde, so [`json`] and [`toml_lite`] are small hand-written readers.
#![forbid(unsafe_code)]

pub mod error;
pub mod ir;
pub mod json;
pub mod lower;
pub mod overlay;
pub mod smithy;
pub mod toml_lite;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use ir::OperationIr;
pub use lower::{Lowered, lower};
pub use overlay::Overlay;
pub use smithy::Model;
