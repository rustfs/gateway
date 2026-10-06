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

//! RustFS's admin API as gateway dialect operations (rustfs/backlog#1744).
//!
//! Responsible for: the `rustfs` dialect — its path-prefix claims, its overlay and one claimed
//! operation per migrated admin route, generated from the recorded route inventory — and the
//! shapes those operations share, plus the two fixed authenticated fallback handlers.
//! NOT responsible for: backend handlers (RustFS registers its own), the
//! routes of registration groups not migrated yet ([`PENDING`]), or validating the inventory
//! (`rustfs-gateway-goldens` does, and binds every operation here back to its row). Upstream:
//! `rustfs-gateway-core`'s dialect mechanism and `cargo xtask rustfs-admin-dialect`. Downstream:
//! RustFS, which installs [`rustfs_admin_dialect`] and registers a handler per operation.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
// No stdout, no stderr, no `dbg!` outside tests: a diagnostic is a `tracing` event (docs/observability.md).
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro))]

pub mod admin;
pub mod dialect;
pub mod ops;
pub mod record;
mod table;

pub use admin::{AdminBody, AdminOperation, AdminResponse, OperationFold};
pub use dialect::{CLAIMS, OVERLAY, rustfs_admin_dialect};
pub use record::{BodyKind, PendingGroup, RouteRecord, StayingRoute};
pub use table::{PENDING, ROUTES, RUSTFS_SOURCE_COMMIT, STAYING, fold_every_operation};
