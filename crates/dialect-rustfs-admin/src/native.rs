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

//! Native RustFS admin declarations and listener-specific extension tables.
//!
//! Responsible for: assembling the native host's claimed admin operations, authenticated fallbacks
//! and STS form route into [`OVERLAY`] and [`dialect`], and exposing listener-specific extension
//! registrations under [`extensions`] while reusing unchanged operation types from [`crate::ops`].
//! NOT responsible for: backend handler execution, validating the recorded inventory
//! (`rustfs-gateway-goldens`), or the frozen v1 combined dialect ([`crate::dialect`]).
//! Upstream: `rustfs-gateway-core`'s dialect builder and `cargo xtask rustfs-admin-dialect`.
//! Downstream: RustFS native S3 and control-plane listeners.

use rustfs_gateway_core::dialect::{ClaimedRoute, Dialect, DialectBuilder, DialectError, DialectOverlay};

pub mod extensions;
mod fold;
pub mod ops;
mod rows;

pub use fold::fold_every_operation;
pub use rows::{FORM_ROUTES, PENDING, ROUTES, RUSTFS_SOURCE_COMMIT, STAYING};

/// The claimed operations, fallbacks and STS row for this host inventory.
pub static OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-native-admin",
    vendor: "rustfs",
    claims: crate::CLAIMS,
    operations: rows::OVERLAY_ROWS,
};

/// A typed visitor that receives the operation's placement in this inventory.
pub trait OperationFold {
    /// The value passed between operations.
    type Carry;
    /// Visits one operation and its native claimed route.
    fn step<O: crate::AdminOperation>(&mut self, carry: Self::Carry, route: ClaimedRoute) -> Self::Carry;
}

struct Declare;

impl OperationFold for Declare {
    type Carry = DialectBuilder;
    fn step<O: crate::AdminOperation>(&mut self, builder: DialectBuilder, route: ClaimedRoute) -> DialectBuilder {
        builder.declare_claimed::<O>(route)
    }
}

/// Builds the native admin dialect. The host registers its handlers separately.
///
/// # Errors
///
/// Returns any mismatch between an operation's declaration and the reviewed overlay rows.
pub fn dialect() -> Result<Dialect, Vec<DialectError>> {
    use crate::ops::{admin_fallback, admin_v4_fallback, sts_form_post};
    fold_every_operation(&mut Declare, Dialect::assemble(&OVERLAY))
        .declare_claimed::<admin_v4_fallback::AdminV4Fallback>(admin_v4_fallback::ROUTE)
        .declare_claimed::<admin_fallback::AdminFallback>(admin_fallback::ROUTE)
        .declare_form::<sts_form_post::StsFormPost>(rows::STS_ROUTE)
        .build()
}
