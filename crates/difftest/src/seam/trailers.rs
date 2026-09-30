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

//! The trailer section each stack hands a RustFS upload body, as that body reads it
//! (rustfs/gateway#1148).
//!
//! Responsible for: [`TrailerView`], one handle's state once the body was drained, read from the
//! legacy stack's own handle and from the handle the RustFS profile's adapter attaches
//! (`LegacyTrailers`), so the seam diff compares the two like any other member; and [`attach`],
//! the adapter's step that makes one where the legacy stack would.
//! NOT responsible for: draining (`stacks.rs`), or which requests reach an upload handler
//! (`table.rs`).
//! Upstream: the compat seam's trailer handle. Downstream: `stacks.rs`, `table.rs`, `mod.rs`.

use rustfs_gateway::{Operation, Req};
use rustfs_gateway_types::compat::s3s_0_17_0::trailers::{LegacyTrailers, legacy_attaches_trailers};

use crate::s3s;

/// A trailer handle as a RustFS body reads it after the body ended (the RustFS trailer adapter,
/// `rustfs/src/app/trailer_adapter.rs:22-44` on rustfs/rustfs `3268c42e00`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrailerView {
    /// No handle was handed over.
    Absent,
    /// A handle whose section never arrived: every lookup stays pending.
    Pending,
    /// The fields of the section, sorted.
    Fields(Vec<(String, Vec<u8>)>),
}

fn fields(map: &http::HeaderMap) -> TrailerView {
    let mut fields: Vec<(String, Vec<u8>)> = map
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    fields.sort();
    TrailerView::Fields(fields)
}

/// The legacy stack's handle.
pub(crate) fn legacy_view(handle: Option<&s3s::TrailingHeaders>) -> TrailerView {
    handle.map_or(TrailerView::Absent, |handle| handle.read(fields).unwrap_or(TrailerView::Pending))
}

/// The handle the RustFS profile's adapter attached.
pub(crate) fn gateway_view(handle: Option<&LegacyTrailers>) -> TrailerView {
    handle.map_or(TrailerView::Absent, |handle| handle.read(fields).unwrap_or(TrailerView::Pending))
}

/// The adapter's step for an upload: a fresh handle exactly where the legacy stack attaches one —
/// `request`'s principal carries a verified SigV4 scope and its `x-amz-content-sha256` names an
/// aws-chunked payload — for the upload's body to fill (`LegacyTrailers::publishing`).
pub(crate) fn attach<O: Operation>(request: &Req<O>, headers: &http::HeaderMap) -> Option<LegacyTrailers> {
    let verified = request.context().verified_scope().is_some();
    legacy_attaches_trailers(verified, headers).then(LegacyTrailers::default)
}
