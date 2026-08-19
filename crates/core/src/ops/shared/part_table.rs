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

//! Where the parts of a completed multipart object begin and end.
//!
//! Shares: range
//!
//! No `Members:` line, and that is the honest state rather than an omission. An `impl Operation`
//! is settled before a request is read, so no operation module can call this: the part table is a
//! fact only the *handler* has, exactly like the representation a precondition is evaluated
//! against. The caller is the backend, reaching it through the facade re-export.
//!
//! Responsible for: turning "part N of an object whose parts are these lengths" into the byte
//! window a `206` serves, and refusing every part number that names no window. It is the other
//! half of [`super::precondition::evaluate_range`], which is handed the object's total length and
//! nothing about where its parts begin and therefore stops at
//! [`super::precondition::RangeDecision::Part`].
//! NOT responsible for: producing a part table (storage's), deciding whether a part read carries
//! `x-amz-mp-parts-count` or which status it gets — both are policy, and
//! [`super::precondition::RangeDecision`] owns them — or the `Range`-and-`partNumber` conflict,
//! which `evaluate_range` refuses before this is reached.
//! Upstream: `rustfs-gateway-types`' `ErrorCode` and [`super::precondition`]. Downstream: the
//! facade re-export, and through it every backend that answers `partNumber`.

use rustfs_gateway_types::ErrorCode;

use super::precondition::{PreconditionRejection, RangeDecision};

/// Where one part of a completed multipart object begins and ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartWindow {
    /// First byte of the part, inclusive.
    pub start: u64,
    /// Last byte of the part, inclusive.
    pub end_inclusive: u64,
    /// The object's full length, which `Content-Range` reports.
    pub total: u64,
}

impl PartWindow {
    /// The same window as the ordinary [`RangeDecision::Partial`], so that `Content-Range`,
    /// `Content-Length` and the status are rendered by the code that already renders them for a
    /// byte range rather than by a second spelling in a backend.
    #[must_use]
    pub const fn as_decision(&self) -> RangeDecision {
        RangeDecision::Partial {
            start: self.start,
            end_inclusive: self.end_inclusive,
            total: self.total,
        }
    }
}

/// Resolves a `partNumber` selection against the lengths of the parts the object was completed
/// from, in part order.
///
/// [`super::precondition::evaluate_range`] cannot do this: it is given the object's total length and nothing about
/// where its parts begin, so [`RangeDecision::Part`] leaves it as a selector. The part table is
/// storage's to produce and this is the only place that reads one, which is what stops two
/// backends from disagreeing about which bytes part 2 is — the disagreement is invisible, because
/// a wrong offset still returns the right *number* of bytes.
///
/// # Errors
///
/// [`ErrorCode::INVALID_PART_NUMBER`] when the number names no part of this object: zero (parts
/// are numbered from one), a number past the end of the table, a table with no parts at all, a
/// part carrying no bytes — which has no last byte to report — or a table whose lengths do not fit
/// the address space. Every one of them is a request for a window that does not exist, and
/// answering any of them with bytes would hand a client part of some other part.
pub fn resolve_part(part_number: u32, part_lengths: &[u64]) -> Result<PartWindow, PreconditionRejection> {
    let refuse = |reason| Err(PreconditionRejection::new(ErrorCode::INVALID_PART_NUMBER, reason));
    let Some(index) = part_number.checked_sub(1).map(|index| index as usize) else {
        return refuse("a part number starts at 1, so 0 names no part of any object");
    };
    let Some(length) = part_lengths.get(index).copied() else {
        return refuse("the object holds fewer parts than the request named");
    };
    // Checked first, and not folded into the arithmetic below: `start + 0 - 1` does not overflow
    // for any part after the first, it answers `bytes 16-15/16` — a window that reads as valid
    // everywhere downstream and covers no byte the client asked for.
    if length == 0 {
        return refuse("the named part carries no bytes, so it names no window to serve");
    }
    let mut total: u64 = 0;
    let mut start: u64 = 0;
    for (position, part) in part_lengths.iter().enumerate() {
        let Some(sum) = total.checked_add(*part) else {
            return refuse("the object's parts do not fit the address space");
        };
        if position < index {
            start = sum;
        }
        total = sum;
    }
    let Some(end_inclusive) = start.checked_add(length).and_then(|end| end.checked_sub(1)) else {
        return refuse("the named part's last byte does not fit the address space");
    };
    Ok(PartWindow {
        start,
        end_inclusive,
        total,
    })
}
