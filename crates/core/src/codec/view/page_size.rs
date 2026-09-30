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

//! The page-size ceiling a view clamps one query parameter to.
//!
//! Responsible for: [`PageSizeCeiling`], its parameter, its ceiling and the clamp itself.
//! NOT responsible for: which listings a deployment clamps (the gateway's view policy) or reading
//! the parameter (`super::MetaView::query`).
//! Upstream: the deployment's view policy. Downstream: `super::MetaView`.

/// A page-size query parameter answered with its ceiling when the request asked for more.
///
/// The RustFS profile's reading of an oversized page size (rustfs/backlog#1677, R1): RustFS lowers
/// `max-keys` to the listing maximum before it lists or echoes it, so a client asking for five
/// thousand reads a page of at most a thousand and `<MaxKeys>1000</MaxKeys>`. Only a value that
/// parses as an integer above the ceiling is replaced; an unparseable or negative value reaches
/// the decoder as sent and is refused there exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSizeCeiling {
    parameter: &'static str,
    ceiling: i32,
}

impl PageSizeCeiling {
    /// Clamps the query parameter `parameter` to `ceiling`.
    #[must_use]
    pub const fn new(parameter: &'static str, ceiling: i32) -> Self {
        Self { parameter, ceiling }
    }

    /// The query parameter this ceiling governs.
    #[must_use]
    pub const fn parameter(&self) -> &'static str {
        self.parameter
    }

    /// The largest page size the parameter is answered with.
    #[must_use]
    pub const fn ceiling(&self) -> i32 {
        self.ceiling
    }

    /// `value` clamped, when it is an integer above the ceiling under the codec's own integer
    /// reading, and `None` otherwise.
    pub(super) fn clamp(&self, value: &str) -> Option<i32> {
        crate::codec::value::parse_integer(value).filter(|&requested| requested > self.ceiling)?;
        Some(self.ceiling)
    }
}
