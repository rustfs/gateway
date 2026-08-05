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

//! Which operations a deployment insists on, and the one sentence it gets when some are missing.
//!
//! Responsible for: [`OperationSet`] — a named set of operation names — and [`MissingHandlers`],
//! whose `Display` is the human-readable replacement for a compile-time completeness check.
//! NOT responsible for: registering anything, calling anything, or deciding what a missing
//! operation does at request time (that is the 501 in `crate::dispatch`).
//! Upstream: `crate::op`'s standard-name set, derived from the generated route table.
//! Downstream: [`super::RouterBuilder::require`].
//!
//! # Why this exists at all
//!
//! The alternative was a bundle supertrait — `trait ObjectApi: Handler<A> + Handler<B> + ...` —
//! so that an incomplete backend failed to compile. It was measured: one missing implementation
//! produced **73** `E0277` errors, one per supertrait, and the bundle was not dyn compatible
//! either. Seventy-three errors is not a stronger guarantee than one sentence; it is the same
//! guarantee, delivered in a form nobody can read.
//!
//! So completeness is a run-time assertion made once, at assembly, and its whole quality bar is
//! the message. It is one line, it names what is missing, and it says how much is missing out of
//! how much was asked for.

use std::collections::BTreeSet;
use std::fmt;

use crate::op::standard_operation_names;

/// How many names are listed before the message truncates.
///
/// A backend that implements nothing would otherwise print every operation there is, and the
/// reader learns less from a screen of names than from a count.
const MAX_LISTED: usize = 10;

/// A set of operations, by name.
///
/// A name set rather than a bit set: an index-based set needs an index assignment, an index
/// assignment needs a generator, and a generated index that drifts from the route table silently
/// asserts the wrong operations. The set is consulted once per assembly, never per request, so its
/// cost is not interesting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationSet {
    names: BTreeSet<&'static str>,
}

impl OperationSet {
    /// The empty set: `require` on it always succeeds.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A set from names.
    #[must_use]
    pub fn of<I: IntoIterator<Item = &'static str>>(names: I) -> Self {
        Self {
            names: names.into_iter().collect(),
        }
    }

    /// Every AWS operation this build knows, taken from the generated route table.
    ///
    /// There is no hand-written `AWS_CORE` beside it. A curated subset cannot be derived from
    /// anything in the repository today, and a hand-written one would be a second source of truth
    /// about which operations exist — the exact drift this module avoids. When codegen emits
    /// curated sets, they belong there and this function stays as it is.
    #[must_use]
    pub fn aws_full() -> Self {
        Self::of(standard_operation_names())
    }

    /// This set plus another.
    #[must_use]
    pub fn union(mut self, other: &Self) -> Self {
        self.names.extend(other.names.iter().copied());
        self
    }

    /// Whether a name is in the set.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// How many operations are in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        self.names.iter().copied().collect::<Vec<_>>().into_iter()
    }

    /// The members of this set that `has` says are not handled.
    pub(crate) fn missing(&self, has: impl Fn(&str) -> bool) -> Option<MissingHandlers> {
        let missing: Vec<&'static str> = self.names.iter().copied().filter(|name| !has(name)).collect();
        if missing.is_empty() {
            return None;
        }
        Some(MissingHandlers {
            missing,
            required: self.names.len(),
        })
    }
}

/// The operations a required set asked for and the backend does not handle.
///
/// Its `Display` is a single line. That is asserted by a test rather than left to review: a
/// multi-line assembly error is scrolled past, and the whole reason this type exists instead of a
/// bundle trait is that a person has to be able to read the failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingHandlers {
    missing: Vec<&'static str>,
    required: usize,
}

impl MissingHandlers {
    /// The missing operations, sorted.
    #[must_use]
    pub fn missing(&self) -> &[&'static str] {
        &self.missing
    }

    /// How many operations the required set asked for.
    #[must_use]
    pub const fn required(&self) -> usize {
        self.required
    }
}

impl fmt::Display for MissingHandlers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("backend is missing handlers for: ")?;
        for (position, name) in self.missing.iter().take(MAX_LISTED).enumerate() {
            if position > 0 {
                f.write_str(", ")?;
            }
            f.write_str(name)?;
        }
        if let Some(rest) = self.missing.len().checked_sub(MAX_LISTED).filter(|rest| *rest > 0) {
            write!(f, ", ... and {rest} more")?;
        }
        write!(f, " ({} of {})", self.missing.len(), self.required)
    }
}

impl std::error::Error for MissingHandlers {}
