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

//! Every query key the route table routes on, as one bit each.
//!
//! Responsible for: [`SubresourceBits`] — assigning a bit to each routing query key and reducing a
//! request's query string to a `u64` in one pass.
//! NOT responsible for: matching (`selector`), or the value dimension — `list-type=2` sets the
//! `list-type` bit and its value is still checked by a predicate, because a bitmap cannot hold a
//! value.
//! Upstream: `selector`, `rustfs-gateway-http`'s `QueryView`. Downstream: `compiled`.
//!
//! # The table is its own source
//!
//! The obvious implementation is a hand-written list of the forty-odd S3 subresource keywords,
//! compiled into a perfect hash. The failure mode of that design is drift: the list and the route
//! table are edited by different people at different times, and a key that is missing from the
//! list silently stops contributing to the mask, which silently changes routing.
//!
//! So the keys are *derived from the route table itself* at compile time. There is no second list
//! to keep in sync, a key cannot be added by hand without a selector that uses it, and the
//! sixty-four-bit ceiling becomes a real, testable failure ([`CompileError::TooManySubresourceKeys`])
//! rather than a silent truncation.
//!
//! # Why binary search and not a perfect hash
//!
//! `phf` is not a workspace dependency and this task may not add one. A sorted table of at most
//! sixty-four short keys is six comparisons at worst, allocates nothing, and — unlike a perfect
//! hash — needs no build script. If the key count ever approaches the ceiling, revisiting this is
//! a measurement, not a rewrite: the interface is two methods.

use rustfs_gateway_http::QueryView;

use super::selector::RouteEntry;

/// How many distinct routing query keys fit in the mask.
pub const MAX_SUBRESOURCE_KEYS: usize = 64;

/// Why a route table could not be compiled into its fast form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// More routing query keys than there are bits.
    ///
    /// Deliberately fatal. Truncating to sixty-four would drop keys from the mask and change
    /// routing without any diagnostic; widening to `u128` or splitting the mask into segments is a
    /// decision somebody has to make on purpose.
    TooManySubresourceKeys {
        /// How many distinct keys the table routes on.
        count: usize,
        /// The first key that did not fit, for the operator who has to act on this.
        overflow: &'static str,
    },
    /// A selector names a method outside the closed HTTP vocabulary the compiled table indexes.
    UnroutableMethod {
        /// The operation.
        op_name: &'static str,
        /// The method it names.
        method: String,
    },
    /// More entries than an operation id can address.
    TooManyEntries {
        /// How many entries the table holds.
        count: usize,
    },
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManySubresourceKeys { count, overflow } => write!(
                f,
                "the route table routes on {count} query keys, more than the {MAX_SUBRESOURCE_KEYS} bits of the \
                 subresource mask (first key over the line: {overflow:?}); widen the mask to u128 or segment it, \
                 do not drop keys"
            ),
            Self::UnroutableMethod { op_name, method } => {
                write!(f, "{op_name} routes on method {method}, which the compiled table does not index")
            }
            Self::TooManyEntries { count } => {
                write!(f, "{count} route entries is more than an operation id can address")
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Routing query keys, sorted, one bit each.
#[derive(Clone, Debug, Default)]
pub struct SubresourceBits {
    keys: Box<[(&'static str, u8)]>,
}

impl SubresourceBits {
    /// Assigns a bit to every query key any selector in the table mentions.
    ///
    /// # Errors
    ///
    /// [`CompileError::TooManySubresourceKeys`] when the table routes on more than
    /// [`MAX_SUBRESOURCE_KEYS`] distinct keys.
    pub fn derive(entries: &[RouteEntry]) -> Result<Self, CompileError> {
        let mut keys: Vec<&'static str> = entries
            .iter()
            .flat_map(|entry| {
                entry
                    .selector
                    .predicates()
                    .iter()
                    .filter_map(super::selector::Predicate::query_key)
            })
            .collect();
        keys.sort_unstable();
        keys.dedup();
        if keys.len() > MAX_SUBRESOURCE_KEYS {
            return Err(CompileError::TooManySubresourceKeys {
                count: keys.len(),
                overflow: keys.get(MAX_SUBRESOURCE_KEYS).copied().unwrap_or(""),
            });
        }
        let numbered = keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, u8::try_from(index).unwrap_or(0)))
            .collect::<Vec<_>>();
        Ok(Self {
            keys: numbered.into_boxed_slice(),
        })
    }

    /// How many keys carry a bit.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the table routes on no query key at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Every key with its bit, in key order.
    #[must_use]
    pub fn keys(&self) -> &[(&'static str, u8)] {
        &self.keys
    }

    /// The single-bit mask for a key, or zero when the table does not route on it.
    ///
    /// A key with no bit is inert by construction: no selector mentions it, so it cannot change
    /// which operation is selected. That is what makes `?x-id=PutObject` and the six pagination
    /// parameters free.
    #[must_use]
    pub fn mask_for(&self, key: &str) -> u64 {
        match self.keys.binary_search_by_key(&key, |(name, _)| *name) {
            Ok(index) => self
                .keys
                .get(index)
                .map_or(0, |(_, bit)| 1u64.checked_shl(u32::from(*bit)).unwrap_or(0)),
            Err(_) => 0,
        }
    }

    /// The mask of one request's query string.
    ///
    /// One pass over the already-indexed parameters, no allocation. A request with no query at all
    /// does not even enter the loop, which is the shape ninety-five percent of data-plane traffic
    /// has.
    #[must_use]
    pub fn mask_of(&self, query: QueryView<'_>) -> u64 {
        if self.keys.is_empty() {
            return 0;
        }
        let mut mask = 0u64;
        for (key, _) in query.iter() {
            mask |= self.mask_for(key);
        }
        mask
    }
}
