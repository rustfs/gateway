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
//! Responsible for: [`SubresourceBits`] — validating that every standard selector uses the
//! codegen-owned bit assignment and exposing that assignment to route compilation.
//! NOT responsible for: matching (`selector`), or the value dimension — `list-type=2` sets the
//! `list-type` bit and its value is still checked by a predicate, because a bitmap cannot hold a
//! value.
//! Upstream: `selector`, `rustfs-gateway-http`'s generated bit table. Downstream: `compiled`.
//!
//! # Codegen is the only source
//!
//! The obvious implementation is a hand-written list of the forty-odd S3 subresource keywords,
//! compiled into a perfect hash. The failure mode of that design is drift: the list and the route
//! table are edited by different people at different times, and a key that is missing from the
//! list silently stops contributing to the mask, which silently changes routing.
//!
//! Codegen extracts the standard keys from the lowered selectors and emits the PHF table consumed
//! by the HTTP query index. Route compilation validates every standard selector against that
//! authority. Third-party operations may introduce keys codegen cannot know; those remain residual
//! predicates and take the slower, semantics-preserving path.
//!
//! # Why this type still stores keys
//!
//! Compilation and explanations need to report which keys this particular table routes on. The
//! sorted slice serves that startup-only purpose; request lookup uses the PHF-derived mask already
//! stored in `QueryIndex` and never searches this slice.

use rustfs_gateway_http::subresource_bit;

use crate::op::is_standard_operation_name;

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
    /// A selector key is absent from the codegen-owned PHF table.
    UnknownSubresourceKey {
        /// The selector key codegen failed to emit.
        key: &'static str,
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
            Self::UnknownSubresourceKey { key } => write!(
                f,
                "route selector key {key:?} is absent from the generated subresource bit table; regenerate from the lowered selectors"
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
    active_mask: u64,
}

impl SubresourceBits {
    /// Collects the generated bit for every standard query key the table routes on.
    ///
    /// # Errors
    ///
    /// [`CompileError::TooManySubresourceKeys`] when the table routes on more than
    /// [`MAX_SUBRESOURCE_KEYS`] distinct generated keys, or
    /// [`CompileError::UnknownSubresourceKey`] when a standard selector is absent from codegen.
    pub fn derive(entries: &[RouteEntry]) -> Result<Self, CompileError> {
        let mut keys = Vec::new();
        for entry in entries {
            for key in entry
                .selector
                .predicates()
                .iter()
                .filter_map(super::selector::Predicate::query_key)
            {
                let mask = subresource_bit(key);
                if mask == 0 {
                    if is_standard_operation_name(entry.op_name) {
                        return Err(CompileError::UnknownSubresourceKey { key });
                    }
                    continue;
                }
                keys.push(key);
            }
        }
        keys.sort_unstable();
        keys.dedup();
        if keys.len() > MAX_SUBRESOURCE_KEYS {
            return Err(CompileError::TooManySubresourceKeys {
                count: keys.len(),
                overflow: keys.get(MAX_SUBRESOURCE_KEYS).copied().unwrap_or(""),
            });
        }
        let mut numbered = Vec::with_capacity(keys.len());
        let mut active_mask = 0u64;
        for key in keys {
            let mask = subresource_bit(key);
            let bit = u8::try_from(mask.trailing_zeros()).unwrap_or(0);
            numbered.push((key, bit));
            active_mask |= mask;
        }
        Ok(Self {
            keys: numbered.into_boxed_slice(),
            active_mask,
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

    /// The single-bit mask for a generated key, or zero for an inactive or third-party key.
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

    /// Keeps only generated bits that this compiled table has selectors for.
    #[must_use]
    pub const fn restrict(&self, mask: u64) -> u64 {
        mask & self.active_mask
    }
}
