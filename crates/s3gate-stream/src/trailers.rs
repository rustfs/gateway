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

//! The trailer section that arrives after the last byte of a body.
//!
//! Responsible for: carrying the trailing header fields, and being obtainable by a consumer
//! **only** as part of an end-of-stream event. There is deliberately no shared mutable slot
//! (`Arc<Mutex<Option<_>>>`, `OnceCell`, ...) anywhere: a slot makes "the body has been read
//! to the end" a comment-maintained convention, and a consumer that looks too early sees an
//! empty slot and cannot distinguish it from a body that carried no trailer at all.
//! NOT responsible for: deciding which trailer names are acceptable, verifying the digests
//! carried in them, or comparing them against header fields — all three are protocol rules and
//! live in the wire layer.
//! Upstream: `http::HeaderMap`. Downstream: `s3gate-http`, which builds the value at the end
//! of a decoded body, and the handler layer, which receives it through the end-of-stream event.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

/// The trailing header fields of a body.
///
/// Consumers obtain this type from [`PayloadRead::Eof`] or [`ReadProgress::Eof`] and from
/// nowhere else. The absence of trailer fields is represented by an empty map, never by
/// `Option::None`: "the producer sent no trailer" and "the body has not been read to the end"
/// are different facts, and a single `None` collapses them into one, which is how a trailer
/// carried digest ends up silently unverified.
///
/// [`PayloadRead::Eof`]: crate::PayloadRead::Eof
/// [`ReadProgress::Eof`]: crate::ReadProgress::Eof
#[derive(Debug, Default, Clone)]
pub struct TrailingHeaders(HeaderMap);

impl TrailingHeaders {
    /// An empty trailer section — what a producer reports when the body declared no trailer.
    #[must_use]
    pub fn empty() -> Self {
        Self(HeaderMap::new())
    }

    /// Builds a trailer section from an already assembled map.
    ///
    /// Producers call this at the moment they have finished decoding the body. Nothing in this
    /// crate can call it on a consumer's behalf, which is what keeps the ordering property: a
    /// value only exists once a producer has decided the body is over.
    #[must_use]
    pub fn from_header_map(map: HeaderMap) -> Self {
        Self(map)
    }

    /// Whether the producer reported any trailer field at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of trailer fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Looks a trailer field up by name.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.0.get(name)
    }

    /// Whether a trailer field with this name arrived.
    #[must_use]
    pub fn contains_key(&self, name: &HeaderName) -> bool {
        self.0.contains_key(name)
    }

    /// Iterates over the trailer fields.
    pub fn iter(&self) -> http::header::Iter<'_, HeaderValue> {
        self.0.iter()
    }

    /// Borrows the underlying map.
    ///
    /// The borrow is shared and read-only on purpose: the wire layer needs to walk the fields,
    /// and nothing needs to mutate them after the producer has closed the body.
    #[must_use]
    pub fn as_header_map(&self) -> &HeaderMap {
        &self.0
    }

    /// Consumes the trailer section and returns the underlying map.
    #[must_use]
    pub fn into_header_map(self) -> HeaderMap {
        self.0
    }
}

impl<'a> IntoIterator for &'a TrailingHeaders {
    type Item = (&'a HeaderName, &'a HeaderValue);
    type IntoIter = http::header::Iter<'a, HeaderValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
