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

//! Shares: pagination
//! Members: ListBuckets, ListObjectVersions, ListObjects, ListObjectsV2
//!
//! Responsible for: what a page cursor is allowed to be — [`CursorSpec`], the ceiling every cursor
//! is read under, and [`key_count`], the one place the returned-entry arithmetic is written.
//! NOT responsible for: minting a cursor, storing one, or deciding what a backend does with the
//! bytes. A cursor's meaning belongs to whoever produced it; this module only decides what may be
//! accepted from a client, and refuses to give the value any structure at all.
//! Upstream: [`crate::error::PreAuthError`]. Downstream: the four listing operations named above,
//! and — when the multipart family lands — `ListParts` and `ListMultipartUploads`, which page the
//! same way and must be added to the member list in the same change that makes them use this.
//!
//! # Why a cursor gets a type instead of being a `String`
//!
//! Every cursor in this family arrives from the client: `marker`, `continuation-token`,
//! `key-marker`, `version-id-marker`. Three of the four are echoes of something the server minted,
//! which is exactly what makes them dangerous — the code that reads one is written by somebody who
//! knows what the server put in it, and a client is under no obligation to send that back.
//!
//! The two failures this exists to prevent are specific. The first is treating a cursor as a path
//! or a key prefix, at which point `../../` is a traversal the listing performs on request. The
//! second is treating it as unbounded, at which point a megabyte of query string is a megabyte the
//! server holds per connection. Neither is caught by review reliably, so neither is left to it:
//! [`CursorSpec::accept`] is the only sanctioned way to turn the wire bytes into a value, it never
//! returns anything but a borrowed slice of the input, and it has no method that parses.
//!
//! # Why the page-size arithmetic is here and not in the operations
//!
//! `KeyCount` is the number of entries plus the number of common prefixes. An implementation that
//! counts only the entries returns a count below the requested page size on a delimited listing,
//! and a client that compares the two decides the page was short, asks for the next one, and gets
//! the same answer forever. The failure is invisible in any single response — see s3s#350 — so the
//! arithmetic is written once, here, rather than four times in four operations.

use crate::error::PreAuthError;

/// The largest cursor accepted from a client, in bytes.
///
/// Well above anything a server in this family mints — an encoded key plus a version id is a few
/// hundred bytes at the outside — and far below the point where holding one per in-flight request
/// is interesting. The value is a ceiling, not a size: nothing allocates it.
pub const MAX_CURSOR_BYTES: usize = 2048;

/// What a cursor's bytes mean to the operation that reads them.
///
/// The distinction is not cosmetic. A key cursor is a key: the client may legitimately compose one
/// itself, and the listing compares it against the key space. An opaque cursor is a token the
/// server minted, and the only correct thing to do with the bytes is hand them back to whatever
/// produced them. Recording which is which is what stops the second kind from being compared,
/// split, or joined onto a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CursorKind {
    /// A server-minted token with no client-visible structure.
    Opaque,
    /// An object key the client may compose itself.
    Key,
}

/// One cursor an operation pages with: the query key that carries it, and what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CursorSpec {
    query_key: &'static str,
    kind: CursorKind,
}

impl CursorSpec {
    /// A server-minted token, echoed back by the client and never interpreted.
    #[must_use]
    pub const fn opaque(query_key: &'static str) -> Self {
        Self {
            query_key,
            kind: CursorKind::Opaque,
        }
    }

    /// A cursor that is an object key, which the client may compose itself.
    #[must_use]
    pub const fn key(query_key: &'static str) -> Self {
        Self {
            query_key,
            kind: CursorKind::Key,
        }
    }

    /// The query key that carries this cursor.
    #[must_use]
    pub const fn query_key(&self) -> &'static str {
        self.query_key
    }

    /// What the bytes mean.
    #[must_use]
    pub const fn kind(&self) -> CursorKind {
        self.kind
    }

    /// Checks one cursor value from a request and returns it unchanged.
    ///
    /// Returns the input slice, never an owned or rewritten value: a function that could return
    /// something other than what arrived is a function somebody will use to normalise a cursor,
    /// and a normalised cursor no longer matches the one the server minted.
    ///
    /// An empty value is accepted and means "from the beginning", which is what every SDK sends
    /// when it clears a cursor. That is deliberate: rejecting it turns a correct client into a
    /// failing one, and it is indistinguishable from the parameter being absent.
    ///
    /// # Errors
    ///
    /// [`PreAuthError::invalid_argument`] when the value is longer than [`MAX_CURSOR_BYTES`] or
    /// carries a byte that cannot appear in an XML document — the C0 controls and `DEL`. The
    /// second check is not about the cursor at all: the value is echoed into the response body,
    /// and a control character there produces a document no client can parse, from input the
    /// client chose. The message is a constant, so nothing the caller sent is reflected back.
    pub fn accept<'a>(&self, raw: &'a str) -> Result<&'a str, PreAuthError> {
        if raw.len() > MAX_CURSOR_BYTES {
            return Err(PreAuthError::invalid_argument(
                "the pagination cursor is longer than this service accepts",
            ));
        }
        if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(PreAuthError::invalid_argument(
                "the pagination cursor carries a byte that cannot be written into a response document",
            ));
        }
        Ok(raw)
    }
}

/// The number of entries a listing page reports: its entries plus its common prefixes.
///
/// Saturating rather than wrapping. A page cannot hold `i32::MAX` entries — the page size ceiling
/// is four orders of magnitude below it — so the saturation is unreachable in practice, and the
/// alternative is either a panic or a wrap to a negative count. A negative count is the one answer
/// a client will act on and no client will survive.
#[must_use]
pub fn key_count(entries: usize, common_prefixes: usize) -> i32 {
    let total = entries.saturating_add(common_prefixes);
    i32::try_from(total).unwrap_or(i32::MAX)
}

#[cfg(test)]
// Test code only. The crate denies these three so that no request path can panic; a test that
// cannot assert an `Ok` is a test that says less than it should.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const CONTINUATION: CursorSpec = CursorSpec::opaque("continuation-token");
    const MARKER: CursorSpec = CursorSpec::key("marker");

    #[test]
    fn a_cursor_is_returned_exactly_as_it_arrived() {
        let raw = "eyJrZXkiOiJhLzEudHh0In0";
        assert_eq!(CONTINUATION.accept(raw).expect("a plain token is accepted"), raw);
    }

    /// Negative: a cursor is never a path, so the traversal spelling is data like any other and
    /// must not be given meaning here. The guarantee is that nothing is parsed, not that this
    /// particular spelling is blocked — a blocklist would be the wrong shape of answer.
    #[test]
    fn a_traversal_spelling_is_returned_as_data_and_not_as_a_path() {
        let raw = "../../etc/passwd";
        let accepted = MARKER.accept(raw).expect("the value is inert text here");
        assert_eq!(accepted, raw, "the cursor must not be rewritten");
        assert_eq!(MARKER.kind(), CursorKind::Key);
    }

    /// Negative: the ceiling is enforced, and the value just under it is not.
    #[test]
    fn a_cursor_over_the_ceiling_is_refused() {
        let at_ceiling = "a".repeat(MAX_CURSOR_BYTES);
        assert!(CONTINUATION.accept(&at_ceiling).is_ok(), "the ceiling itself is accepted");

        let over = "a".repeat(MAX_CURSOR_BYTES + 1);
        let err = CONTINUATION.accept(&over).expect_err("one byte over must be refused");
        assert!(!format!("{err:?}").contains("aaaa"), "the message must not echo the cursor");
    }

    /// Negative: a byte that cannot be written into XML is refused rather than echoed into a body
    /// the client then cannot parse.
    #[test]
    fn a_cursor_carrying_a_control_byte_is_refused() {
        for raw in ["a\u{0}b", "a\u{1}b", "a\u{1f}b", "a\u{7f}b", "line\nbreak", "tab\there"] {
            assert!(CONTINUATION.accept(raw).is_err(), "{raw:?} must be refused");
        }
    }

    /// Negative: an empty cursor is not an error. Every SDK sends one when it clears its state,
    /// and refusing it breaks correct clients while catching nothing.
    #[test]
    fn an_empty_cursor_is_accepted() {
        assert_eq!(CONTINUATION.accept("").expect("empty is a legal cursor"), "");
    }

    /// Multi-byte text survives unchanged: the ceiling is bytes, and the check is byte-wise, so a
    /// key in a non-Latin script must not be refused for its length in characters.
    #[test]
    fn multi_byte_text_is_accepted_unchanged() {
        // Written as escapes so the source stays ASCII while the bytes under test stay CJK,
        // which is the case that actually turns up in object keys. Spelling it literally puts
        // the file in breach of the English-only rule, which has no exemption for fixtures.
        // U+76EE U+5F55 / U+6587 U+4EF6 — "directory/file" in Chinese.
        let raw = "\u{76ee}\u{5f55}/\u{6587}\u{4ef6}.txt";
        assert_eq!(MARKER.accept(raw).expect("multi-byte text is legal"), raw);
    }

    #[test]
    fn the_key_count_is_entries_plus_common_prefixes() {
        assert_eq!(key_count(0, 0), 0);
        assert_eq!(key_count(3, 0), 3);
        assert_eq!(key_count(0, 4), 4, "common prefixes alone still count");
        assert_eq!(key_count(2, 5), 7, "a delimited page counts both lists");
    }

    /// Negative: the arithmetic saturates rather than wrapping into a negative count, which is the
    /// one answer a client would act on and none would survive.
    #[test]
    fn the_key_count_saturates_instead_of_going_negative() {
        assert_eq!(key_count(usize::MAX, usize::MAX), i32::MAX);
        assert!(key_count(usize::MAX, 1) >= 0);
    }

    #[test]
    fn a_cursor_spec_reports_the_query_key_it_reads() {
        assert_eq!(CONTINUATION.query_key(), "continuation-token");
        assert_eq!(CONTINUATION.kind(), CursorKind::Opaque);
        assert_eq!(MARKER.query_key(), "marker");
    }
}
