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

//! Which characters an XML 1.0 document may contain at all.
//!
//! Responsible for: the `Char` production of XML 1.0 §2.2, as one predicate, and the substitute
//! the writer puts in place of a character that fails it.
//! NOT responsible for: escaping. `&`, `<`, `>` and `"` are all perfectly representable and are
//! [`crate::write`]'s business; this module answers the prior question of whether the character
//! has any spelling in an XML document, escaped or otherwise.
//! Upstream: nothing. Downstream: [`crate::read`], which refuses a document carrying one;
//! [`crate::write`], which cannot emit one; and `rustfs-gateway-types`, which re-exports the
//! predicate so the listing path can force percent-encoding on a stored key that fails it.
//!
//! # Why this is one function and not two
//!
//! The set the reader refuses and the set the writer cannot emit have to be the same set. If they
//! drift, either the gateway refuses a document it could have answered, or — the direction that
//! matters — it accepts a value on the way in and writes it into a response that no conforming
//! parser will accept, hiding every other value in the same document behind a syntax error. One
//! function, called from both, is the only shape in which they cannot drift.

/// Whether every character of a value can appear in an XML 1.0 document at all.
///
/// XML 1.0 admits tab, newline and carriage return out of the C0 controls and excludes the rest
/// **entirely** — escaped or not, `&#1;` is as illegal as the raw byte, because a character
/// reference to a character outside this production is itself a fatal error. `U+FFFE` and
/// `U+FFFF` are excluded for the same reason, and the surrogate range cannot occur in a `&str`.
///
/// `U+007F` (DEL) **is** admitted. XML 1.1 requires it to be escaped; XML 1.0, which is what S3
/// speaks, admits it raw, and measurement agrees — `expat` accepts `<v>a\u{7f}b</v>` and rejects
/// `<v>a\u{1}b</v>`.
///
/// This is about *representability*, not about escaping: `&`, `<`, `>` and `"` are all
/// representable and are [`crate::write`]'s business, not this predicate's.
#[must_use]
pub fn is_xml_representable(value: &str) -> bool {
    value.chars().all(is_xml_char)
}

/// The single-character half of [`is_xml_representable`], for the writer's per-character loop.
#[must_use]
pub fn is_xml_char(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
    )
}

/// What the writer emits in place of a character XML 1.0 cannot represent.
///
/// The writer has no option to refuse: `XmlWriter::finish` closes whatever is still open rather
/// than returning early, because a truncated document is the one failure a client cannot
/// distinguish from a dropped connection. So a value that reaches the writer is written, and the
/// only question is what byte stands in.
///
/// `U+FFFD` rather than dropping the character: an operator reading a response should be able to
/// see that something was there and could not be carried, and a silent deletion is
/// indistinguishable from a value that never held the byte. It is lossy either way, and it is
/// ambiguous with a `U+FFFD` the value genuinely held — which is why it is a backstop and not the
/// mechanism. Every caller-supplied value is refused by [`crate::read`] long before it gets here;
/// what remains is a value some backend already stored, which the gateway did not choose and
/// cannot refuse without hiding every sibling value in the same document.
pub const UNREPRESENTABLE: char = '\u{fffd}';
