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

//! The entity tag, stored once as an opaque tag and rendered only with an explicit context.
//!
//! Responsible for: holding the *unquoted* opaque-tag plus its weakness flag and the `*` wildcard,
//! parsing every form a client is known to send, rendering the three forms S3 emits, RFC 9110
//! strong/weak comparison, and the multipart `<hex>-<N>` shape.
//! NOT responsible for: reading the `ETag` header off a request or writing it into XML (the wire
//! layers do that, by calling [`ETag::render`]), evaluating preconditions as a whole (that is the
//! `Conditional` operation cluster), and XML escaping — [`EtagRender::XmlQuoted`] returns the text
//! *value*, with literal quotation marks, and the writer escapes them.
//! Upstream: [`super::parse_error`]. Downstream: every operation that carries an `ETag`, the
//! precondition evaluator, and the multipart family.
//!
//! # Why this type exists
//!
//! In a codebase where an entity tag is a `String`, "does this position carry quotes?" is answered
//! by an `if` inside whichever serialiser happens to run. That question has been answered
//! inconsistently in the same codebase more than once — quotes were added to XML output in one
//! change and removed again for `GetObjectAttributes` in another, leaving two rules that
//! contradict each other (see the evidence links on the `c-etag-0001` conformance case). Here the
//! answer is a parameter: there is no `Display`, no `Into<String>`, and no default rendering, so
//! the caller cannot omit the context.

use std::borrow::Cow;

use md5::{Digest as _, Md5};

use super::parse_error::{ParseError, rules};
use crate::placeholder::WirePlaceholder;

/// The maximum number of parts a multipart upload may have, which bounds the `-N` suffix.
const MAX_MULTIPART_PARTS: u32 = 10_000;

/// Where an [`ETag`] is about to be written. There is no default, on purpose.
///
/// Exhaustive by construction: the IR froze exactly these three rendering contexts, and a fourth
/// one would be a wire-format change that has to travel through the IR first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtagRender {
    /// An HTTP header value: always quoted, `W/` prefixed when weak.
    ///
    /// Used by the `ETag` response header and by the conditional request headers.
    HeaderQuoted,
    /// An XML text node that carries *literal* double quotes around the tag.
    ///
    /// This is the normal case: `ListObjectsV2`, `HeadObject`'s body-less twin, the multipart
    /// responses. The quotes are returned as the byte `"`, and the writer this rendering is bound
    /// to escapes them, so the bytes on the wire read `&quot;d41d…&quot;`. That escaping is *not*
    /// something every text node gets — an object key carrying a quote comes back with the
    /// literal byte — so it belongs to this rendering context and travels with it.
    XmlQuoted,
    /// An XML text node with no quotes at all.
    ///
    /// `GetObjectAttributes` is the single AWS response that spells the tag bare. It is the whole
    /// reason this enum has three variants instead of two.
    XmlBare,
}

/// An immutable entity tag: the opaque-tag, its weakness, or the `*` wildcard.
///
/// The stored tag is always *unquoted*, whatever the input looked like, so two tags that differ
/// only in quoting compare equal. `PartialEq` is byte equality of that normalised tag plus the
/// weakness flag; it is **not** the RFC 9110 comparison — use [`ETag::matches_strong`] and
/// [`ETag::matches_weak`] for that, because they differ precisely on weak tags and on `*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ETag {
    weak: bool,
    any: bool,
    tag: Cow<'static, str>,
}

impl ETag {
    /// The `*` wildcard, as sent in `If-Match: *` and `If-None-Match: *`.
    ///
    /// A wildcard is a legitimate value of the conditional headers, not a malformed tag: parsing
    /// it must never produce a 400.
    pub const ANY: Self = Self {
        weak: false,
        any: true,
        tag: Cow::Borrowed("*"),
    };

    /// Builds a strong tag from a value the storage layer produced.
    ///
    /// Tolerant in exactly the same way as the wire parsers — a surrounding quote pair and a `W/`
    /// prefix are stripped — so that a value that made a round trip through somebody's database
    /// with its quotes still attached cannot end up double-quoted on the wire. Unlike the wire
    /// parsers this accepts an embedded `"` inside the tag, because S3 places no constraint on
    /// what a backend stores.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the value is empty after normalisation or contains a control
    /// character.
    pub fn new(value: impl Into<Cow<'static, str>>) -> Result<Self, ParseError> {
        let value = value.into();
        // Reuse the caller's allocation when normalisation was a no-op.
        let (weak, normalised) = {
            let (weak, tag) = split_weak_and_quotes(value.as_ref());
            validate_tag_body(tag, false)?;
            let normalised = if tag.len() == value.len() {
                None
            } else {
                Some(tag.to_owned())
            };
            (weak, normalised)
        };
        let tag = match normalised {
            Some(owned) => Cow::Owned(owned),
            None => value,
        };
        Ok(Self { weak, any: false, tag })
    }

    /// Builds a weak tag from a value the storage layer produced.
    ///
    /// # Errors
    ///
    /// As [`ETag::new`].
    pub fn new_weak(value: impl Into<Cow<'static, str>>) -> Result<Self, ParseError> {
        let mut tag = Self::new(value)?;
        tag.weak = true;
        Ok(tag)
    }

    /// Parses an HTTP header value: `"v"`, `W/"v"`, bare `v`, or `*`.
    ///
    /// Bare values are accepted deliberately. Several widely deployed SDKs send an unquoted tag in
    /// `x-amz-copy-source-if-match` and friends; rejecting them turns a conditional copy into a
    /// 400 for clients that are otherwise working. Being permissive on input costs nothing here
    /// because output is generated by [`ETag::render`], never echoed.
    ///
    /// One ambiguity comes with that tolerance and is resolved in favour of the RFC: a *bare*
    /// value that begins with `W/` is read as a weak validator, not as a tag whose first two
    /// characters are `W/`. A client that means the latter must quote the value, which is what the
    /// grammar requires of it anyway.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the value is empty, unbalanced (`"abc`), or contains a
    /// control character or an embedded quote.
    pub fn parse_http_header(value: &str) -> Result<Self, ParseError> {
        let trimmed = value.trim_matches(|c| c == ' ' || c == '\t');
        if trimmed == "*" {
            return Ok(Self::ANY);
        }
        Self::parse_wire(trimmed)
    }

    /// Parses the text content of an XML `<ETag>` element.
    ///
    /// Both quoted and bare forms occur in the wild — quoted from AWS, bare from
    /// `GetObjectAttributes` and from several third-party implementations — so the parser accepts
    /// both. `*` is *not* special here: a wildcard has no meaning in a body.
    ///
    /// # Errors
    ///
    /// As [`ETag::parse_http_header`].
    pub fn parse_xml_text(value: &str) -> Result<Self, ParseError> {
        Self::parse_wire(value.trim())
    }

    fn parse_wire(value: &str) -> Result<Self, ParseError> {
        // The weakness prefix comes off first: `W/"abc"` is balanced, but only once the `W/` is
        // no longer in front of the opening quote.
        let (weak, body) = strip_weak(value);
        if body.starts_with('"') != body.ends_with('"') || body == "\"" {
            return Err(ParseError::new(
                "ETag",
                rules::RFC9110_ENTITY_TAG,
                "unbalanced double quote around the opaque tag",
            ));
        }
        let tag = strip_quotes(body);
        validate_tag_body(tag, true)?;
        Ok(Self {
            weak,
            any: false,
            tag: Cow::Owned(tag.to_owned()),
        })
    }

    /// Computes the multipart entity tag: MD5 over the concatenated part digests, then `-N`.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when `part_digests` is empty or longer than the 10,000 part limit.
    /// Zero parts is not a representable multipart upload, and `-0` must never be emitted.
    pub fn from_part_digests(part_digests: &[[u8; 16]]) -> Result<Self, ParseError> {
        let count = u32::try_from(part_digests.len()).unwrap_or(u32::MAX);
        if part_digests.is_empty() || count > MAX_MULTIPART_PARTS {
            return Err(ParseError::new(
                "ETag",
                rules::AWS_CHECKSUM,
                "a multipart entity tag needs between 1 and 10000 part digests",
            ));
        }
        let mut hasher = Md5::new();
        for digest in part_digests {
            hasher.update(digest);
        }
        let outer: [u8; 16] = hasher.finalize().into();
        Ok(Self {
            weak: false,
            any: false,
            tag: Cow::Owned(format!("{}-{count}", hex::encode(outer))),
        })
    }

    /// Builds the single-part entity tag of an object: the hex MD5 of its content.
    #[must_use]
    pub fn from_content_md5(digest: [u8; 16]) -> Self {
        Self {
            weak: false,
            any: false,
            tag: Cow::Owned(hex::encode(digest)),
        }
    }

    /// Renders the tag for exactly one wire position.
    ///
    /// This is the only way to obtain the wire form. `ETag` implements neither `Display` nor
    /// `Into<String>`, so a caller cannot accidentally write an unquoted tag into a header or a
    /// quoted one into `GetObjectAttributes`.
    ///
    /// For [`EtagRender::HeaderQuoted`] an embedded `"` or `\` is escaped as a `quoted-pair`, so
    /// the header stays parseable whatever the backend stored. For the XML contexts the value is
    /// returned raw, quotation marks and all: escaping text nodes is the XML writer's job, and
    /// returning `&quot;` here would be escaped a second time into `&amp;quot;`.
    #[must_use]
    pub fn render(&self, ctx: EtagRender) -> Cow<'_, str> {
        if self.any {
            return Cow::Borrowed("*");
        }
        match ctx {
            EtagRender::HeaderQuoted => {
                let body = escape_quoted_string(&self.tag);
                let prefix = if self.weak { "W/" } else { "" };
                Cow::Owned(format!("{prefix}\"{body}\""))
            }
            EtagRender::XmlQuoted => Cow::Owned(format!("\"{}\"", self.tag)),
            EtagRender::XmlBare => Cow::Borrowed(self.tag.as_ref()),
        }
    }

    /// The normalised opaque tag, without quotes and without the `W/` prefix.
    ///
    /// This is the form to use as a storage key or a comparison input. It is **not** a wire form:
    /// writing it to the wire directly is the bug this type exists to prevent — use
    /// [`ETag::render`], which is also what produces the bare `GetObjectAttributes` spelling.
    #[must_use]
    pub fn opaque_tag(&self) -> &str {
        &self.tag
    }

    /// Whether this is the `*` wildcard.
    #[must_use]
    pub fn is_any(&self) -> bool {
        self.any
    }

    /// Whether the tag is a weak validator (`W/"…"`).
    #[must_use]
    pub fn is_weak(&self) -> bool {
        self.weak
    }

    /// The part count of a multipart entity tag, if the tag has the `<hex>-<N>` shape.
    ///
    /// Returns `None` for a single-part tag, and also for `-0`, a leading-zero count, or a count
    /// beyond the 10,000 part limit: those are not multipart tags, they are malformed ones, and
    /// reporting a part count for them would let a caller build a manifest that cannot exist.
    #[must_use]
    pub fn part_count(&self) -> Option<u32> {
        let (digest, count) = self.tag.rsplit_once('-')?;
        if digest.is_empty() || count.is_empty() || count.starts_with('0') {
            return None;
        }
        if !count.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        match count.parse::<u32>() {
            Ok(n) if (1..=MAX_MULTIPART_PARTS).contains(&n) => Some(n),
            _ => None,
        }
    }

    /// RFC 9110 strong comparison, as `If-Match` and `x-amz-copy-source-if-match` require.
    ///
    /// Two tags match only when neither is weak and their opaque tags are byte-equal. A wildcard
    /// on either side matches, because `*` means "any current representation" and the caller only
    /// reaches this method when a representation exists.
    #[must_use]
    pub fn matches_strong(&self, other: &Self) -> bool {
        if self.any || other.any {
            return true;
        }
        !self.weak && !other.weak && self.tag == other.tag
    }

    /// RFC 9110 weak comparison, as `If-None-Match` requires: weakness is ignored.
    #[must_use]
    pub fn matches_weak(&self, other: &Self) -> bool {
        if self.any || other.any {
            return true;
        }
        self.tag == other.tag
    }
}

impl Default for ETag {
    /// The empty strong tag — a placeholder that is **invalid on the wire**, and exists for one
    /// reason.
    ///
    /// ADR-0004 P10: a required member of a generated dto uses a bare type, and every generated
    /// dto derives `Default` so that `..Default::default()` keeps compiling when AWS adds a
    /// member. `ETag` is required in a `PutObject` response and in every `Object` listing entry,
    /// so it needs a `Default`. The value it produces is rejected by [`ETag::new`] and by every
    /// parser in this module, and it is not the `*` wildcard either.
    ///
    /// **The decoding path never produces it.** Treat a value that compares equal to this one as
    /// a bug, never as an entity tag — in particular, never let one answer a conditional request.
    fn default() -> Self {
        Self {
            weak: false,
            any: false,
            tag: Cow::Borrowed(""),
        }
    }
}

impl WirePlaceholder for ETag {
    fn is_wire_placeholder(&self) -> bool {
        !self.any && self.tag.is_empty()
    }
}

/// Strips an optional `W/` prefix and one surrounding quote pair. Purely lexical: no validation.
fn split_weak_and_quotes(value: &str) -> (bool, &str) {
    let (weak, rest) = strip_weak(value);
    (weak, strip_quotes(rest))
}

/// Strips the weakness prefix. Lowercase `w/` is accepted because clients send it, even though
/// RFC 9110 spells it uppercase.
fn strip_weak(value: &str) -> (bool, &str) {
    match value.strip_prefix("W/").or_else(|| value.strip_prefix("w/")) {
        Some(rest) => (true, rest),
        None => (false, value),
    }
}

/// Strips one surrounding quote pair, if there is one.
fn strip_quotes(value: &str) -> &str {
    match value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        Some(inner) => inner,
        None => value,
    }
}

/// Validates a normalised tag body. `from_wire` additionally rejects an embedded quote, which
/// cannot be represented unambiguously in either wire form.
fn validate_tag_body(tag: &str, from_wire: bool) -> Result<(), ParseError> {
    if tag.is_empty() {
        return Err(ParseError::new("ETag", rules::RFC9110_ENTITY_TAG, "the opaque tag is empty"));
    }
    if tag.chars().any(|c| c.is_control()) {
        return Err(ParseError::new(
            "ETag",
            rules::RFC9110_ENTITY_TAG,
            "the opaque tag contains a control character",
        ));
    }
    if from_wire && tag.contains('"') {
        return Err(ParseError::new(
            "ETag",
            rules::RFC9110_ENTITY_TAG,
            "the opaque tag contains an embedded double quote",
        ));
    }
    Ok(())
}

/// Escapes a `quoted-string` body so an embedded quote cannot terminate the header value early.
fn escape_quoted_string(tag: &str) -> Cow<'_, str> {
    if !tag.contains(['"', '\\']) {
        return Cow::Borrowed(tag);
    }
    let mut out = String::with_capacity(tag.len() + 2);
    for c in tag.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    Cow::Owned(out)
}
