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

//! Legacy RustFS's `encoding-type=url` rule for one listing, as the RustFS profile applies it
//! (rustfs/gateway#1059).
//!
//! Responsible for: [`RustFsListing`] — which members one listing percent-encodes and whether it
//! echoes `encoding-type` — the per-member decision [`UrlEncoding::member`], the `/`-preserving
//! escape, and the echo [`rustfs_listing_echo`].
//! NOT responsible for: which operations use which table (the assembly's RustFS profile), the
//! AWS-model default (`super::value`), or the member list the IR declares encodable.
//! Upstream: the view (`super::view::MetaView::with_rustfs_listing_encoding`). Downstream: the
//! generated listing encoders, through `super::value`.
//!
//! # What legacy RustFS does, and how this reproduces it
//!
//! Legacy RustFS encodes a listing only when `encoding-type` is exactly `url`, and then only some
//! of the members AWS encodes: `Contents/Key` and `CommonPrefixes/Prefix` on ListObjectsV2,
//! those and `NextMarker` on ListObjects, every key-shaped member on ListObjectVersions and
//! ListMultipartUploads, and nothing on ListParts. Each encoded value is split on `/`, each segment
//! is percent-encoded (every byte outside `A-Z a-z 0-9 - . _ ~`, uppercase hex) and the segments
//! are joined with `/` again, so `/` stays literal. The echo is the request's own `encoding-type`
//! value on the four listings that take one and absent on ListParts. It never encodes a member the
//! request did not ask for. (rustfs/rustfs@1e7065101d `rustfs/src/storage/s3_api/bucket.rs:44-61`,
//! `:212-279`, `:282-359`, `:361-411`; ListMultipartUploads since
//! <https://github.com/rustfs/rustfs/commit/182b2bfe9>, rustfs/gateway#1614.)
//!
//! The generated encoder makes one decision per response
//! ([`super::value::url_encoding_for_response`]) and then asks it once per encodable member,
//! naming the member by path — `Prefix` at the root, `Object.Key` inside a shape. Under the RustFS
//! profile the response-wide decision is [`UrlEncoding::RustFs`], and [`UrlEncoding::member`] turns
//! it into [`UrlEncoding::RustFsMember`] for exactly the members the table lists and preserves
//! the raw RustFS decision for every other one. A value no XML document can carry still forces the
//! AWS-model encoding of the whole response, as it does by default: legacy RustFS writes such a value
//! raw and produces a body no XML parser reads.

use std::borrow::Cow;

use rustfs_gateway_types::{dto, is_xml_representable};

use crate::codec::error::CodecError;
use crate::codec::value::{ENCODING_TYPE, ENCODING_TYPE_URL, UrlEncoding, UrlEncodingValue, needs_url_encoding};
use crate::codec::view::MetaView;

/// Legacy RustFS's `encoding-type=url` rule for one listing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustFsListing {
    /// The member paths legacy RustFS percent-encodes: a root member by name (`NextMarker`), a
    /// member of a nested shape as `Shape.Member` (`Object.Key`).
    members: &'static [&'static str],
    /// Whether the response echoes the request's `encoding-type`, verbatim.
    echoes: bool,
}

impl RustFsListing {
    /// A listing that encodes exactly `members` and echoes `encoding-type` when `echoes`.
    #[must_use]
    pub const fn new(members: &'static [&'static str], echoes: bool) -> Self {
        Self { members, echoes }
    }

    /// The member paths this listing percent-encodes.
    #[must_use]
    pub const fn members(&self) -> &'static [&'static str] {
        self.members
    }

    /// Whether this listing echoes the request's `encoding-type`.
    #[must_use]
    pub const fn echoes(&self) -> bool {
        self.echoes
    }
}

impl UrlEncoding {
    /// The decision for the one member at `path`: a root member by name, a nested one as
    /// `Shape.Member`.
    ///
    /// The AWS-model decisions apply to every member alike and come back unchanged. Under the
    /// RustFS profile a member legacy RustFS encodes becomes [`Self::RustFsMember`] when the
    /// request asked for exactly `url`, and every other member keeps the raw RustFS decision.
    #[must_use]
    pub fn member(self, path: &str) -> Self {
        match self {
            Self::RustFs { requested, listing } => {
                if requested && listing.members.contains(&path) {
                    Self::RustFsMember
                } else {
                    self
                }
            }
            other => other,
        }
    }
}

/// The response-wide decision under the RustFS profile, or `None` when the view carries no RustFS
/// listing rule.
pub(crate) fn rustfs_decision(request: &MetaView<'_>) -> Option<UrlEncoding> {
    let listing = request.rustfs_listing_encoding()?;
    let requested = request.query(ENCODING_TYPE).ok().flatten().as_deref() == Some(ENCODING_TYPE_URL);
    Some(UrlEncoding::RustFs { requested, listing })
}

pub(crate) fn requires_url_encoding<T: UrlEncodingValue>(request: &MetaView<'_>, value: &T) -> bool {
    value.encoding_value().is_some_and(|value| {
        if request.rustfs_listing_encoding().is_some() {
            !is_xml_representable(value)
        } else {
            needs_url_encoding(value)
        }
    })
}

pub(crate) fn any_requires_url_encoding<T, V: UrlEncodingValue>(
    request: &MetaView<'_>,
    values: &[T],
    field: impl Fn(&T) -> &V,
) -> bool {
    values.iter().any(|value| requires_url_encoding(request, field(value)))
}

/// `value` percent-encoded the way legacy RustFS encodes a listing value: segment by segment, so
/// `/` stays literal.
pub(crate) fn slash_preserving(value: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(value.len());
    for (index, segment) in value.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(&rustfs_gateway_sig::percent_encode(segment.as_bytes()));
    }
    Cow::Owned(out)
}

/// Sets the `EncodingType` echo the way legacy RustFS writes it, when `encoding` is the RustFS
/// profile's decision: the request's own `encoding-type` value, verbatim, on a listing that echoes
/// it, and nothing on one that does not. Leaves `echo` alone under every other decision.
///
/// Generated into the `encode` of every listing that has an `EncodingType` member, right after the
/// AWS-model echo, so the default is untouched.
///
/// # Errors
///
/// [`CodecError::invalid_argument`] when the echoed `encoding-type` carries invalid UTF-8 or a
/// character XML 1.0 cannot represent (which would otherwise corrupt to `U+FFFD`).
pub fn rustfs_listing_echo(
    request: &MetaView<'_>,
    encoding: UrlEncoding,
    echo: &mut Option<dto::EncodingType>,
) -> Result<(), CodecError> {
    let UrlEncoding::RustFs { listing, .. } = encoding else {
        return Ok(());
    };
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS echoes whatever `encoding-type` the request
    // carried, `URL` or `foo` included, while it only encodes for exactly `url`, and it encodes
    // only some of the members AWS encodes, so a client that decodes the members its echo covers
    // mis-reads a raw `Prefix` holding `%` or `+`. The intended future behaviour is the core default:
    // every AWS member encoded and a canonical echo.
    *echo = if listing.echoes {
        match request.query(ENCODING_TYPE).map_err(|error| error.about("EncodingType"))? {
            Some(value) if !is_xml_representable(&value) => {
                return Err(
                    CodecError::invalid_argument("the request carries an encoding-type value XML 1.0 cannot represent")
                        .about("EncodingType"),
                );
            }
            Some(value) => Some(dto::EncodingType::custom(value.into_owned())),
            None => None,
        }
    } else {
        None
    };
    Ok(())
}

/// Reads a query parameter as strict UTF-8, attributing a refusal to `member`.
///
/// # Errors
///
/// [`CodecError::invalid_argument`] naming `member` when the decoded bytes are not valid UTF-8.
pub fn query<'a>(request: &'a MetaView<'a>, key: &str, member: &'static str) -> Result<Option<Cow<'a, str>>, CodecError> {
    request.query(key).map_err(|error| error.about(member))
}

/// Verifies that a non-URL-encoded echoed listing cursor carries only XML 1.0 representable
/// characters, refusing forbidden C0 controls instead of silently substituting `U+FFFD`.
///
/// # Errors
///
/// [`CodecError::invalid_argument`] naming `member` when `value` carries an unrepresentable char.
pub fn xml_cursor_text<'a>(value: &'a str, member: &'static str) -> Result<&'a str, CodecError> {
    if !is_xml_representable(value) {
        return Err(CodecError::invalid_argument("a listing cursor carries a character XML 1.0 cannot represent").about(member));
    }
    Ok(value)
}
