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

//! The identifier an embedding host assigned a request, and the only text path into a
//! [`RequestId`].
//!
//! Responsible for: [`HostRequestId`], its closed-alphabet check, and [`InvalidRequestId`].
//! NOT responsible for: where the host's value comes from (the host's), which identifiers an answer
//! carries (`super::answer`), or reading the extension (`crate::service`, once, at the top).
//! Upstream: `super`. Downstream: `crate::service`, and every host that identifies its own
//! requests.
//!
//! # Why a host hands its identifier over at all
//!
//! A host that already identifies every request records that identifier in its own logs, audit
//! entries and notifications. RustFS does: an external S3 request is given a server-owned
//! `uuid::Uuid::new_v4()` at ingress, before any stack sees it (rustfs/rustfs `e870a6d25b`,
//! `rustfs/src/storage/request_context.rs:121-123`, `rustfs/src/server/layer.rs:253-292`), and its
//! answers carry that value in `x-amz-request-id` and `x-request-id` (`layer.rs:364-367`). A service
//! that minted a second identifier would answer with one request's name in the head and another's in
//! its body and events. So the host inserts this type into the request's extensions, and the
//! service identifies the request by it everywhere (rustfs/backlog#1677, ruling R10).
//!
//! # Why the alphabet is RFC 3986's unreserved set
//!
//! ASCII letters, digits, `-`, `.`, `_` and `~`, 1 to [`RequestId::MAX_LEN`] bytes: no byte of it is
//! special in a header, an XML document, a URL or a `key=value` log line, so an identifier needs no
//! escaping anywhere it is written. Every identifier RustFS gives an S3 request passes it — a UUID,
//! and the `trace-<hex>` and `req-<hex>` fallbacks (`request_context.rs:188-192`) — and so does
//! every value RustFS itself is willing to write into an XML document, which it filters to letters,
//! digits and `-` (`rustfs/src/server/rate_limit.rs:434-438`, `rustfs/src/server/ssec_transport.rs:116-120`).
//! A value outside it is refused with a typed error rather than repaired: a repaired identifier
//! would name a request the host never logged.
//!
//! What that leaves out is a value the host did not mint: RustFS copies a caller's own `x-request-id`
//! on its admin paths (`layer.rs:262-270`), and a caller may send anything. A host handed such a
//! value hands nothing over, the service mints its own for its events, and the answer on that path
//! still carries the host's value, which the host writes itself (`Answer::HostWritten`); a host that
//! must join the two records the pair where it has both.
//!
//! # Security
//!
//! Extensions cannot be written from the wire, so no caller can hand one of these over: only code
//! in the host's process can. That makes the host responsible for where the value comes from. A host
//! that copies it from a request header hands the caller the identifier, which RustFS does only for
//! its control-plane routes (the propagated `x-request-id`, `layer.rs:262-270`); even then the
//! alphabet keeps the value inert in a log line, a header and an XML document.

use super::RequestId;

/// The identifier an embedding host assigned one request, handed to the service in the request's
/// extensions.
///
/// With one present, the request's identifier is this value everywhere the service writes or
/// reports one: the identifier headers, an error document's `<RequestId>`, the observer's
/// [`crate::RequestEvent`], the authorization audit's [`crate::AuthzAuditEvent`] and a response
/// filter's [`crate::ResponseView`]. Without one, the service mints its own ([`crate::TraceSource`]).
///
/// ```
/// use rustfs_gateway::HostRequestId;
///
/// let mut request = http::Request::new(());
/// let id = HostRequestId::new("7c9e6679-7425-40de-944b-e07fc1f90ae7").expect("RustFS's own shape");
/// request.extensions_mut().insert(id);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostRequestId(RequestId);

impl HostRequestId {
    /// The host's identifier `text`, when it is 1 to [`RequestId::MAX_LEN`] bytes of ASCII letters,
    /// digits, `-`, `.`, `_` and `~`.
    ///
    /// # Errors
    ///
    /// [`InvalidRequestId`] naming the first rule `text` breaks. The value is refused, never
    /// trimmed, truncated or escaped into shape.
    pub fn new(text: &str) -> Result<Self, InvalidRequestId> {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Err(InvalidRequestId::Empty);
        }
        if bytes.len() > RequestId::MAX_LEN {
            return Err(InvalidRequestId::TooLong);
        }
        if let Some(offset) = bytes.iter().position(|byte| !is_identifier_byte(*byte)) {
            return Err(InvalidRequestId::ForbiddenByte { offset });
        }
        Ok(Self(RequestId::from_ascii(bytes)))
    }

    /// The identifier the request will be answered and reported with.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.0
    }
}

impl core::fmt::Debug for HostRequestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HostRequestId({})", self.0.as_str())
    }
}

/// Why a host's identifier was refused.
///
/// Carries no byte of the refused value: a refusal is the kind of thing that gets logged, and the
/// value is exactly what failed the check that makes an identifier safe to log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidRequestId {
    /// The value is empty.
    Empty,
    /// The value is longer than [`RequestId::MAX_LEN`] bytes.
    TooLong,
    /// The byte at this offset is not an ASCII letter, digit, `-`, `.`, `_` or `~`.
    ForbiddenByte {
        /// Where the first such byte is.
        offset: usize,
    },
}

impl core::fmt::Display for InvalidRequestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("a request identifier is empty"),
            Self::TooLong => write!(f, "a request identifier is longer than {} bytes", RequestId::MAX_LEN),
            Self::ForbiddenByte { offset } => write!(
                f,
                "a request identifier carries a byte outside ASCII letters, digits, '-', '.', '_' and '~' at offset {offset}"
            ),
        }
    }
}

impl std::error::Error for InvalidRequestId {}

/// RFC 3986's unreserved bytes: the whole alphabet a host's identifier may use.
const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — every byte outside the alphabet is refused where it stands, the ones that would
    /// break a header, an XML document or a log line first among them. None is repaired.
    #[test]
    fn a_byte_outside_the_alphabet_is_refused_at_its_offset() {
        for (text, offset) in [
            ("abc def", 3),
            ("<RequestId>", 0),
            ("id\"quoted", 2),
            ("line\r\nbreak", 4),
            ("nul\0byte", 3),
            ("slash/", 5),
            ("percent%41", 7),
            ("Root=1-5759e988", 4),
            ("a;b", 1),
            ("a,b", 1),
            ("a+b", 1),
            ("user@host", 4),
            ("amp&", 3),
            ("apos'", 4),
            ("caf\u{e9}", 3),
            ("\u{1b}[31mred", 0),
        ] {
            assert_eq!(HostRequestId::new(text), Err(InvalidRequestId::ForbiddenByte { offset }), "{text:?}");
        }
    }

    /// Negative — an empty value and one past the ceiling are refused rather than padded or cut.
    #[test]
    fn an_empty_or_overlong_value_is_refused() {
        assert_eq!(HostRequestId::new(""), Err(InvalidRequestId::Empty));
        let longest = "a".repeat(RequestId::MAX_LEN);
        assert!(HostRequestId::new(&longest).is_ok());
        assert_eq!(HostRequestId::new(&format!("{longest}a")), Err(InvalidRequestId::TooLong));
    }

    /// Negative — a refusal names the rule and the offset, never a byte of the value.
    #[test]
    fn a_refusal_carries_no_byte_of_the_value() {
        let refusal = HostRequestId::new("secret\ntoken").expect_err("a line break is refused");
        for rendered in [refusal.to_string(), format!("{refusal:?}")] {
            assert!(!rendered.contains("secret"), "{rendered}");
            assert!(!rendered.contains("token"), "{rendered}");
        }
    }

    /// Positive — every identifier RustFS gives an S3 request is carried byte for byte: its UUID
    /// and both of its fallback spellings, and the rest of the unreserved set.
    #[test]
    fn every_identifier_rustfs_mints_is_carried_byte_for_byte() {
        for text in [
            "7c9e6679-7425-40de-944b-e07fc1f90ae7",
            "trace-4bf92f3577b34da6a3ce929d0e0e4736",
            "req-1f2e3d4c",
            "0123456789ABCDEF",
            "req_2026.09.30~a",
        ] {
            let id = HostRequestId::new(text).expect("inside the alphabet");
            assert_eq!(id.request_id().as_str(), text);
            assert_eq!(format!("{id:?}"), format!("HostRequestId({text})"));
        }
    }
}
