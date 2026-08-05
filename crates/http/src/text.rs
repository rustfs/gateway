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

//! Byte-level predicates and the one small ASCII buffer this crate stores strings in.
//!
//! Responsible for: the control-character and CRLF predicates every acceptance rule shares, and
//! [`AsciiBuf`], a stack-inline buffer that keeps a normalised host off the heap for the sizes
//! that actually occur.
//! NOT responsible for: any protocol meaning. Nothing here knows what a host, a header or a query
//! parameter is; it only knows bytes.
//! Upstream: `smallvec`. Downstream: `host`, `header_view`, `query_view`, `metadata`.

use smallvec::SmallVec;

/// How many bytes an [`AsciiBuf`] holds before it reaches for the heap.
///
/// A hostname that exceeds this is legal but rare; the inline size is chosen so the common case
/// costs no allocation at all rather than so the worst case fits.
const INLINE_BYTES: usize = 64;

/// A short, ASCII-only, owned string.
///
/// Every constructor validates that the bytes are ASCII, which is what makes [`AsciiBuf::as_str`]
/// infallible without a panicking conversion. The type is private to the crate: it exists to
/// avoid an allocation, not to be a general string type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AsciiBuf(SmallVec<[u8; INLINE_BYTES]>);

impl AsciiBuf {
    /// An empty buffer.
    pub(crate) fn new() -> Self {
        Self(SmallVec::new())
    }

    /// Appends one ASCII byte. Non-ASCII input is rejected rather than replaced.
    pub(crate) fn push_ascii(&mut self, byte: u8) -> bool {
        if !byte.is_ascii() {
            return false;
        }
        self.0.push(byte);
        true
    }

    /// The buffer as a string slice.
    ///
    /// Every byte was checked ASCII on the way in, so the conversion cannot fail; the fallback
    /// exists only to keep this function total and non-panicking.
    pub(crate) fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("") // unreachable: constructors admit ASCII only
    }

    /// Whether the bytes are still inline, meaning no heap allocation was made for them.
    pub(crate) fn is_inline(&self) -> bool {
        !self.0.spilled()
    }
}

/// Whether the slice contains a byte HTTP forbids inside a field value.
///
/// CR and LF are the header-injection primitives; NUL and the remaining C0 controls (horizontal
/// tab excepted, which RFC 9110 permits in a field value) are what smuggle a terminator past a
/// downstream parser that trims differently.
pub(crate) fn contains_forbidden_control(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| is_forbidden_control(*byte))
}

/// Whether one byte is forbidden inside a field value.
pub(crate) fn is_forbidden_control(byte: u8) -> bool {
    matches!(byte, 0x00..=0x08 | 0x0A..=0x1F | 0x7F)
}

/// Whether the slice is free of CR and LF specifically.
///
/// Kept separate from [`contains_forbidden_control`] because the decoded-metadata rule cares
/// about the injection pair on its own, and reporting "control character" for a decoded `\r\n`
/// loses the reason the check exists.
pub(crate) fn contains_crlf(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
}

/// Whether every byte is a visible ASCII character, with no space and no control.
pub(crate) fn is_all_ascii_graphic(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_graphic)
}

/// Whether the byte is a valid HTTP token character (RFC 9110 §5.6.2 `tchar`).
pub(crate) fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// Whether the slice is a non-empty HTTP token.
pub(crate) fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| is_tchar(*byte))
}
