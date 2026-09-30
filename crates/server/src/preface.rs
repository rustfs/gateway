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

//! Tells an HTTP/2 connection from an HTTP/1.1 one by its first octets.
//!
//! Responsible for: matching a connection's first reads, however they are split, against the
//! HTTP/2 client connection preface. NOT responsible for: choosing the protocol, which Hyper does
//! from the same octets, or anything the answer is used for (`io.rs`'s idle deadline).
//! Upstream: `ProgressIo::poll_read`. Downstream: none.
//! Evidence: <https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4> — every HTTP/2 connection,
//! cleartext or TLS, opens with the same 24-octet client preface.

/// The client connection preface.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How far a connection's first octets have matched [`HTTP2_PREFACE`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Preface {
    /// This many octets matched so far; the next read decides more.
    Matching(usize),
    /// The whole preface arrived: an HTTP/2 connection.
    Http2,
    /// An octet diverged: not an HTTP/2 connection.
    Other,
}

impl Default for Preface {
    fn default() -> Self {
        Self::Matching(0)
    }
}

impl Preface {
    /// Continues the match with the next octets read off the connection.
    pub(crate) fn observe(&mut self, octets: &[u8]) {
        let Self::Matching(matched) = *self else {
            return;
        };
        let expected = HTTP2_PREFACE.get(matched..).unwrap_or_default();
        if !octets.iter().zip(expected).all(|(octet, want)| octet == want) {
            *self = Self::Other;
            return;
        }
        let matched = matched + octets.len().min(expected.len());
        *self = if matched == HTTP2_PREFACE.len() {
            Self::Http2
        } else {
            Self::Matching(matched)
        };
    }

    /// Whether the connection opened with the whole preface.
    pub(crate) fn is_http2(self) -> bool {
        self == Self::Http2
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // Test-only slices of the fixed 24-octet preface.
mod tests {
    use super::{HTTP2_PREFACE, Preface};

    fn after(reads: &[&[u8]]) -> Preface {
        let mut preface = Preface::default();
        for read in reads {
            preface.observe(read);
        }
        preface
    }

    /// Negative — an HTTP/1.1 request line is not HTTP/2.
    #[test]
    fn an_http1_request_is_not_http2() {
        assert_eq!(after(&[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"]), Preface::Other);
    }

    /// Negative — a request that shares the preface's first octets and then diverges is not HTTP/2,
    /// even when the divergence arrives in a later read.
    #[test]
    fn a_preface_that_diverges_in_a_later_read_is_not_http2() {
        assert_eq!(after(&[b"PRI * HTTP/", b"1.1\r\n"]), Preface::Other);
    }

    /// Negative — a connection that has sent only part of the preface is not yet HTTP/2.
    #[test]
    fn a_partial_preface_is_not_yet_http2() {
        let partial = after(&[&HTTP2_PREFACE[..10]]);
        assert_eq!(partial, Preface::Matching(10));
        assert!(!partial.is_http2());
    }

    /// Positive — the preface split across reads, followed in the same read by the first frame, is
    /// HTTP/2, and stays so whatever follows.
    #[test]
    fn a_preface_split_across_reads_is_http2() {
        let mut preface = after(&[&HTTP2_PREFACE[..3], &HTTP2_PREFACE[3..20], b"\r\n\r\n\x00\x00\x00\x04"]);
        assert!(preface.is_http2());
        preface.observe(b"GET / HTTP/1.1");
        assert!(preface.is_http2());
    }
}
