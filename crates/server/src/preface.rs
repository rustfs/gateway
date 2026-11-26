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

//! Tells an HTTP/2 connection from an HTTP/1.1 one by its first octets and observes HTTP/2 header
//! block boundaries for per-stream header read timeouts.
//!
//! Responsible for: matching a connection's first reads against the HTTP/2 client connection
//! preface, and tracking whether an HTTP/2 `HEADERS`/`CONTINUATION` header block is currently
//! incomplete without allocating.
//! NOT responsible for: choosing the protocol, HPACK decoding, or arming timers (`io.rs` does that).
//! Upstream: `ProgressIo::poll_read`. Downstream: none.
//! Evidence: <https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4> and §6.2/§6.10 — every
//! HTTP/2 connection opens with the 24-octet client preface, and every frame starts with a 9-octet
//! header where type `0x01` (`HEADERS`) and `0x09` (`CONTINUATION`) carry `END_HEADERS` (`0x04`).

/// The client connection preface.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_TYPE_HEADERS: u8 = 0x01;
const FRAME_TYPE_CONTINUATION: u8 = 0x09;
const FLAG_END_HEADERS: u8 = 0x04;

/// How far a connection's first octets have matched [`HTTP2_PREFACE`], and for HTTP/2 connections
/// the current frame-boundary state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Preface {
    /// This many octets matched so far; the next read decides more.
    Matching(usize),
    /// The whole preface arrived: an HTTP/2 connection with lightweight frame tracking.
    Http2(H2HeaderTracker),
    /// An octet diverged: not an HTTP/2 connection.
    Other,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct H2HeaderTracker {
    phase: FramePhase,
    awaiting_continuation: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FramePhase {
    Header {
        buf: [u8; 9],
        len: usize,
    },
    Payload {
        remaining: usize,
        is_header_frame: bool,
        ends_headers: bool,
    },
}

impl Default for FramePhase {
    fn default() -> Self {
        Self::Header { buf: [0_u8; 9], len: 0 }
    }
}

impl H2HeaderTracker {
    fn observe(&mut self, mut octets: &[u8]) {
        while !octets.is_empty() {
            match self.phase {
                FramePhase::Header { mut buf, mut len } => {
                    let take = (9 - len).min(octets.len());
                    if let (Some(dst), Some(src)) = (buf.get_mut(len..len + take), octets.get(..take)) {
                        dst.copy_from_slice(src);
                    }
                    len += take;
                    octets = octets.get(take..).unwrap_or_default();
                    if len < 9 {
                        self.phase = FramePhase::Header { buf, len };
                        return;
                    }
                    let [b0, b1, b2, frame_type, flags, ..] = buf;
                    let payload_len = (usize::from(b0) << 16) | (usize::from(b1) << 8) | usize::from(b2);
                    let is_header_frame = matches!(frame_type, FRAME_TYPE_HEADERS | FRAME_TYPE_CONTINUATION);
                    let ends_headers = (flags & FLAG_END_HEADERS) != 0;
                    if payload_len == 0 {
                        if is_header_frame {
                            self.awaiting_continuation = !ends_headers;
                        }
                        self.phase = FramePhase::Header { buf: [0_u8; 9], len: 0 };
                    } else {
                        self.phase = FramePhase::Payload {
                            remaining: payload_len,
                            is_header_frame,
                            ends_headers,
                        };
                    }
                }
                FramePhase::Payload {
                    remaining,
                    is_header_frame,
                    ends_headers,
                } => {
                    let take = remaining.min(octets.len());
                    let next_remaining = remaining - take;
                    octets = octets.get(take..).unwrap_or_default();
                    if next_remaining == 0 {
                        if is_header_frame {
                            self.awaiting_continuation = !ends_headers;
                        }
                        self.phase = FramePhase::Header { buf: [0_u8; 9], len: 0 };
                    } else {
                        self.phase = FramePhase::Payload {
                            remaining: next_remaining,
                            is_header_frame,
                            ends_headers,
                        };
                    }
                }
            }
        }
    }

    fn reading_headers(&self) -> bool {
        if self.awaiting_continuation {
            return true;
        }
        match self.phase {
            FramePhase::Payload { is_header_frame, .. } => is_header_frame,
            FramePhase::Header {
                buf: [_, _, _, frame_type, ..],
                len,
            } => len >= 4 && matches!(frame_type, FRAME_TYPE_HEADERS | FRAME_TYPE_CONTINUATION),
        }
    }
}

impl Default for Preface {
    fn default() -> Self {
        Self::Matching(0)
    }
}

impl Preface {
    /// Continues the match with the next octets read off the connection, and once HTTP/2 is
    /// established advances the frame-boundary observer over all trailing octets.
    pub(crate) fn observe(&mut self, octets: &[u8]) {
        match self {
            Self::Other => {}
            Self::Http2(tracker) => tracker.observe(octets),
            Self::Matching(matched) => {
                let already = *matched;
                let expected = HTTP2_PREFACE.get(already..).unwrap_or_default();
                if !octets.iter().zip(expected).all(|(octet, want)| octet == want) {
                    *self = Self::Other;
                    return;
                }
                let consumed = octets.len().min(expected.len());
                let next_matched = already + consumed;
                if next_matched == HTTP2_PREFACE.len() {
                    let mut tracker = H2HeaderTracker::default();
                    tracker.observe(octets.get(consumed..).unwrap_or_default());
                    *self = Self::Http2(tracker);
                } else {
                    *self = Self::Matching(next_matched);
                }
            }
        }
    }

    /// Whether the connection opened with the whole preface.
    pub(crate) fn is_http2(self) -> bool {
        matches!(self, Self::Http2(_))
    }

    /// Whether an HTTP/2 connection is currently inside an incomplete `HEADERS` / `CONTINUATION`
    /// header block.
    pub(crate) fn reading_h2_headers(self) -> bool {
        match self {
            Self::Http2(tracker) => tracker.reading_headers(),
            Self::Matching(_) | Self::Other => false,
        }
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

    /// Negative — an incomplete `HEADERS` frame or a `HEADERS` frame without `END_HEADERS` keeps
    /// `reading_h2_headers` true until a `CONTINUATION` with `END_HEADERS` completes.
    #[test]
    fn n_incomplete_h2_header_block_tracks_continuation_until_end_headers() {
        // HEADERS (type 0x01) len=4, flags=0x00 (no END_HEADERS), stream=1, payload=[1,2,3,4]
        let headers_no_end = [0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4];
        // CONTINUATION (type 0x09) len=2, flags=0x00, stream=1
        let cont_no_end = [0x00, 0x00, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 5, 6];
        // CONTINUATION (type 0x09) len=2, flags=0x04 (END_HEADERS), stream=1
        let cont_end = [0x00, 0x00, 0x02, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 7, 8];
        // DATA (type 0x00) len=4, flags=0x00, stream=1, split mid-payload
        let data_partial = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a', b'b'];

        let mut preface = after(&[HTTP2_PREFACE]);
        assert!(!preface.reading_h2_headers());

        preface.observe(&headers_no_end[..11]); // mid-HEADERS payload
        assert!(preface.reading_h2_headers());
        preface.observe(&headers_no_end[11..]); // HEADERS payload done, still missing END_HEADERS
        assert!(preface.reading_h2_headers());
        preface.observe(&cont_no_end);
        assert!(preface.reading_h2_headers());
        preface.observe(&cont_end[..10]); // mid-final-CONTINUATION
        assert!(preface.reading_h2_headers());
        preface.observe(&cont_end[10..]); // END_HEADERS finished!
        assert!(!preface.reading_h2_headers());

        // Partial DATA frame must NOT be flagged as reading headers.
        preface.observe(&data_partial);
        assert!(!preface.reading_h2_headers());
    }
}
