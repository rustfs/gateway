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

//! How a body stream may fail, and how much of it was accepted before it failed.
//!
//! Responsible for: the one error type every producer and adapter in this crate returns, and
//! the byte counter an upper layer needs in order to decide what it may still commit.
//! NOT responsible for: mapping failures onto protocol status codes or wire error documents —
//! this crate has no protocol vocabulary at all; the wire layer owns that mapping.
//! Upstream: `std::io`. Downstream: every module in this crate, then `s3gate-http`.

use core::fmt;

/// A body stream failure, together with the number of body bytes that had already been
/// handed to the consumer when it happened.
///
/// The byte count is part of the error on purpose. A consumer that aborts mid-body has to
/// answer "how much did I accept?" at exactly the point it aborts, and an error that does not
/// carry the answer forces that state to be tracked in a second place, where it drifts.
#[derive(Debug)]
pub struct StreamError {
    kind: StreamErrorKind,
    bytes_before_error: u64,
}

/// The exhaustive set of reasons a body stream ends other than by reaching [`PayloadRead::Eof`].
///
/// [`PayloadRead::Eof`]: crate::PayloadRead::Eof
#[derive(Debug)]
pub enum StreamErrorKind {
    /// The stream ended before the announced body — or its trailer section — had arrived.
    ///
    /// This is the variant that must terminate a truncated body. Producing an end-of-stream
    /// event instead would let a partially received body be accepted as complete.
    IncompleteBody,
    /// The body length disagrees with the length that was declared up front.
    LengthMismatch {
        /// The length the producer declared before any byte was read.
        declared: u64,
        /// The number of body bytes actually observed.
        observed: u64,
    },
    /// The stream was polled again after it had already reported end-of-stream.
    ///
    /// A terminated stream never produces another chunk; polling one is a consumer bug, and
    /// this variant makes it loud instead of letting a fresh chunk appear after the end.
    PolledAfterEof,
    /// The underlying transport or file failed.
    Io(std::io::Error),
    /// A producer outside this crate failed for a reason this crate cannot name.
    Upstream(Box<dyn std::error::Error + Send + Sync>),
}

impl StreamError {
    /// Builds an error from a kind, with a byte count of zero.
    #[must_use]
    pub fn new(kind: StreamErrorKind) -> Self {
        Self {
            kind,
            bytes_before_error: 0,
        }
    }

    /// The stream ended before the announced body or trailer section had arrived.
    #[must_use]
    pub fn incomplete_body() -> Self {
        Self::new(StreamErrorKind::IncompleteBody)
    }

    /// The stream was polled after it had already reported end-of-stream.
    #[must_use]
    pub fn polled_after_eof() -> Self {
        Self::new(StreamErrorKind::PolledAfterEof)
    }

    /// The observed body length disagrees with the declared one.
    #[must_use]
    pub fn length_mismatch(declared: u64, observed: u64) -> Self {
        Self::new(StreamErrorKind::LengthMismatch { declared, observed })
    }

    /// Wraps a producer error this crate cannot classify.
    #[must_use]
    pub fn upstream(source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::new(StreamErrorKind::Upstream(source))
    }

    /// Records how many body bytes had already been delivered when the failure occurred.
    #[must_use]
    pub fn with_bytes_before_error(mut self, bytes: u64) -> Self {
        self.bytes_before_error = bytes;
        self
    }

    /// Records `bytes` only if no count has been recorded yet.
    ///
    /// Adapters use this so that a count set by the original producer is never overwritten by
    /// the smaller count an adapter happens to know about.
    #[must_use]
    pub fn or_bytes_before_error(self, bytes: u64) -> Self {
        if self.bytes_before_error == 0 {
            self.with_bytes_before_error(bytes)
        } else {
            self
        }
    }

    /// Why the stream failed.
    #[must_use]
    pub fn kind(&self) -> &StreamErrorKind {
        &self.kind
    }

    /// Consumes the error and returns why the stream failed.
    #[must_use]
    pub fn into_kind(self) -> StreamErrorKind {
        self.kind
    }

    /// How many body bytes had already been delivered to the consumer when the stream failed.
    #[must_use]
    pub fn bytes_before_error(&self) -> u64 {
        self.bytes_before_error
    }
}

impl From<std::io::Error> for StreamError {
    fn from(err: std::io::Error) -> Self {
        Self::new(StreamErrorKind::Io(err))
    }
}

impl fmt::Display for StreamErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteBody => f.write_str("body stream ended before it was complete"),
            Self::LengthMismatch { declared, observed } => {
                write!(f, "body length mismatch: declared {declared} bytes, observed {observed} bytes")
            }
            Self::PolledAfterEof => f.write_str("body stream polled after end-of-stream"),
            Self::Io(err) => write!(f, "body stream i/o failure: {err}"),
            Self::Upstream(err) => write!(f, "body stream producer failure: {err}"),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (after {} body bytes)", self.kind, self.bytes_before_error)
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            StreamErrorKind::Io(err) => Some(err),
            StreamErrorKind::Upstream(err) => Some(err.as_ref()),
            StreamErrorKind::IncompleteBody | StreamErrorKind::LengthMismatch { .. } | StreamErrorKind::PolledAfterEof => None,
        }
    }
}
