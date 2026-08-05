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

//! Watching one run of bytes several times over without reading it several times over.
//!
//! Responsible for: the [`ByteObserver`] trait a digest, a counter or a size accountant
//! implements, the outcome it produces at end-of-body, and [`ByteCounter`] — the witness a
//! single-pass gate asserts against.
//! NOT responsible for: any digest algorithm, any digest name, and any decision about which
//! observers a request needs. Naming an algorithm here would put protocol vocabulary in the one
//! crate that must not have it; the wire layer owns the choice and the implementations.
//! Upstream: nothing. Downstream: the wire layer's ingest pipeline, which drives every observer
//! from the same borrowed slice, and the storage layer that reads the outcomes.
//!
//! # Why a trait and not a stack of streams
//!
//! The obvious shape is one stream per concern — decode, then checksum, then hash — and it costs
//! a poll, a waker hand-off and usually a re-slice per layer per chunk, on top of walking the
//! same bytes once per layer. With four digests over a 1 GiB upload that is four extra passes
//! through memory. An observer is called with a slice that is *already* in L1 because the layer
//! above it has just written it there, so the second, third and fourth digests are close to free.

use core::fmt;

/// The largest digest an observer may produce, in bytes.
///
/// Sixty-four covers every digest width in use and leaves the outcome a plain value type: a
/// heap-allocated result per observer per request would put an allocation back on the path this
/// trait exists to keep allocation-free.
pub const MAX_OBSERVER_DIGEST_BYTES: usize = 64;

/// What an observer has to say once the body is over.
///
/// The label is `&'static str` rather than an enum of algorithm names on purpose: an enum here
/// would be protocol vocabulary, and this crate has none. The layer that installed the observer
/// knows which label it asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObserverOutcome {
    label: &'static str,
    digest: [u8; MAX_OBSERVER_DIGEST_BYTES],
    digest_len: usize,
    observed_bytes: u64,
}

impl ObserverOutcome {
    /// Builds an outcome from a digest that is at most [`MAX_OBSERVER_DIGEST_BYTES`] long.
    ///
    /// A longer digest is truncated rather than rejected only because there is no such digest;
    /// the constructor takes the shorter of the two lengths so that no slice index can panic.
    #[must_use]
    pub fn new(label: &'static str, digest: &[u8], observed_bytes: u64) -> Self {
        let mut buf = [0u8; MAX_OBSERVER_DIGEST_BYTES];
        let digest_len = digest.len().min(MAX_OBSERVER_DIGEST_BYTES);
        if let (Some(dst), Some(src)) = (buf.get_mut(..digest_len), digest.get(..digest_len)) {
            dst.copy_from_slice(src);
        }
        Self {
            label,
            digest: buf,
            digest_len,
            observed_bytes,
        }
    }

    /// The label the installing layer chose.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// The digest bytes.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        self.digest.get(..self.digest_len).unwrap_or(&[])
    }

    /// How many body bytes this observer was shown.
    ///
    /// A single-pass gate compares this against the body length: a second pass shows up here as
    /// twice the number of bytes, which is a value a test can assert on rather than a timing
    /// difference nobody notices.
    #[must_use]
    pub fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }
}

impl fmt::Debug for ObserverOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObserverOutcome")
            .field("label", &self.label)
            .field("digest_len", &self.digest_len)
            .field("observed_bytes", &self.observed_bytes)
            .finish()
    }
}

/// One consumer of the body bytes, driven in step with every other consumer.
///
/// # Contract
///
/// * `update` is called with each run of body bytes exactly once, in order, and never with a run
///   the caller has already shown it. An implementation that buffers instead of consuming defeats
///   the purpose and reintroduces the memory it was meant to avoid.
/// * `update` is never called after `finish`, which is why `finish` takes the observer by box.
/// * `update` must not fail. An observer that can fail is a validation step wearing the wrong
///   trait: validation belongs where the failure can be turned into a wire response.
pub trait ByteObserver: Send {
    /// Shows the observer the next run of body bytes.
    fn update(&mut self, bytes: &[u8]);

    /// Ends the observation and produces the result.
    fn finish(self: Box<Self>) -> ObserverOutcome;

    /// A stable label, used to attribute the outcome and in diagnostics.
    fn label(&self) -> &'static str;
}

/// The observer that counts, and nothing else.
///
/// It exists so a test can state the single-pass property as an equality — "the observers were
/// shown exactly as many bytes as the body carried" — instead of as a benchmark. It is also the
/// cheapest possible observer, which makes it usable in production as a decoded-byte accountant.
#[derive(Debug, Default)]
pub struct ByteCounter {
    observed_bytes: u64,
    update_calls: u64,
    smallest_run: Option<usize>,
}

impl ByteCounter {
    /// A counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bytes have been shown so far.
    #[must_use]
    pub fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// How many separate calls those bytes arrived in.
    ///
    /// The call count is the granularity witness: hardware digest instructions lose most of their
    /// advantage when they are restarted every few hundred bytes, so a pipeline that splits the
    /// body at every framing boundary shows up here as a call count far above the chunk count.
    #[must_use]
    pub fn update_calls(&self) -> u64 {
        self.update_calls
    }

    /// The shortest run the counter was shown, if any.
    #[must_use]
    pub fn smallest_run(&self) -> Option<usize> {
        self.smallest_run
    }
}

impl ByteObserver for ByteCounter {
    fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.observed_bytes = self.observed_bytes.saturating_add(bytes.len() as u64);
        self.update_calls = self.update_calls.saturating_add(1);
        self.smallest_run = Some(match self.smallest_run {
            Some(smallest) => smallest.min(bytes.len()),
            None => bytes.len(),
        });
    }

    fn finish(self: Box<Self>) -> ObserverOutcome {
        ObserverOutcome::new("byte-counter", &self.observed_bytes.to_be_bytes(), self.observed_bytes)
    }

    fn label(&self) -> &'static str {
        "byte-counter"
    }
}
