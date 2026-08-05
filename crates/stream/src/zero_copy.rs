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

//! Asking for the kernel-side transfer path, and being told exactly why the answer is no.
//!
//! Responsible for: [`TransportCaps`] (what the transport underneath can do), the
//! [`VerificationObligation`] the wire layer attaches to a body it has promised to verify, the
//! [`ZeroCopyQuery`] that pairs the two, and [`NoZeroCopy`] — the named refusal that replaces a
//! `None` nobody can attribute.
//! NOT responsible for: performing a transfer, opening a file, or knowing what TLS is. Every type
//! here is a description; the transport reads them and acts.
//! Upstream: `bitflags`. Downstream: `payload`, `metrics`, and the transport that writes a
//! response.
//!
//! # Why the refusal is an enum and not an `Option`
//!
//! Four different facts stop a body from being handed to `sendfile`, and an operator staring at a
//! throughput regression has to tell them apart: the body was never a file; the transport in front
//! has no kernel-side path; TLS sits in the way, so the bytes must pass through user space to be
//! encrypted; or the body carries a verification obligation, and letting the kernel move bytes the
//! gateway promised to check is how a fast path becomes a validation bypass. `None` collapses all
//! four into "it did not work", which is exactly the state in which a fast path decays silently.

use core::fmt;

bitflags::bitflags! {
    /// What the transport underneath a response can do.
    ///
    /// A transport declares these once, at construction. The payload never inspects the
    /// transport and the transport never inspects the payload's concrete type: both sides state
    /// capabilities, and the negotiation is a comparison of two named sets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TransportCaps: u32 {
        /// The transport can write several buffers in one call.
        const VECTORED = 1 << 0;
        /// The transport can hand a file descriptor to the kernel and never touch the bytes.
        const SENDFILE = 1 << 1;
        /// The transport can splice between descriptors.
        const SPLICE = 1 << 2;
        /// The transport encrypts, so every byte must be readable in user space.
        ///
        /// This is a capability in the sense that it describes the path; it is the one bit whose
        /// presence *removes* options.
        const TLS_IN_PATH = 1 << 3;
    }
}

impl TransportCaps {
    /// Whether any kernel-side transfer is possible at all.
    #[must_use]
    pub fn has_kernel_transfer(self) -> bool {
        self.intersects(Self::SENDFILE | Self::SPLICE)
    }
}

/// Whether the gateway has promised to verify the bytes of this body.
///
/// Not a `bool`. The value travels with the payload through several layers, and at each hand-off
/// the question "true meaning what?" has to be answerable from the type alone.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationObligation {
    /// Nothing about this body still has to be checked.
    None,
    /// The body is framed, signed, digested or otherwise still owed a check.
    ///
    /// A payload in this state must never reach a path that moves bytes without the gateway
    /// seeing them: the check would then be performed on nothing, or skipped outright. This is
    /// the type-level form of the review finding recorded as C-22.
    Present,
}

impl VerificationObligation {
    /// Whether a check is still owed.
    #[must_use]
    pub fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

/// One transport's question: can this body take the kernel-side path?
///
/// Both halves are required. A query built from the transport alone cannot see the obligation and
/// would answer "yes" for a body the gateway has promised to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroCopyQuery {
    transport: TransportCaps,
    obligation: VerificationObligation,
}

impl ZeroCopyQuery {
    /// Builds a query from a transport's capabilities and the body's outstanding obligation.
    #[must_use]
    pub fn new(transport: TransportCaps, obligation: VerificationObligation) -> Self {
        Self { transport, obligation }
    }

    /// The transport's capabilities.
    #[must_use]
    pub fn transport(&self) -> TransportCaps {
        self.transport
    }

    /// The body's outstanding verification obligation.
    #[must_use]
    pub fn obligation(&self) -> VerificationObligation {
        self.obligation
    }

    /// The reason a kernel-side transfer is unavailable, ignoring the payload's own shape.
    ///
    /// The order is deliberate and is the security order, not the cheap-check order: an
    /// outstanding verification obligation refuses first, so a body the gateway promised to check
    /// is never reported as "the transport could have done it".
    #[must_use]
    pub fn refusal(&self) -> Option<NoZeroCopy> {
        if self.obligation.is_present() {
            return Some(NoZeroCopy::VerificationObligationPresent);
        }
        if self.transport.contains(TransportCaps::TLS_IN_PATH) {
            return Some(NoZeroCopy::TlsInPath);
        }
        if !self.transport.has_kernel_transfer() {
            return Some(NoZeroCopy::TransportLacksSendfile);
        }
        None
    }
}

/// Why a body could not be handed to a kernel-side transfer.
///
/// Every variant is a fact an operator can act on, and every one of them is counted in
/// [`StreamMetrics`]. This is the type that replaces a runtime downcast returning `None`.
///
/// [`StreamMetrics`]: crate::StreamMetrics
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoZeroCopy {
    /// The body is not a file region; there is no descriptor to hand over.
    NotFileBacked,
    /// The transport in front has no `sendfile`/`splice` path.
    TransportLacksSendfile,
    /// The body still owes a verification, so no path may move its bytes unseen.
    VerificationObligationPresent,
    /// TLS is in the path, so every byte must be readable in user space to be encrypted.
    TlsInPath,
}

impl NoZeroCopy {
    /// A short, stable label for logs, metrics and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFileBacked => "not-file-backed",
            Self::TransportLacksSendfile => "transport-lacks-sendfile",
            Self::VerificationObligationPresent => "verification-obligation-present",
            Self::TlsInPath => "tls-in-path",
        }
    }
}

impl fmt::Display for NoZeroCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFileBacked => "payload is not backed by a file region",
            Self::TransportLacksSendfile => "transport has no kernel-side transfer path",
            Self::VerificationObligationPresent => "payload still owes a verification, so its bytes may not be moved unseen",
            Self::TlsInPath => "TLS is in the path, so the bytes must pass through user space",
        })
    }
}

impl std::error::Error for NoZeroCopy {}
