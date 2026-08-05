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

//! What a payload can do, stated as named bits instead of a runtime type test.
//!
//! Responsible for: the capability bit set a transport asks a payload about before it picks a
//! write strategy, and the consistency rule that ties the bits to the declared length.
//! NOT responsible for: performing any transfer, or deciding which strategy is best — the bits
//! only describe what is possible, the transport decides what to do with that.
//! Upstream: `bitflags`. Downstream: `payload`, `stream`, `read`, `body`, `byte_stream`, and
//! the wire layer that negotiates a write strategy.

use core::fmt;

bitflags::bitflags! {
    /// The named capabilities of a payload.
    ///
    /// Capability negotiation is explicit and exhaustible: a transport reads the bits and calls
    /// a named accessor. There is no `as_any()` and no downcast anywhere in this crate, because
    /// a downcast has no contract — when it stops matching, the fast path disappears with no
    /// compile error, no metric, and no way to notice — and because a downcast can hand the
    /// transport the inner payload of a validating wrapper, which is a way to skip validation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PayloadCaps: u32 {
        /// The exact byte length is known up front; [`len_hint`] returns `Some`.
        ///
        /// [`len_hint`]: crate::Payload::len_hint
        const KNOWN_LENGTH = 1 << 0;
        /// The payload can be re-positioned; reading it does not consume the source.
        const SEEKABLE = 1 << 1;
        /// The payload is a file region and can be handed to a kernel-side transfer path.
        const FILE_REGION = 1 << 2;
        /// The payload is already split into segments that can be written in one vectored call.
        const VECTORED = 1 << 3;
        /// The payload can be produced again from the start, as a retry or a re-sign needs.
        const REPLAYABLE = 1 << 4;
        /// The payload bytes are already resident in user-space memory.
        const IN_MEMORY = 1 << 5;
        /// The payload natively supports the pull model: the consumer supplies the buffer.
        const PULL = 1 << 6;
        /// The payload natively supports the push model: the producer supplies the buffer.
        const PUSH = 1 << 7;
    }
}

/// The declared capabilities and the declared length contradict each other.
///
/// [`PayloadCaps::KNOWN_LENGTH`] and a `Some` length hint must agree in both directions. A
/// producer that sets the bit without a length makes every consumer that trusts the bit
/// allocate against a length that does not exist; a producer that knows the length but hides
/// the bit silently costs every consumer the fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsInconsistency {
    /// The capability bits the producer declared.
    pub caps: PayloadCaps,
    /// Whether the producer also declared an exact length.
    pub has_len_hint: bool,
}

impl fmt::Display for CapsInconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_len_hint {
            f.write_str("payload declares an exact length but not PayloadCaps::KNOWN_LENGTH")
        } else {
            f.write_str("payload declares PayloadCaps::KNOWN_LENGTH but no exact length")
        }
    }
}

impl std::error::Error for CapsInconsistency {}

/// Checks that [`PayloadCaps::KNOWN_LENGTH`] and the length hint agree.
///
/// This is a plain checked function rather than a `debug_assert!` so that the rule holds in
/// release builds too: a capability lie is a wire-facing defect, and a check that only runs in
/// debug builds is a check that does not run where it matters.
pub fn validate_caps(caps: PayloadCaps, len_hint: Option<u64>) -> Result<(), CapsInconsistency> {
    if caps.contains(PayloadCaps::KNOWN_LENGTH) == len_hint.is_some() {
        Ok(())
    } else {
        Err(CapsInconsistency {
            caps,
            has_len_hint: len_hint.is_some(),
        })
    }
}
