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

//! The stated payload digest of `sign.payload_hash = "literal"`.
//!
//! Responsible for: turning `sign.payload_hash_literal` into the exact-digest payload mode the
//! header signer then signs as stated, so a case can sign the digest of bytes it does not send —
//! the only way to ask whether a server compares the payload with its signed hash (c-sig-0596).
//! NOT responsible for: reading the case key (the caller does, so the key ledger records the read
//! where the decision is made), or any streaming spelling, which needs framing this target lacks.
//! Upstream: `super::sign_request`. Downstream: the facade's SigV4 signer.

use rustfs_gateway::sig::{PayloadMode, TrailerSet};

use crate::sut::SutError;

/// The exact-digest payload mode `literal` spells, in hex or canonical base64.
///
/// # Errors
///
/// [`SutError::Environment`] when the key is absent, or names anything but a SHA-256 digest — a
/// streaming or unsigned token would be a different mode, not a stated digest.
pub(super) fn payload(literal: Option<&str>) -> Result<PayloadMode, SutError> {
    let literal =
        literal.ok_or_else(|| SutError::Environment("`payload_hash = \"literal\"` needs `payload_hash_literal`".to_owned()))?;
    match PayloadMode::parse(literal, TrailerSet::None) {
        Ok(payload) if payload.digest().is_some() => Ok(payload),
        _ => Err(SutError::Environment(format!(
            "`payload_hash_literal = \"{literal}\"` is not a SHA-256 digest in hex or base64"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_PAYLOAD_SHA256: &str = "c32cace75647e3e184b9dce888af087f63740976550541874c37a1037b196b56";

    #[test]
    fn a_hex_digest_is_signed_as_stated() {
        let payload = payload(Some(EXPECTED_PAYLOAD_SHA256)).ok();
        assert!(payload.as_ref().and_then(PayloadMode::digest).is_some(), "{payload:?}");
    }

    #[test]
    fn anything_but_a_digest_is_refused_by_name() {
        for literal in [
            None,
            Some("UNSIGNED-PAYLOAD"),
            Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
            Some("c32c"),
        ] {
            assert!(matches!(payload(literal), Err(SutError::Environment(_))), "{literal:?}");
        }
    }
}
