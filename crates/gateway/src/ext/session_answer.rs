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

//! The session refusal a verifier decided before its signature comparison, held until after it.
//!
//! Responsible for: [`PendingSessionRefusal`], the only route to an `ExpiredToken` answer, which
//! takes the comparison's [`SignatureMatch`] as an argument, and the placeholder session an
//! unknown access key is admitted against so the two paths do the same session work.
//! NOT responsible for: deciding which session rule fired (`super::credentials::Credentials::admit`
//! does, and the reason never leaves that file) or comparing a signature (`rustfs-gateway-sig`).
//! Upstream: `super::credentials`. Downstream: `super::authenticator` (rustfs/gateway#1575).

use std::sync::OnceLock;

use rustfs_gateway_sig::{AuthError, SignatureMatch};

use super::credentials::{Credentials, SessionBinding};

/// A refusal the built-in authenticator computed before the signature comparison.
///
/// It has no public constructor and no `Default`. The only answer that names the expiry,
/// [`PendingSessionRefusal::answer`], takes the [`SignatureMatch`] that only a constant-time
/// signature comparison produces, so "tell the caller its session expired before its signature
/// verified" cannot be written with this type. Without a match the answer is
/// [`PendingSessionRefusal::uniform`].
///
/// ```compile_fail,E0061
/// use rustfs_gateway::PendingSessionRefusal;
/// fn leak(pending: PendingSessionRefusal) -> rustfs_gateway_sig::AuthError {
///     pending.answer() // the proof is the argument; there is no other way to the answer
/// }
/// ```
///
/// ```compile_fail,E0451
/// let _ = rustfs_gateway::PendingSessionRefusal { expired: true };
/// ```
#[must_use]
pub struct PendingSessionRefusal {
    expired: bool,
}

impl PendingSessionRefusal {
    /// Built only by `Credentials`' session admission, beside the rule that decided it.
    pub(super) const fn new(expired: bool) -> Self {
        Self { expired }
    }

    /// The answer owed after the signature compared equal under the credential's own secret:
    /// `ExpiredToken` when the session's lifetime ended and the issued token was presented, the
    /// uniform `InvalidAccessKeyId` for every other session rule.
    pub const fn answer(self, proof: &SignatureMatch) -> AuthError {
        let _ = proof;
        if self.expired {
            AuthError::ExpiredToken
        } else {
            AuthError::InvalidAccessKeyId
        }
    }

    /// The answer owed when the signature did not compare equal: always the uniform refusal.
    pub const fn uniform(self) -> AuthError {
        AuthError::InvalidAccessKeyId
    }
}

impl core::fmt::Debug for PendingSessionRefusal {
    /// Says nothing about which rule fired.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PendingSessionRefusal")
    }
}

/// The session an unknown access key is admitted against, so the session rules cost an unknown
/// key what they cost a known one: the same token comparison, or the same query scan and decode.
///
/// `None` only if the constant fixture below were refused, which would leave the unknown-key path
/// doing less work rather than answering differently.
pub(super) fn placeholder_session() -> Option<&'static Credentials> {
    static PLACEHOLDER: OnceLock<Option<Credentials>> = OnceLock::new();
    PLACEHOLDER
        .get_or_init(|| {
            let binding = SessionBinding::new("placeholder.invalid", i64::MIN).ok()?;
            Credentials::new("AKIDPLACEHOLDERSESSION", b"placeholder-session-secret")
                .ok()?
                .with_session("placeholder-session-token-of-a-typical-issued-length-0000000000", binding)
                .ok()
        })
        .as_ref()
}
