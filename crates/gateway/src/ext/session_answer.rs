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

    /// Whether verifying a signature over the request body can change the refusal from the
    /// uniform `InvalidAccessKeyId` (specifically, to `ExpiredToken` via [`Self::answer`]).
    ///
    /// Used only by the STS / S3 Vectors body-digest path (`rustfs/gateway#1581`) to avoid
    /// buffering an unauthenticated body when no signature could alter the uniform refusal.
    /// Obtaining `ExpiredToken` still requires a [`SignatureMatch`] through [`Self::answer`].
    pub(super) const fn needs_signature_proof(&self) -> bool {
        self.expired
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use rustfs_gateway_sig::{RawQuery, RequestNow};

    use super::*;
    use crate::ext::credentials::SessionSurface;

    /// Positive — the constant placeholder session fixture must be accepted so the unknown-key,
    /// disabled-key and long-term-key equalization paths never silently skip token work
    /// (rustfs/gateway#1584).
    #[test]
    fn placeholder_session_is_present_and_carries_an_enabled_temporary_session() {
        let placeholder = placeholder_session().expect("placeholder_session() must return Some");
        assert!(placeholder.session_token().is_some());
        assert!(!placeholder.is_disabled());
    }

    /// Negative — admitting requests against the placeholder session always produces a pending
    /// refusal whose unmatched answer is uniform `InvalidAccessKeyId`.
    #[test]
    fn n_placeholder_session_refuses_presented_and_absent_tokens_uniformly() {
        let placeholder = placeholder_session().expect("placeholder_session() must return Some");
        let now = RequestNow::from_unix_seconds(1_000);
        let with_token = placeholder
            .admit_surface_pending(Some(b"caller-presented-token"), SessionSurface::Sts, now)
            .expect("arbitrary presented token must be refused");
        assert_eq!(with_token.uniform(), AuthError::InvalidAccessKeyId);

        let without_token = placeholder
            .admit_surface_pending(None, SessionSurface::Sts, now)
            .expect("missing token must be refused");
        assert_eq!(without_token.uniform(), AuthError::InvalidAccessKeyId);

        let query_refusal = placeholder
            .admit_query_param_pending(
                RawQuery::new("X-Amz-Security-Token=caller-presented-token"),
                rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN,
                SessionSurface::Sts,
                now,
            )
            .expect("arbitrary presigned token must be refused");
        assert_eq!(query_refusal.uniform(), AuthError::InvalidAccessKeyId);
    }

    /// Negative — `PendingSessionRefusal::uniform` and `Debug` reveal nothing about whether the
    /// underlying refusal was an expired session.
    #[test]
    fn n_pending_session_refusal_uniform_and_debug_hide_expiry() {
        for expired in [false, true] {
            let pending = PendingSessionRefusal::new(expired);
            let rendered = format!("{pending:?}");
            assert_eq!(rendered, "PendingSessionRefusal");
            assert_eq!(pending.uniform(), AuthError::InvalidAccessKeyId);
        }
    }

    fn equalization_cases() -> [(&'static str, Credentials, bool); 6] {
        let live_binding = SessionBinding::new("sts.example.com", 2_000).expect("valid binding");
        let expired_binding = SessionBinding::new("sts.example.com", 500).expect("valid binding");
        let temporary = |binding| {
            Credentials::new("AKIDTEMP", b"test-material")
                .expect("valid")
                .with_session("session-token-value", binding)
                .expect("valid")
        };
        let placeholder = placeholder_session().expect("placeholder session").clone_credentials();
        let long_term = Credentials::new("AKIDLONG", b"test-material").expect("valid");
        let disabled_long_term = Credentials::new("AKIDDISLONG", b"test-material").expect("valid").disable();
        [
            ("unknown-placeholder", placeholder, true),
            ("live-session", temporary(live_binding.clone()), false),
            ("expired-session", temporary(expired_binding), true),
            ("disabled-session", temporary(live_binding).disable(), true),
            ("disabled-long-term", disabled_long_term, true),
            ("active-long-term", long_term, true),
        ]
    }

    /// Negative — disabled and long-term keys presenting a token run the same single constant-time
    /// token comparison as temporary and unknown keys on both STS and S3 Express surfaces
    /// (rustfs/gateway#1584), and every state runs zero comparisons when no token is presented.
    #[test]
    fn n_disabled_and_long_term_surface_refusals_match_token_comparison_count() {
        let now = RequestNow::from_unix_seconds(1_000);
        for (label, creds, expects_sts_refusal) in equalization_cases() {
            for (surface_name, surface) in [("sts", SessionSurface::Sts), ("s3express", SessionSurface::S3Express)] {
                let mut with_token = 0_usize;
                let pending = creds.admit_surface_pending_with(Some(b"session-token-value"), surface, now, |tok, p| {
                    with_token += 1;
                    tok.ct_verify(p).is_ok()
                });
                if surface == SessionSurface::Sts {
                    assert_eq!(pending.is_some(), expects_sts_refusal, "{label}");
                } else {
                    assert!(pending.is_some(), "{label} ({surface_name})");
                }
                if let Some(refusal) = pending {
                    assert_eq!(refusal.uniform(), AuthError::InvalidAccessKeyId, "{label} ({surface_name})");
                }
                assert_eq!(with_token, 1, "{label} ({surface_name}) must perform one token comparison");

                let mut without_token = 0_usize;
                let _ = creds.admit_surface_pending_with(None, surface, now, |tok, p| {
                    without_token += 1;
                    tok.ct_verify(p).is_ok()
                });
                assert_eq!(without_token, 0, "{label} ({surface_name}) must perform zero comparisons without a token");
            }
        }
    }

    /// Negative — disabled and long-term keys run the same single presigned query token scan and
    /// comparison as temporary and unknown keys on both STS and S3 Express query parameters
    /// (rustfs/gateway#1584).
    #[test]
    fn n_disabled_and_long_term_query_refusals_match_query_scan_count() {
        let now = RequestNow::from_unix_seconds(1_000);
        let sts_query = RawQuery::new("X-Amz-Security-Token=session-token-value");
        let express_query = RawQuery::new("X-Amz-S3session-Token=session-token-value");
        for (label, creds, expects_sts_refusal) in equalization_cases() {
            for (surface_name, surface, param, query) in [
                ("sts", SessionSurface::Sts, rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN, sts_query),
                (
                    "s3express",
                    SessionSurface::S3Express,
                    rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN,
                    express_query,
                ),
            ] {
                let mut scans = 0_usize;
                let pending = creds.admit_query_param_pending_with(surface, now, |tok| {
                    scans += 1;
                    query.session_token_matches(param, tok)
                });
                if surface == SessionSurface::Sts {
                    assert_eq!(pending.is_some(), expects_sts_refusal, "{label}");
                } else {
                    assert!(pending.is_some(), "{label} ({surface_name})");
                }
                if let Some(refusal) = pending {
                    assert_eq!(refusal.uniform(), AuthError::InvalidAccessKeyId, "{label} ({surface_name})");
                }
                assert_eq!(scans, 1, "{label} ({surface_name}) must perform one presigned query token scan");
            }
        }
    }
}
