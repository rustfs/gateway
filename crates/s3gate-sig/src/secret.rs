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

//! Key material containers: zeroized on drop, unprintable, and uncomparable.
//!
//! Responsible for: holding bytes that must never reach a log line, a panic message, a `tracing`
//! field or a `==`, and wiping them when they go out of scope.
//! NOT responsible for: fetching, caching or validating credentials (that is P2-04 and the
//! `Authorizer` extension point), nor comparing anything — a secret comparison belongs in
//! [`crate::Signature`], where it is constant-time by construction.
//! Upstream: `zeroize`. Downstream: [`crate::SigIdentity`], and P2-02's credential lookup.

use zeroize::Zeroizing;

use crate::error::SigParseError;

/// A byte string that is wiped on drop and can be neither printed nor compared.
///
/// The missing impls are the feature. There is no `Debug`, so a secret cannot be interpolated
/// into a log line or an error type by a `#[derive(Debug)]` three structs away. There is no
/// `Display`, so it cannot be formatted into a response body. There is no `PartialEq`, so
/// `secret_a == secret_b` does not compile and every comparison has to go through a constant-time
/// path that the author had to write deliberately.
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of key material.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the raw bytes.
    ///
    /// The name is the warning. Every call site is a place where key material escapes the
    /// container, so each one should be short, local, and headed straight into a cryptographic
    /// primitive or a constant-time comparison.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the container is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An STS session token, from `X-Amz-Security-Token` (header or query).
///
/// The token is a credential, so it gets the same treatment as the secret key: no `Debug`, no
/// `Display`, no `PartialEq`, wiped on drop. It is also a *signed* input — P2-03 requires it to
/// appear in `SignedHeaders`, otherwise an attacker could swap the token on an otherwise valid
/// request and change which identity the request runs as.
///
/// The absence of `Debug` propagates: a struct that holds one cannot derive `Debug` either, so
/// the leak cannot be re-introduced three types away from here.
///
/// ```compile_fail,E0277
/// use s3gate_sig::SessionToken;
/// #[derive(Debug)]
/// struct Claims {
///     token: SessionToken, // no Debug: the derive does not compile
/// }
/// ```
///
/// The same absence blocks the serialization route. There is no `Display`, and with no `Debug`
/// and no `Serialize` there is no formatting path that reaches the bytes:
///
/// ```compile_fail,E0277
/// use s3gate_sig::SessionToken;
/// let token = SessionToken::new("secret").expect("non-empty");
/// let _ = format!("{token}"); // no Display: does not compile
/// ```
#[derive(Clone)]
pub struct SessionToken(SecretBytes);

impl SessionToken {
    /// Validates and stores a session token.
    ///
    /// # Errors
    ///
    /// [`SigParseError::EmptySessionToken`] if the token is empty. An empty token is not the same
    /// as an absent one: absent means long-term credentials, present-but-empty means a client or
    /// a proxy dropped the value, and silently treating it as long-term would strip the session
    /// scoping that limits what the credentials may do.
    pub fn new(token: &str) -> Result<Self, SigParseError> {
        if token.is_empty() {
            return Err(SigParseError::EmptySessionToken);
        }
        Ok(Self(SecretBytes::new(token.as_bytes().to_vec())))
    }

    /// Borrows the raw token bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Number of bytes in the token.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: an empty token cannot be constructed.
    ///
    /// Provided because `len` without `is_empty` is a clippy lint, and because a caller reading
    /// `token.is_empty()` should see, in one hop, that emptiness was already rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_session_token_is_rejected() {
        assert!(matches!(SessionToken::new(""), Err(SigParseError::EmptySessionToken)));
    }

    #[test]
    fn session_token_exposes_exactly_what_was_given() {
        let token = SessionToken::new("FQoGZXIvYXdzE").expect("non-empty");
        assert_eq!(token.expose(), b"FQoGZXIvYXdzE");
        assert_eq!(token.len(), 13);
        assert!(!token.is_empty());
    }
}
