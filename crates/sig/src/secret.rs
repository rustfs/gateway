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

//! Key material containers: zeroized on drop, unprintable, uncomparable, uncloneable.
//!
//! Responsible for: holding bytes that must never reach a log line, a panic message, a `tracing`
//! field or a `==`, and wiping them when they go out of scope — [`SecretBytes`] for a long-term
//! secret access key, [`SigningKey`] for each of the four SigV4 derivation steps, [`SessionToken`]
//! for an STS token; plus [`SafeToLog`], the compile-time gate that says *why* none of them may be
//! formatted.
//! NOT responsible for: fetching, caching or validating credentials (that is P2-04 and the
//! `Authorizer` extension point), deriving the keys themselves (P2-03 owns the HMAC chain), nor
//! comparing anything — a secret comparison belongs in [`crate::Signature`], where it is
//! constant-time by construction.
//! Upstream: `zeroize`. Downstream: [`crate::SigIdentity`], [`crate::timing`]'s placeholder
//! credential, and P2-03's key derivation.
//!
//! # Why every container is `Box<[u8]>` and never `Vec<u8>` or `String`
//!
//! `zeroize` clears a `Vec`'s whole capacity, not just its length — but it cannot clear the
//! buffers a `Vec` left behind when it grew. A secret accumulated into a `Vec` that reallocated
//! 16 → 32 → 64 leaves the 16- and 32-byte copies intact on the heap, and `Drop` never sees them.
//! `Box<[u8]>` is allocated once at its final size and never reallocates, so there is nothing to
//! leave behind. `String` has the same defect as `Vec`.
//!
//! The rule that follows: key material is never accumulated into a growing buffer. Build the bytes
//! in a fixed-size array and hand ownership over, or copy once from a borrowed slice.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::SigParseError;

/// Values that may be interpolated into a log line, an error message or a span field.
///
/// Implemented for everything that has a `Debug` — including the types in this crate that
/// hand-write a redacting one, such as [`crate::SigIdentity`]. Key material has no `Debug` at all,
/// so it is the one thing this trait does *not* cover, and [`assert_safe_to_log`] turns that into
/// a compile error with an explanation instead of an `E0277` about a missing `Debug` impl.
#[diagnostic::on_unimplemented(
    message = "`{Self}` may not be written to a log, an error message or a span field",
    label = "no `Debug`, because this value carries key material",
    note = "`SecretBytes`, `SigningKey` and `SessionToken` deliberately implement neither `Debug`, \
            `Display`, nor any serializer: that absence propagates, so a struct three types away \
            cannot re-introduce the leak with `#[derive(Debug)]` either.",
    note = "If you need the bytes for a cryptographic primitive, call `expose()` at the call site \
            and keep the borrow short. If you need to name the value in a diagnostic, log the \
            access key id — it is a public identifier — and never the secret."
)]
pub trait SafeToLog {}

impl<T: fmt::Debug + ?Sized> SafeToLog for T {}

/// Compile-time gate: accepts anything printable, rejects key material.
///
/// Call it where a value is about to become part of a diagnostic. It costs nothing at run time
/// and turns "somebody logged the secret" into a compile error carrying the reason.
///
/// ```
/// # use rustfs_gateway_sig::assert_safe_to_log;
/// assert_safe_to_log(&"AKIAIOSFODNN7EXAMPLE");
/// ```
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::{SecretBytes, assert_safe_to_log};
/// let secret = SecretBytes::new(b"wJalrXUtnFEMI");
/// assert_safe_to_log(&secret); // key material: does not compile
/// ```
pub fn assert_safe_to_log<T: SafeToLog + ?Sized>(_value: &T) {}

/// A byte string that is wiped on drop and can be neither printed, compared, nor cloned.
///
/// The missing impls are the feature:
///
/// * no `Debug` and no `Display`, so it cannot be interpolated into a log line, a panic message or
///   a response body — not directly, and not by a `#[derive(Debug)]` three structs away;
/// * no `Serialize`, so it cannot be written into a config dump or an admin API response;
/// * no `PartialEq`, so `secret_a == secret_b` does not compile and every comparison has to go
///   through a constant-time path the author wrote deliberately;
/// * no `Clone`, so a copy is never implicit. [`SecretBytes::clone_secret`] exists for the cases
///   that genuinely need one, and its name is long and greppable on purpose.
///
/// ```compile_fail,E0369
/// use rustfs_gateway_sig::SecretBytes;
/// let a = SecretBytes::new(b"one");
/// let b = SecretBytes::new(b"two");
/// let _ = a == b; // no PartialEq: does not compile
/// ```
///
/// ```compile_fail,E0599
/// use rustfs_gateway_sig::SecretBytes;
/// let a = SecretBytes::new(b"one");
/// let _ = a.clone(); // no Clone: use `clone_secret`, which is visible in review
/// ```
pub struct SecretBytes(Zeroizing<Box<[u8]>>);

impl SecretBytes {
    /// Copies key material into a container that is allocated once and wiped on drop.
    ///
    /// The copy is exact-sized and never reallocates. The caller's own buffer is not this type's
    /// responsibility: if it came out of a growing `Vec` or a `String`, the residue of that growth
    /// is already on the heap and no `Drop` can reach it.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(Box::from(bytes)))
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

    /// An explicit second copy of the same key material.
    ///
    /// Spelled out rather than `Clone` so that duplicating a secret is a decision somebody made
    /// and a reviewer can `grep` for, instead of something a `#[derive(Clone)]` did on their
    /// behalf.
    #[must_use]
    pub fn clone_secret(&self) -> Self {
        Self::new(self.expose())
    }

    /// Number of bytes held. The length is not key material; the bytes are.
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

/// One of the four SigV4 derivation steps: `kDate`, `kRegion`, `kService`, `kSigning`.
///
/// Every step is a secret equivalent, not just the last one: `kService` signs `aws4_request` to
/// produce `kSigning`, so anybody holding an intermediate can mint the final signing key for that
/// scope and every request under it. Wrapping all four in one type means all four are wiped, and
/// none of them can be printed or compared.
///
/// It is a fixed 32 bytes because every step is an HMAC-SHA256 output. Construction takes an
/// owned array so the value moves in rather than being borrowed from a buffer that outlives it.
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::SigningKey;
/// #[derive(Debug)]
/// struct Derivation {
///     k_signing: SigningKey, // no Debug: the derive does not compile
/// }
/// ```
pub struct SigningKey(Zeroizing<Box<[u8]>>);

impl SigningKey {
    /// The width of every derivation step, in bytes: one HMAC-SHA256 output.
    pub const LEN: usize = 32;

    /// Takes ownership of one derivation step's output.
    ///
    /// Boxed immediately: an intermediate key that stays in a local `[u8; 32]` is copied by every
    /// move, and those copies are not reachable from any `Drop`.
    #[must_use]
    pub fn from_array(bytes: [u8; Self::LEN]) -> Self {
        Self(Zeroizing::new(Box::from(bytes.as_slice())))
    }

    /// Borrows the key, for feeding straight into the next HMAC step.
    ///
    /// Always exactly [`SigningKey::LEN`] bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// An explicit second copy. See [`SecretBytes::clone_secret`] for why this is not `Clone`.
    #[must_use]
    pub fn clone_secret(&self) -> Self {
        Self(Zeroizing::new(Box::from(self.expose())))
    }
}

/// An STS session token, from `X-Amz-Security-Token` (header or query).
///
/// The token is a credential, so it gets the same treatment as the secret key: no `Debug`, no
/// `Display`, no `PartialEq`, no `Clone`, wiped on drop. It is also a *signed* input — P2-03
/// requires it to appear in `SignedHeaders`, otherwise an attacker could swap the token on an
/// otherwise valid request and change which identity the request runs as.
///
/// The absence of `Debug` propagates: a struct that holds one cannot derive `Debug` either, so
/// the leak cannot be re-introduced three types away from here.
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::SessionToken;
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
/// use rustfs_gateway_sig::SessionToken;
/// let token = SessionToken::new("secret").expect("non-empty");
/// let _ = format!("{token}"); // no Display: does not compile
/// ```
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
        Ok(Self(SecretBytes::new(token.as_bytes())))
    }

    /// Borrows the raw token bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// An explicit second copy. See [`SecretBytes::clone_secret`] for why this is not `Clone`.
    #[must_use]
    pub fn clone_secret(&self) -> Self {
        Self(self.0.clone_secret())
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

    #[test]
    fn clone_secret_copies_the_bytes_without_clone() {
        let secret = SecretBytes::new(b"wJalrXUtnFEMI/K7MDENG");
        let copy = secret.clone_secret();
        assert_eq!(copy.expose(), secret.expose());
        // Distinct allocations: dropping one must not leave the other dangling or wiped.
        assert!(!core::ptr::eq(copy.expose().as_ptr(), secret.expose().as_ptr()));
    }

    #[test]
    fn signing_key_is_always_one_hmac_wide() {
        let key = SigningKey::from_array([0x5a; SigningKey::LEN]);
        assert_eq!(key.expose().len(), SigningKey::LEN);
        assert_eq!(key.clone_secret().expose(), key.expose());
    }
}
