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

//! SigV2 — `Authorization: AWS <access-key>:<signature>`, HMAC-SHA1, standard base64.
//!
//! Responsible for: the exact `Authorization` grammar, the 20-byte signature decode, the SigV2-only
//! `Expires` rules (absolute Unix second, not SigV4's window), the [`SigV2Policy`] switch, and the
//! single verification entry point — which is [`Signature::ct_verify`], reached through
//! [`verify_presented`]. There is deliberately no comparison of any kind in this module.
//! NOT responsible for: building the string-to-sign (that is [`string_to_sign`]), clock skew,
//! privileged-operation refusal or duplicate signature parameters (that is [`crate::SecurityFloor`],
//! H1/H3/H6), POST-form field enforcement (that is [`crate::post_policy`]), or deciding whether a
//! request presented credentials at all (that is [`crate::detect_credentials`], H4).
//! Upstream: [`crate::codec`], [`crate::Signature`], [`crate::RequestNow`]. Downstream: P2-06's
//! verifier wiring, which is not yet in place — [`crate::SecurityFloor::admit`] still answers
//! `NotImplemented(SigV2)`, so nothing here is reachable from a served request today.
//!
//! # Why SigV2 at all
//!
//! aws-sdk-js v2, botocore's `signature_version: s3`, and a long tail of embedded clients sign this
//! way, and RustFS's own warm-tier signer does too. Refusing it outright is a compatibility break;
//! implementing it carelessly is worse, because SigV2 is the algorithm whose presigned form MinIO
//! #5411 was rewritten from.
//!
//! # The two rules this module exists to keep
//!
//! 1. **One comparison.** SigV2's 20-byte signature goes through the same [`Signature::ct_verify`]
//!    as SigV4's 32-byte one. A second comparison — `presented == expected`, on two `String`s —
//!    is the s3s#616 and rustfs#4519 defect, and `scripts/check_ct_eq.sh` rule 9 fails the build
//!    if one appears anywhere under `crates/sig/src/`.
//! 2. **One encoding.** Standard base64 alphabet, exact padding, exactly 20 bytes, real
//!    timestamps. URL-safe unpadded base64 and a timestamp truncated to midnight are the two
//!    halves of rustfs#4456.

pub mod sealed;
pub mod signer;
pub mod string_to_sign;
pub mod timestamp;

pub use sealed::SealedSigV2;
pub use signer::SigV2Signer;
pub use string_to_sign::{INCLUDED_QUERY, SIGV2_EXPIRES_PARAM, SigV2Mode, SigV2StringToSign, SigV2StringToSignSpec};
pub use timestamp::{parse_sigv2_date, signed_timestamp};

use crate::clock::{MAX_PRESIGNED_EXPIRY_SECONDS, RequestNow};
use crate::codec::decode_base64_exact;
use crate::contracts::SIGV2_EXPIRES_ABSOLUTE;
use crate::scheme::ALGORITHM_SIGV2_PREFIX;
use crate::signature::{CtBytes, Signature, SignatureMatch};
use crate::verdict::{AuthError, Identity};

/// Whether SigV2 is accepted, and in which location.
///
/// The default is [`SigV2Policy::HeaderOnly`]: header authentication works, presigned SigV2 does
/// not. Presigned is the dangerous half — a presigned URL is a bearer token that travels in
/// referrer headers, proxy logs and browser history, SigV2 signs almost none of the query string
/// (see [`INCLUDED_QUERY`]), and MinIO #5411 was a rewritten SigV2 presigned URL that reached an
/// admin operation. Turning it on is therefore an explicit deployment decision, and the startup
/// security-posture report names the value in force.
///
/// `#[non_exhaustive]`, so a downstream `match` keeps a wildcard arm and a future stricter variant
/// is not a breaking change.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SigV2Policy {
    /// SigV2 is refused in every location. The safest setting, and the right one for a deployment
    /// with no legacy clients.
    Disabled,
    /// `Authorization: AWS …` is accepted; presigned SigV2 URLs are refused.
    #[default]
    HeaderOnly,
    /// Both locations are accepted. Opt-in, and still subject to the security floor's H1/H3/H6.
    HeaderAndPresigned,
}

impl SigV2Policy {
    /// Whether this policy admits SigV2 in the given location.
    #[must_use]
    pub const fn allows(&self, mode: SigV2Mode) -> bool {
        match (self, mode) {
            (Self::Disabled, _) => false,
            (Self::HeaderOnly, SigV2Mode::HeaderAuth) => true,
            (Self::HeaderOnly, SigV2Mode::PresignedUrl) => false,
            (Self::HeaderAndPresigned, _) => true,
        }
    }

    /// The name used in the startup security-posture report.
    ///
    /// A posture report that prints a number nobody can map back to a variant is a report nobody
    /// reads, so the spelling is fixed here rather than derived from `Debug`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::HeaderOnly => "HeaderOnly",
            Self::HeaderAndPresigned => "HeaderAndPresigned",
        }
    }
}

/// A parsed `Authorization: AWS <access-key>:<signature>` header.
///
/// It has no `Debug` — it carries a [`Signature`], which has none either, so printing the
/// presented signature is a compile error rather than a log line an attacker can read back.
pub struct SigV2Authorization {
    access_key_id: String,
    presented: Signature,
}

impl SigV2Authorization {
    /// The presented access key id. A public identifier, not key material.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The presented signature, for [`verify_presented`] and nothing else.
    #[must_use]
    pub fn presented(&self) -> &Signature {
        &self.presented
    }
}

/// Parses `Authorization: AWS <AccessKeyId>:<Signature>`, exactly.
///
/// The grammar is deliberately rigid: literal `AWS`, exactly one space, a non-empty access key id
/// containing no control characters and no space, exactly one colon, and a signature that is
/// canonical standard base64 of exactly 20 bytes. Every relaxation of this grammar is an ambiguity
/// surface — two spellings that name one credential — and an attacker chooses the spelling.
///
/// Note what is *not* here: no lowercase `aws` prefix, no surrounding whitespace, no tolerance for
/// a second colon. A header this function rejects is still an AWS credential marker as far as
/// [`crate::detect_credentials`] is concerned, so the request is refused rather than downgraded to
/// anonymous.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] for every deviation, with no detail about which
/// one: "which field was wrong" is a hint this crate does not hand out.
///
/// # Examples
///
/// ```
/// # use rustfs_gateway_sig::sig_v2::parse_authorization;
/// let parsed = parse_authorization("AWS AKIAIOSFODNN7EXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
///     .expect("well formed");
/// assert_eq!(parsed.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
/// assert!(parse_authorization("AWS  AKIAIOSFODNN7EXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
/// ```
pub fn parse_authorization(raw: &str) -> Result<SigV2Authorization, AuthError> {
    let rest = raw
        .strip_prefix(ALGORITHM_SIGV2_PREFIX)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(AuthError::AuthorizationHeaderMalformed)?;
    if rest.starts_with(' ') {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    let (access_key_id, encoded) = rest.split_once(':').ok_or(AuthError::AuthorizationHeaderMalformed)?;
    if access_key_id.is_empty() || encoded.is_empty() || encoded.contains(':') {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    // The same rule SigV4's `CredentialScope::parse` applies: non-empty, at most 128 bytes,
    // ASCII-graphic only. SigV2 used to check only for control characters and whitespace, which
    // let a multi-kilobyte or non-ASCII access key id reach the credential store and the audit
    // record that names it — the access key id is the one authentication value that legitimately
    // appears in a log line, so its character set is a rule and not a formality.
    let access_key_id = Identity::new(access_key_id).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    let bytes = decode_base64_exact::<20>(encoded).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    Ok(SigV2Authorization {
        access_key_id: access_key_id.access_key_id().to_owned(),
        presented: Signature::HmacSha1(CtBytes::from_array(bytes)),
    })
}

/// Reads the credential a SigV2 presigned URL carries, with the same strictness as the header.
///
/// The presigned form splits what the header packs into one value: `AWSAccessKeyId` and
/// `Signature` are separate query parameters. The rules do not relax because of that — the access
/// key id goes through [`Identity::new`], the same character-set and length rule SigV4's credential
/// scope applies, and the signature is canonical standard base64 of exactly twenty bytes.
///
/// The parameters are read after [`crate::enforce_no_duplicate_sig_params`] has refused a repeated
/// spelling of either, so "which occurrence was this" is not a question that can be asked here.
///
/// # Errors
///
/// [`AuthError::AuthorizationQueryParametersError`] for every deviation. It is the query-shaped
/// sibling of the header's [`AuthError::AuthorizationHeaderMalformed`], and like it says nothing
/// about which field was wrong.
pub fn parse_presigned_credential(access_key_id: &str, signature: &str) -> Result<SigV2Authorization, AuthError> {
    let access_key_id = Identity::new(access_key_id).map_err(|_| AuthError::AuthorizationQueryParametersError)?;
    let bytes = decode_base64_exact::<20>(signature).map_err(|_| AuthError::AuthorizationQueryParametersError)?;
    Ok(SigV2Authorization {
        access_key_id: access_key_id.access_key_id().to_owned(),
        presented: Signature::HmacSha1(CtBytes::from_array(bytes)),
    })
}

/// The one place a SigV2 signature is compared.
///
/// It is a thin wrapper over [`Signature::ct_verify`] on purpose: the wrapper exists so that no
/// caller in the SigV2 path ever has a reason to reach for anything else, and so that
/// `scripts/check_ct_eq.sh` has a single name to point at. A mismatched *width* — a 32-byte SigV4
/// signature offered against a 20-byte expectation — becomes the same
/// [`AuthError::SignatureDoesNotMatch`] as a wrong value, because which width the server expected
/// is not a fact a client needs.
///
/// # Errors
///
/// [`AuthError::SignatureDoesNotMatch`] when the comparison fails, for either reason.
pub fn verify_presented(presented: &Signature, expected: &Signature) -> Result<SignatureMatch, AuthError> {
    presented.ct_verify(expected).map_err(AuthError::from)
}

/// Parses SigV2's presigned `Expires` and checks it against the clock.
///
/// SigV2's `Expires` is an **absolute** Unix second — the instant the URL stops working — whereas
/// SigV4's `X-Amz-Expires` is a window measured from the signing time. The floor's H2 rule
/// (`1..=604800`) therefore does not apply verbatim; the equivalent seven-day ceiling is applied
/// here to `expires - now`.
///
/// Every step is checked: the digits must fit a `u64` (a 40-digit expiry is refused rather than
/// wrapped), and the subtraction is a `checked_sub`, so `u64::MAX` cannot become "never expires".
///
/// # Errors
///
/// * [`AuthError::AuthorizationQueryParametersError`] if the value is not a strict unsigned
///   decimal, does not fit, or is more than [`MAX_PRESIGNED_EXPIRY_SECONDS`] in the future.
/// * [`AuthError::RequestExpired`] if the instant has already passed. The wire answer is
///   `AccessDenied`, which is what S3 says, because confirming that a URL *used to* work is a
///   fact worth withholding from whoever is holding it.
pub fn parse_presigned_expires(raw: &str, now: RequestNow) -> Result<u64, AuthError> {
    let expires = parse_expires_digits(raw)?;
    let now_seconds = u64::try_from(now.unix_seconds()).map_err(|_| AuthError::AuthorizationQueryParametersError)?;
    if !SIGV2_EXPIRES_ABSOLUTE {
        if matches!(expires, 0) || expires > MAX_PRESIGNED_EXPIRY_SECONDS {
            return Err(AuthError::AuthorizationQueryParametersError);
        }
        return now_seconds
            .checked_add(expires)
            .ok_or(AuthError::AuthorizationQueryParametersError);
    }
    if expires <= now_seconds {
        return Err(AuthError::RequestExpired);
    }
    // `expires` is strictly greater, so the subtraction cannot borrow; `checked_sub` is kept
    // anyway because a later edit to the guard above must not silently become a wrap.
    let remaining = expires
        .checked_sub(now_seconds)
        .ok_or(AuthError::AuthorizationQueryParametersError)?;
    if remaining > MAX_PRESIGNED_EXPIRY_SECONDS {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    Ok(expires)
}

/// The syntax half of the `Expires` rule, shared with the string-to-sign builder.
///
/// ASCII digits only, at least one, and it must fit a `u64`. `+1`, `-1`, ` 1`, `1.5`, `0x10` and
/// the full-width zero U+FF10 are all refused: `str::parse` would accept some of them, and a value
/// with two spellings is a value two implementations disagree about.
pub(crate) fn parse_expires_digits(raw: &str) -> Result<u64, AuthError> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    raw.parse::<u64>().map_err(|_| AuthError::AuthorizationQueryParametersError)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative: the policy is closed by default in the dangerous location, and open in it only
    /// when a deployment says so — both directions, so the switch is not stuck on one answer.
    #[test]
    fn the_policy_defaults_to_header_only() {
        assert_eq!(SigV2Policy::default(), SigV2Policy::HeaderOnly);
        assert!(!SigV2Policy::default().allows(SigV2Mode::PresignedUrl));
        assert!(SigV2Policy::HeaderAndPresigned.allows(SigV2Mode::PresignedUrl));
        assert!(!SigV2Policy::Disabled.allows(SigV2Mode::HeaderAuth));
    }

    /// Negative: a `u64::MAX` expiry is refused by the ceiling rather than wrapping into it.
    #[test]
    fn a_ceiling_expiry_never_wraps_into_a_valid_window() {
        let now = RequestNow::from_unix_seconds(1_000);
        assert_eq!(
            parse_presigned_expires(&u64::MAX.to_string(), now).err(),
            Some(AuthError::AuthorizationQueryParametersError)
        );
    }

    /// Negative: a negative clock reading is refused rather than converted.
    #[test]
    fn a_pre_epoch_clock_is_refused() {
        let now = RequestNow::from_unix_seconds(-1);
        assert_eq!(
            parse_presigned_expires("100", now).err(),
            Some(AuthError::AuthorizationQueryParametersError)
        );
    }
}
