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

//! The extension point for other authentication schemes, and the boundary it may not cross.
//!
//! Responsible for: [`SignatureVerifier`] (the extension point, which returns a [`Verdict`] and
//! nothing else), [`CustomAuthRequest`] and [`SealedAws`] (the two post-floor request views, both
//! unconstructible from outside this crate), [`detect_aws_credential_marker`] (the sealing
//! predicate), [`CustomAuthScheme`]/[`CustomSchemeRegistry`] (registration-time prefix rules), the
//! optional replay hook ([`ReplayNonceStore`]), and [`DangerAck`], the witness a deployment must
//! spell out to replace the built-in SigV4 computation.
//! NOT responsible for: running the floor — [`crate::floor`] does that, *outside* every type here
//! — or computing any signature.
//! Upstream: [`crate::floor`]'s [`WireView`], [`crate::scheme`], [`crate::verdict`].
//! Downstream: `rustfs-gateway-core`'s authentication stage, and P6-02's `Authorizer`.
//!
//! # What "sealed" means, concretely
//!
//! A request is **AWS-marked** when it carries an `Authorization` header, or an `X-Amz-Algorithm`,
//! `X-Amz-Signature` or `X-Amz-Credential` query parameter, or the same fields in a POST form, or
//! SigV2's `AWSAccessKeyId`. [`crate::SecurityFloor::admit`] answers such a request with
//! [`crate::Admission::Sealed`], which carries a [`SealedAws`] — and there is no way to turn a
//! [`SealedAws`] into a [`CustomAuthRequest`]. A third-party [`SignatureVerifier`] therefore never
//! sees an AWS-marked request; it is not a rule it is asked to respect, it is a value it is never
//! handed.
//!
//! That is the answer to attack scenario C. "Replace the verifier for an internal deployment" stays
//! available for schemes of a deployment's own; "replace SigV4 with something weaker" cannot be
//! written, because the SigV4 input type is not reachable from the extension point.
//!
//! # Why the trait returns a `Verdict` and not a principal
//!
//! ```compile_fail,E0053
//! use rustfs_gateway_sig::{CustomAuthRequest, Identity, SignatureVerifier};
//! struct MyVerifier;
//! impl SignatureVerifier for MyVerifier {
//!     // A return type that can say "authenticated" without carrying a proof does not compile.
//!     fn verify(&self, _request: &CustomAuthRequest<'_>) -> Identity {
//!         Identity::new("AKIAIOSFODNN7EXAMPLE").expect("valid")
//!     }
//! }
//! ```
//!
//! [`Verdict::Authenticated`] needs a [`crate::SignatureMatch`], which only
//! [`crate::Signature::ct_verify`] hands out, and [`Verdict::Anonymous`] needs an
//! [`crate::AnonymousAck`], which only a request that presented nothing can produce. So the widest
//! thing a third-party verifier can return without doing real work is a rejection.
//!
//! # Presigned URLs are replayable within their window
//!
//! This is inherent to the scheme, not a defect in this implementation: a presigned URL *is* a
//! bearer credential, and anybody holding the bytes can use it until it expires. The optional
//! [`ReplayNonceStore`] hook exists for deployments that need single use; there is no
//! implementation in this crate, and enabling one is a deliberate trade (a shared store on the
//! authentication path). Treat "the same presigned URL worked twice" as documented behaviour.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::clock::{ClockChecked, PresignExpiry, RequestNow};
use crate::floor::WireView;
use crate::parse::{X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL};
use crate::query::X_AMZ_SIGNATURE;
use crate::scheme::{ALGORITHM_SIGV2_PREFIX, SigFamily, SigLocation, SigService};
use crate::verdict::{CredentialPresence, Verdict};

/// SigV2's presigned access-key parameter, and its POST-form spelling.
pub const AWS_ACCESS_KEY_ID_PARAM: &str = "AWSAccessKeyId";
/// SigV2's presigned signature parameter.
pub const SIGV2_SIGNATURE_PARAM: &str = "Signature";
/// The `Authorization` header name, lowercased.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The evidence that a request wants to be authenticated as an AWS request.
///
/// Detection is deliberately generous: an `Authorization` header this crate cannot parse is still
/// an AWS marker. The alternative — "unrecognised, so let the custom verifier look at it" — is a
/// downgrade oracle, because an attacker chooses the spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AwsCredentialMarker {
    family: SigFamily,
    location: SigLocation,
}

impl AwsCredentialMarker {
    /// Which algorithm family the marker claims.
    #[must_use]
    pub const fn family(&self) -> SigFamily {
        self.family
    }

    /// Where the marker was found.
    #[must_use]
    pub const fn location(&self) -> SigLocation {
        self.location
    }
}

/// The sealing predicate: does this request claim to be an AWS-signed one?
///
/// `Some` means only the built-in SigV4 path may handle it. `None` means no AWS surface was
/// touched, and a registered [`SignatureVerifier`] may be consulted — after the floor has run.
#[must_use]
pub fn detect_aws_credential_marker(view: &WireView<'_>) -> Option<AwsCredentialMarker> {
    if let Some(value) = view.headers().get(AUTHORIZATION_HEADER) {
        let family = if value.as_bytes().starts_with(b"AWS4-") {
            SigFamily::V4
        } else if value.as_bytes().starts_with(ALGORITHM_SIGV2_PREFIX.as_bytes())
            && value.as_bytes().get(ALGORITHM_SIGV2_PREFIX.len()) == Some(&b' ')
        {
            SigFamily::V2
        } else {
            // Unrecognised, and still AWS-marked: an `Authorization` header is never routed to a
            // custom scheme, because a custom scheme must use its own header prefix.
            SigFamily::V4
        };
        return Some(AwsCredentialMarker {
            family,
            location: SigLocation::Header,
        });
    }

    for name in [X_AMZ_ALGORITHM, X_AMZ_SIGNATURE, X_AMZ_CREDENTIAL] {
        if view.query_contains(name) {
            return Some(AwsCredentialMarker {
                family: SigFamily::V4,
                location: SigLocation::Query,
            });
        }
    }
    if view.query_contains(AWS_ACCESS_KEY_ID_PARAM) || view.query_contains(SIGV2_SIGNATURE_PARAM) {
        return Some(AwsCredentialMarker {
            family: SigFamily::V2,
            location: SigLocation::Query,
        });
    }

    for name in ["x-amz-algorithm", "x-amz-signature", "x-amz-credential"] {
        if view.form_contains(name) {
            return Some(AwsCredentialMarker {
                family: SigFamily::V4,
                location: SigLocation::FormField,
            });
        }
    }
    if view.form_contains(AWS_ACCESS_KEY_ID_PARAM) || view.form_contains("signature") {
        return Some(AwsCredentialMarker {
            family: SigFamily::V2,
            location: SigLocation::FormField,
        });
    }
    None
}

/// Why a custom scheme could not be registered.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemeRegistrationError {
    /// The prefix is empty.
    Empty,
    /// The prefix names an AWS surface (`x-amz-`, `authorization`).
    ///
    /// This is the registration-time half of the sealed boundary: a scheme that could claim
    /// `x-amz-` headers could claim the credential surface itself.
    ReservedPrefix,
    /// The prefix is not a lowercase HTTP token ending in `-`.
    ///
    /// The trailing `-` is required so that prefix matching is unambiguous and one scheme's
    /// namespace cannot start inside another's word.
    MalformedPrefix,
    /// Another registered scheme already owns this prefix, or one that overlaps it.
    Conflict,
}

impl fmt::Display for SchemeRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Empty => "a custom authentication scheme needs a header prefix",
            Self::ReservedPrefix => "a custom authentication scheme may not claim an AWS header prefix",
            Self::MalformedPrefix => "a header prefix must be a lowercase HTTP token ending in '-'",
            Self::Conflict => "another registered scheme already owns an overlapping header prefix",
        };
        f.write_str(text)
    }
}

impl core::error::Error for SchemeRegistrationError {}

/// A third-party authentication scheme, identified by the header prefix it owns.
///
/// The prefix is `&'static str` on purpose: a scheme is registered while the server is being built,
/// from a literal in the deployment's own source. There is no runtime string to smuggle one in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustomAuthScheme {
    header_prefix: &'static str,
}

impl CustomAuthScheme {
    /// Claims a header prefix for a custom scheme.
    ///
    /// # Errors
    ///
    /// * [`SchemeRegistrationError::Empty`] for an empty prefix.
    /// * [`SchemeRegistrationError::ReservedPrefix`] for anything under `x-amz-` or
    ///   `authorization`, compared case-insensitively.
    /// * [`SchemeRegistrationError::MalformedPrefix`] unless the prefix is lowercase
    ///   `[a-z0-9-]` and ends in `-`.
    pub fn new(header_prefix: &'static str) -> Result<Self, SchemeRegistrationError> {
        if header_prefix.is_empty() {
            return Err(SchemeRegistrationError::Empty);
        }
        let lowered = header_prefix.to_ascii_lowercase();
        if lowered.starts_with("x-amz-") || lowered.starts_with(AUTHORIZATION_HEADER) {
            return Err(SchemeRegistrationError::ReservedPrefix);
        }
        let shaped = header_prefix.ends_with('-')
            && header_prefix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !shaped {
            return Err(SchemeRegistrationError::MalformedPrefix);
        }
        Ok(Self { header_prefix })
    }

    /// The header prefix this scheme owns.
    #[must_use]
    pub const fn header_prefix(&self) -> &'static str {
        self.header_prefix
    }

    /// Whether a request carries a header under this scheme's prefix.
    #[must_use]
    pub fn matches(&self, view: &WireView<'_>) -> bool {
        view.headers()
            .keys()
            .any(|name| name.as_str().starts_with(self.header_prefix))
    }
}

/// The registered custom schemes.
///
/// Explicit and greppable: registration is a method call in the deployment's own build code, never
/// a link-time side effect. `inventory` and `linkme` are forbidden repository-wide (ADR-0003) for
/// exactly the reason that matters here — an authentication scheme that registers itself by being
/// linked in is one an audit cannot see.
#[derive(Clone, Debug, Default)]
pub struct CustomSchemeRegistry {
    schemes: Vec<CustomAuthScheme>,
}

impl CustomSchemeRegistry {
    /// An empty registry: no custom scheme, which is the default posture.
    #[must_use]
    pub const fn new() -> Self {
        Self { schemes: Vec::new() }
    }

    /// Registers a scheme.
    ///
    /// # Errors
    ///
    /// [`SchemeRegistrationError::Conflict`] when the prefix overlaps one already registered in
    /// either direction. Overlap is a conflict rather than a precedence question: two schemes that
    /// could both claim one header would make "which verifier saw this request" depend on
    /// registration order.
    pub fn register(&mut self, scheme: CustomAuthScheme) -> Result<(), SchemeRegistrationError> {
        let overlaps = self.schemes.iter().any(|existing| {
            existing.header_prefix().starts_with(scheme.header_prefix())
                || scheme.header_prefix().starts_with(existing.header_prefix())
        });
        if overlaps {
            return Err(SchemeRegistrationError::Conflict);
        }
        self.schemes.push(scheme);
        Ok(())
    }

    /// The registered schemes, for the startup security-posture report.
    #[must_use]
    pub fn schemes(&self) -> &[CustomAuthScheme] {
        &self.schemes
    }

    /// The scheme whose prefix this request carries, if any.
    #[must_use]
    pub fn matching(&self, view: &WireView<'_>) -> Option<CustomAuthScheme> {
        self.schemes.iter().copied().find(|scheme| scheme.matches(view))
    }
}

/// A request the floor has cleared for a custom [`SignatureVerifier`].
///
/// It exists only as the output of [`crate::SecurityFloor::admit`], so possessing one is proof
/// that the floor already ran and that the request carried no AWS credential marker.
///
/// ```compile_fail,E0451
/// use rustfs_gateway_sig::{CredentialPresence, CustomAuthRequest};
/// // The fields are private, and there is no constructor: a verifier cannot manufacture the
/// // request it is asked about.
/// let _ = CustomAuthRequest { presence: CredentialPresence::NONE };
/// ```
#[derive(Clone, Copy)]
pub struct CustomAuthRequest<'a> {
    view: WireView<'a>,
    scheme: CustomAuthScheme,
    presence: CredentialPresence,
    now: RequestNow,
}

impl<'a> CustomAuthRequest<'a> {
    pub(crate) const fn new(view: WireView<'a>, scheme: CustomAuthScheme, presence: CredentialPresence, now: RequestNow) -> Self {
        Self {
            view,
            scheme,
            presence,
            now,
        }
    }

    /// The request as it arrived.
    #[must_use]
    pub const fn view(&self) -> WireView<'a> {
        self.view
    }

    /// The scheme whose prefix this request carried.
    #[must_use]
    pub const fn scheme(&self) -> CustomAuthScheme {
        self.scheme
    }

    /// Which AWS authentication surfaces were touched — none, or this request would not be here.
    #[must_use]
    pub const fn presence(&self) -> CredentialPresence {
        self.presence
    }

    /// The request's clock snapshot.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }
}

impl fmt::Debug for CustomAuthRequest<'_> {
    /// Hand-written, and header-free. A derived `Debug` would print every header value, one of
    /// which is the credential the custom scheme is about to verify.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomAuthRequest")
            .field("scheme", &self.scheme.header_prefix())
            .field("presence", &self.presence)
            .finish_non_exhaustive()
    }
}

/// An AWS-marked request the floor has cleared for the built-in SigV4 path.
///
/// Holding one means H1, H2, H3 and H6 have already run for this request: the clock receipt is
/// present because the skew check produced it, the expiry is present for every presigned request
/// because the expiry check produced it, and the operation's allow-list has already accepted the
/// scheme. What is left for the verifier is the scope cross-check ([`crate::enforce_scope`], which
/// needs the receipt this type carries) and the signature comparison.
///
/// There is no public constructor, and no route from here to a [`CustomAuthRequest`].
pub struct SealedAws<'a> {
    view: WireView<'a>,
    marker: AwsCredentialMarker,
    clock: ClockChecked,
    presence: CredentialPresence,
    expiry: Option<PresignExpiry>,
    expected_service: SigService,
}

impl<'a> SealedAws<'a> {
    pub(crate) const fn new(
        view: WireView<'a>,
        marker: AwsCredentialMarker,
        clock: ClockChecked,
        presence: CredentialPresence,
        expiry: Option<PresignExpiry>,
        expected_service: SigService,
    ) -> Self {
        Self {
            view,
            marker,
            clock,
            presence,
            expiry,
            expected_service,
        }
    }

    /// The request as it arrived.
    #[must_use]
    pub const fn view(&self) -> WireView<'a> {
        self.view
    }

    /// Which AWS surface carried the credential.
    #[must_use]
    pub const fn marker(&self) -> AwsCredentialMarker {
        self.marker
    }

    /// The receipt from the skew check. [`crate::enforce_scope`] takes it, so a scope cannot be
    /// cross-checked against a timestamp nobody validated.
    #[must_use]
    pub const fn clock(&self) -> ClockChecked {
        self.clock
    }

    /// Which authentication surfaces the request touched.
    #[must_use]
    pub const fn presence(&self) -> CredentialPresence {
        self.presence
    }

    /// The presigned lifetime, for a presigned request. `None` for the header and POST forms.
    #[must_use]
    pub const fn expiry(&self) -> Option<PresignExpiry> {
        self.expiry
    }

    /// The service the routed operation belongs to — the value the credential scope must name.
    #[must_use]
    pub const fn expected_service(&self) -> SigService {
        self.expected_service
    }

    /// The replay-hook key for a presigned request: `SHA-256(signed timestamp ‖ signature)`.
    ///
    /// `None` for anything that is not presigned, and for a presigned request whose signature
    /// parameter is unreadable — such a request is about to be rejected anyway.
    ///
    /// A digest rather than the signature itself, so that a store operated outside this process
    /// never receives signature bytes.
    #[must_use]
    pub fn replay_fingerprint(&self) -> Option<ReplayFingerprint> {
        if !self.marker.location().is_presigned() {
            return None;
        }
        let presented = self.view.query().decoded_value(X_AMZ_SIGNATURE).ok()??;
        let mut hasher = Sha256::new();
        hasher.update(self.clock.signed_at().as_str().as_bytes());
        hasher.update(presented.as_bytes());
        Some(ReplayFingerprint(hasher.finalize().into()))
    }
}

impl fmt::Debug for SealedAws<'_> {
    /// Hand-written and header-free, for the same reason as [`CustomAuthRequest`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedAws")
            .field("marker", &self.marker)
            .field("signed_at", &self.clock.signed_at())
            .field("expiry", &self.expiry)
            .field("expected_service", &self.expected_service)
            .finish_non_exhaustive()
    }
}

/// The key a [`ReplayNonceStore`] records. Opaque, and not the signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayFingerprint([u8; 32]);

impl ReplayFingerprint {
    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReplayFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayFingerprint(<opaque>)")
    }
}

/// What a replay store knows about one fingerprint.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplayDecision {
    /// Never seen; the request may proceed.
    FirstUse,
    /// Seen before; the request is a replay and must be rejected.
    Replayed,
    /// The store could not answer. Fail closed: reject, and do not treat it as a first use.
    Unavailable,
}

/// The optional single-use hook for presigned URLs (H7).
///
/// There is no implementation in this crate and none is wired in by default, because presigned
/// replay within the validity window is the scheme's own semantics rather than a defect. A
/// deployment that needs single use provides a store; it is buying a shared, strongly consistent
/// write on the authentication path, which is a real cost and a real availability risk.
pub trait ReplayNonceStore {
    /// Records a fingerprint and reports whether it had been seen.
    fn record_first_use(&self, fingerprint: ReplayFingerprint) -> ReplayDecision;
}

/// The extension point for authentication schemes that are not AWS's.
///
/// One method, one return type, and that return type is a [`Verdict`] — a value whose widening
/// variants both require a receipt this trait cannot manufacture.
///
/// The framework runs the whole security floor **outside** this call, and an AWS-marked request is
/// never passed to it. So an implementation can add a scheme; it cannot remove a rule.
pub trait SignatureVerifier: Send + Sync + 'static {
    /// Decides one request that carried this verifier's scheme prefix and no AWS credential.
    fn verify(&self, request: &CustomAuthRequest<'_>) -> Verdict;
}

/// The witness required to replace the built-in SigV4 computation.
///
/// Not `Default`, no public field, and exactly one constructor whose name is the sentence a
/// reviewer needs to see. That is the intent, not a style choice: the danger has to be spelled out
/// at the call site, in the deployment's own source, where `grep` finds it.
///
/// **Replacing the verifier does not remove the floor.** H1..H7 run in
/// [`crate::SecurityFloor::admit`], which produces the [`SealedAws`] a replacement is handed. A
/// replacement that authenticates everything still never sees an expired presigned URL, a skewed
/// timestamp, a duplicated signature parameter or a presigned request aimed at a privileged
/// operation, because those requests were rejected before it was called.
///
/// ```compile_fail,E0599
/// use rustfs_gateway_sig::DangerAck;
/// let _ = DangerAck::default(); // no Default: does not compile
/// ```
///
/// ```compile_fail,E0423
/// use rustfs_gateway_sig::DangerAck;
/// let _ = DangerAck(()); // private field: does not compile outside the crate
/// ```
#[cfg(feature = "dangerous-replace-signature-verifier")]
#[derive(Clone, Copy)]
pub struct DangerAck(());

#[cfg(feature = "dangerous-replace-signature-verifier")]
impl DangerAck {
    /// Produces the witness. The name is the documentation.
    #[must_use]
    pub const fn i_understand_this_disables_aws_sigv4() -> Self {
        Self(())
    }
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
impl fmt::Debug for DangerAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DangerAck(i_understand_this_disables_aws_sigv4)")
    }
}

/// The replacement point for the built-in SigV4 computation, behind
/// `dangerous-replace-signature-verifier`.
///
/// It takes a [`SealedAws`], so a replacement receives a request the floor has already cleared and
/// cannot reach one it has not. It returns a [`Verdict`], so it cannot widen access without a
/// receipt either. The feature turns off the built-in *computation*; it does not turn off H1..H7.
#[cfg(feature = "dangerous-replace-signature-verifier")]
pub trait AwsSignatureVerifier: Send + Sync + 'static {
    /// Decides one AWS-marked request that has already cleared the floor.
    fn verify_sealed(&self, request: &SealedAws<'_>) -> Verdict;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative — an `Authorization` header nobody recognises is still AWS-marked, so an
    /// unrecognised spelling cannot be used to reach a custom verifier.
    #[test]
    fn an_unrecognised_authorization_header_is_still_aws_marked() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static("authorization"),
            http::HeaderValue::from_static("Bearer something"),
        );
        let view = WireView::new(&headers, crate::query::RawQuery::new(""));
        let marker = detect_aws_credential_marker(&view).expect("marked");
        assert_eq!(marker.location(), SigLocation::Header);
    }

    /// Negative — a prefix that is a prefix of a registered one conflicts in both directions.
    #[test]
    fn overlapping_prefixes_conflict_in_both_directions() {
        let mut registry = CustomSchemeRegistry::new();
        registry
            .register(CustomAuthScheme::new("x-vendor-auth-").expect("legal"))
            .expect("first");
        assert_eq!(
            registry.register(CustomAuthScheme::new("x-vendor-").expect("legal")).err(),
            Some(SchemeRegistrationError::Conflict)
        );
        assert_eq!(
            registry
                .register(CustomAuthScheme::new("x-vendor-auth-v2-").expect("legal"))
                .err(),
            Some(SchemeRegistrationError::Conflict)
        );
        assert!(
            registry
                .register(CustomAuthScheme::new("x-other-auth-").expect("legal"))
                .is_ok()
        );
        assert_eq!(registry.schemes().len(), 2);
    }

    /// Negative — neither post-floor request type prints a header value.
    #[test]
    fn neither_request_view_prints_a_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static("x-vendor-auth-token"),
            http::HeaderValue::from_static("vendor-bearer-value"),
        );
        let view = WireView::new(&headers, crate::query::RawQuery::new(""));
        let request = CustomAuthRequest::new(
            view,
            CustomAuthScheme::new("x-vendor-auth-").expect("legal"),
            CredentialPresence::NONE,
            RequestNow::from_unix_seconds(0),
        );
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("vendor-bearer-value"));
    }
}
