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

//! The security floor: the rules that run outside every verifier, replaceable or not.
//!
//! Responsible for: [`WireView`] (the authentication surfaces of one request), [`SecurityFloor`]
//! and its [`SecurityFloor::admit`] — the one entry point that runs the seven unconditional rules
//! in order — and the three of those rules whose implementation lives here: the presented-credential
//! rule, the duplicate-parameter rule, and the strict `X-Amz-Expires` reader.
//! The allow-list lives in [`crate::operation`] and the scope cross-check in [`crate::scope`];
//! both are still unconditional, and `admit` is what calls them.
//! NOT responsible for: computing or comparing a signature (that is [`crate::derive`] and
//! [`crate::signature`]), the presigned body rules and POST-policy field enforcement (P2-05),
//! SigV2's string-to-sign (P2-06), the operation registry (P4-04 — this module defines what
//! `service`, `privileged` and `allowed_schemes` *mean* and provides the decision functions), or
//! rate limiting (P6-08's `Governor`).
//! Upstream: [`crate::clock`], [`crate::parse`], [`crate::query`], [`crate::verdict`].
//! Downstream: [`crate::verifier`]'s two post-floor request types, and `rustfs-gateway-core`'s
//! authentication stage, which calls [`SecurityFloor::admit`] before it calls anything else.
//!
//! # Why these rules are here and not in the verifier
//!
//! The v1 shape put them inside the SigV4 verifier, and made the verifier replaceable "for
//! deployments that do not want signatures". Those two decisions together mean one `impl` swap
//! silently removes the skew window, the seven-day presigned ceiling, the admin-surface fence, the
//! scope cross-check and the duplicate-parameter rules — none of which the replacement's author was
//! thinking about. That is MinIO CVE-2025-31489 turned into a supported configuration.
//!
//! So the rules live outside. [`SecurityFloor::admit`] produces a [`crate::SealedAws`] or a
//! [`crate::CustomAuthRequest`], both unconstructible elsewhere, and both only obtainable *after*
//! the rules have run. An extension point receives the result of the floor; it is never in a
//! position to skip it.
//!
//! # The order the rules run in, and why it is that order
//!
//! 1. **Duplicate signature parameters.** First, because every later rule reads one of those
//!    parameters, and "which of the two did you read" must not be a question anybody can ask.
//! 2. **Credential presence**, including the two-surfaces-at-once rejection. Before anything is
//!    parsed, so that a parse failure can never be the thing that decides anonymity.
//! 3. **The AWS credential marker.** Decides sealed-versus-custom, and nothing else.
//! 4. **The scheme allow-list**, so a presigned request aimed at an admin operation is refused
//!    before its timestamp is even read.
//! 5. **Clock skew**, on whichever of the three paths carried the timestamp.
//! 6. **Presigned expiry**, which needs the receipt step 5 produced.
//!
//! The scope cross-check ([`enforce_scope`]) is step 7 and runs inside the SigV4 verifier, because
//! it needs the parsed credential. It is still unconditional: it is the only way to obtain the
//! [`VerifiedScope`] that [`crate::signing_key`] takes.

use core::fmt;

use http::HeaderMap;

use crate::clock::{ClockChecked, PresignExpiry, RequestNow, SkewWindow, enforce_clock_skew, enforce_expiry};
use crate::mode::{
    STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, STREAMING_UNSIGNED_TRAILER,
};
use crate::operation::{OperationFloor, SchemeSlot, SigV2Presigned};
use crate::parse::{AmzDate, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNED_HEADERS};
use crate::query::{RawQuery, X_AMZ_SIGNATURE, percent_decode};
use crate::scheme::{SigFamily, SigLocation};
use crate::sig_v2::{SIGV2_EXPIRES_PARAM, SealedSigV2, SigV2Mode, SigV2Policy};
use crate::timing::FailureFloor;
use crate::verdict::{AnonymousAck, AuthError, CredentialPresence, Verdict};
use crate::verifier::{
    AUTHORIZATION_HEADER, AWS_ACCESS_KEY_ID_PARAM, AwsCredentialMarker, CustomAuthRequest, CustomSchemeRegistry,
    SIGV2_SIGNATURE_PARAM, SealedAws, detect_aws_credential_marker,
};

/// The presigned expiry parameter.
pub const X_AMZ_EXPIRES: &str = "X-Amz-Expires";
/// The session-token parameter, in its query spelling.
pub const X_AMZ_SECURITY_TOKEN: &str = "X-Amz-Security-Token";
/// The session-token header, lowercased.
pub const X_AMZ_SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";
/// The timestamp header, lowercased.
pub const X_AMZ_DATE_HEADER: &str = "x-amz-date";
/// The payload declaration header, lowercased.
const X_AMZ_CONTENT_SHA256_HEADER: &str = "x-amz-content-sha256";

/// Every query parameter that carries part of a signature, and must therefore appear at most once.
///
/// A server that reads the first occurrence and a proxy that reads the last disagree about what
/// was signed, which is a parameter-smuggling bypass (s3s#176, open with a security label).
const SIGNED_QUERY_PARAMS: [&str; 10] = [
    X_AMZ_ALGORITHM,
    X_AMZ_CREDENTIAL,
    X_AMZ_DATE,
    X_AMZ_EXPIRES,
    X_AMZ_SIGNED_HEADERS,
    X_AMZ_SIGNATURE,
    X_AMZ_SECURITY_TOKEN,
    AWS_ACCESS_KEY_ID_PARAM,
    SIGV2_SIGNATURE_PARAM,
    // SigV2's own expiry parameter. It is not `X-Amz-Expires` under another name: it is an
    // absolute instant, it is inside SigV2's string-to-sign, and until the SigV2 verifier was
    // wired nothing read it, so nothing noticed it was missing from this list.
    SIGV2_EXPIRES_PARAM,
];

/// Every header that carries part of a signature, and must therefore appear at most once.
const SIGNED_HEADERS: [&str; 4] = [
    AUTHORIZATION_HEADER,
    X_AMZ_DATE_HEADER,
    "x-amz-content-sha256",
    X_AMZ_SECURITY_TOKEN_HEADER,
];

/// Every POST form field that carries part of a signature.
const SIGNED_FORM_FIELDS: [&str; 8] = [
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-signature",
    "x-amz-security-token",
    "policy",
    "signature",
    AWS_ACCESS_KEY_ID_PARAM,
];

/// The authentication surfaces of one request, borrowed rather than copied.
///
/// Three surfaces because SigV4 has three: headers, the query string, and a browser POST form.
/// The form is `Option` because most requests have none, and because the wire layer must have
/// parsed the multipart body before one exists.
///
/// There is no `Debug` that prints a header value: a header map here holds `Authorization` and may
/// hold an SSE-C key.
#[derive(Clone, Copy)]
pub struct WireView<'a> {
    headers: &'a HeaderMap,
    query: RawQuery<'a>,
    form_fields: Option<&'a [(&'a str, &'a str)]>,
}

impl<'a> WireView<'a> {
    /// Wraps the headers and the query of one request.
    #[must_use]
    pub const fn new(headers: &'a HeaderMap, query: RawQuery<'a>) -> Self {
        Self {
            headers,
            query,
            form_fields: None,
        }
    }

    /// Adds the fields of a browser POST form.
    #[must_use]
    pub const fn with_form_fields(mut self, fields: &'a [(&'a str, &'a str)]) -> Self {
        self.form_fields = Some(fields);
        self
    }

    /// The request headers.
    #[must_use]
    pub const fn headers(&self) -> &'a HeaderMap {
        self.headers
    }

    /// The query string, exactly as it arrived.
    #[must_use]
    pub const fn query(&self) -> RawQuery<'a> {
        self.query
    }

    /// The POST form fields, when the request carried a form.
    #[must_use]
    pub const fn form_fields(&self) -> Option<&'a [(&'a str, &'a str)]> {
        self.form_fields
    }

    /// How often a query parameter of this exact name appears.
    ///
    /// The comparison is byte-exact on the decoded name, matching
    /// [`RawQuery::decoded_value`] and the canonical query builder: a differently-cased spelling is
    /// a different parameter, because it signs differently.
    #[must_use]
    pub fn count_query_param(&self, name: &str) -> usize {
        let raw = self.query.as_str();
        if raw.is_empty() {
            return 0;
        }
        raw.split('&')
            .filter(|component| !component.is_empty())
            .filter(|component| {
                let raw_key = component.split_once('=').map_or(*component, |(key, _)| key);
                // A malformed escape cannot decode; compare the wire bytes instead of skipping the
                // component, so a broken spelling cannot hide a second occurrence.
                percent_decode(raw_key).map_or_else(|_| raw_key.as_bytes() == name.as_bytes(), |key| key == name.as_bytes())
            })
            .count()
    }

    /// Whether a query parameter of this exact name is present.
    #[must_use]
    pub fn query_contains(&self, name: &str) -> bool {
        self.count_query_param(name) > 0
    }

    /// How often a POST form field of this exact name appears.
    #[must_use]
    pub fn count_form_field(&self, name: &str) -> usize {
        self.form_fields
            .map_or(0, |fields| fields.iter().filter(|(field, _)| *field == name).count())
    }

    /// Whether a POST form field of this exact name is present.
    #[must_use]
    pub fn form_contains(&self, name: &str) -> bool {
        self.count_form_field(name) > 0
    }

    /// The value of a POST form field, when it appears exactly once.
    #[must_use]
    pub fn form_value(&self, name: &str) -> Option<&'a str> {
        let fields = self.form_fields?;
        let mut found = None;
        for (field, value) in fields {
            if *field == name {
                if found.is_some() {
                    return None;
                }
                found = Some(*value);
            }
        }
        found
    }
}

impl fmt::Debug for WireView<'_> {
    /// Shapes only. A derived `Debug` would render every header value into whatever log line
    /// formatted the request.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireView")
            .field("headers", &self.headers.len())
            .field("query_bytes", &self.query.as_str().len())
            .field("form_fields", &self.form_fields.map(<[(&str, &str)]>::len))
            .finish()
    }
}

/// H4, the detection half — which authentication surfaces this request touched.
///
/// The answer feeds [`CredentialPresence::into_evidence`], which is the only producer of the
/// [`AnonymousAck`] an anonymous verdict needs. So a request that touched any surface cannot be
/// answered anonymously: not by this crate, and not by an extension point either.
#[must_use]
pub fn detect_credentials(view: &WireView<'_>) -> CredentialPresence {
    let mut presence = CredentialPresence::NONE;
    if view.headers().contains_key(AUTHORIZATION_HEADER) {
        presence = presence.with_authorization_header();
    }
    if view.query_contains(X_AMZ_SIGNATURE) || view.query_contains(SIGV2_SIGNATURE_PARAM) {
        presence = presence.with_query_signature();
    }
    if view.form_contains("x-amz-signature") || view.form_contains("signature") {
        presence = presence.with_post_policy_signature();
    }
    if view.headers().contains_key(X_AMZ_SECURITY_TOKEN_HEADER)
        || view.query_contains(X_AMZ_SECURITY_TOKEN)
        || view.form_contains("x-amz-security-token")
    {
        presence = presence.with_security_token();
    }
    presence
}

/// H6 — no signature-bearing parameter, header or form field may appear twice.
///
/// # Errors
///
/// * [`AuthError::AuthorizationQueryParametersError`] for a repeated query parameter.
/// * [`AuthError::AuthorizationHeaderMalformed`] for a repeated header or form field.
///
/// Resolving the ambiguity — first wins, last wins — is not an option: whichever this server picks,
/// some proxy in front of it picks the other, and the difference is a request signed as one thing
/// and executed as another.
pub fn enforce_no_duplicate_sig_params(view: &WireView<'_>) -> Result<(), AuthError> {
    for name in SIGNED_QUERY_PARAMS {
        if view.count_query_param(name) > 1 {
            return Err(AuthError::AuthorizationQueryParametersError);
        }
    }
    for name in SIGNED_HEADERS {
        if view.headers().get_all(name).iter().count() > 1 {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
    }
    for name in SIGNED_FORM_FIELDS {
        if view.count_form_field(name) > 1 {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
    }
    Ok(())
}

/// H2, the parsing half — the strict `X-Amz-Expires` reader.
///
/// Strict means: present exactly once, a non-empty run of ASCII digits and nothing else. No sign,
/// no decimal point, no exponent, no whitespace, no unit suffix, no non-ASCII digit. Everything
/// else is a rejection, because every lenient reader turns some spelling of "very large" into a
/// presigned URL that outlives its ceiling (rustfs/rustfs#5368).
///
/// The range and overflow rules are [`crate::enforce_expiry`]'s, and this function calls it.
///
/// # Errors
///
/// [`AuthError::AuthorizationQueryParametersError`] for every spelling fault and for a value
/// outside `1..=604800`; [`AuthError::RequestExpired`] when the URL's lifetime has passed.
pub fn enforce_presign_expiry(view: &WireView<'_>, clock: ClockChecked) -> Result<PresignExpiry, AuthError> {
    if view.count_query_param(X_AMZ_EXPIRES) != 1 {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    let raw = view
        .query()
        .decoded_value(X_AMZ_EXPIRES)
        .map_err(|_| AuthError::AuthorizationQueryParametersError)?
        .ok_or(AuthError::AuthorizationQueryParametersError)?;

    let digits = raw.as_bytes();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    let mut seconds: u64 = 0;
    for digit in digits {
        seconds = seconds
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(AuthError::AuthorizationQueryParametersError)?;
    }
    enforce_expiry(clock, seconds)
}

/// Refuses a SigV2 request that declares a framed payload.
///
/// `x-amz-content-sha256` is not part of SigV2 at all; a client that sends one has it signed as an
/// ordinary `x-amz-*` header and nothing else. The token spellings below name `aws-chunked`
/// framing whose chunk signatures are SigV4 values, so a SigV2 request cannot have produced them.
///
/// The alternative is worse than a refusal. The pipeline decodes framing only for a payload mode
/// it was given, and the SigV2 path gives it none — so an ignored declaration means the chunk
/// size lines and chunk signatures are delivered to the operation as object bytes.
///
/// Non-streaming declarations (`UNSIGNED-PAYLOAD`, a hex digest) are left alone: they claim
/// nothing about framing, some middleboxes add them, and refusing them would reject requests that
/// are correctly signed and correctly framed.
///
/// # Errors
///
/// [`AuthError::NotImplemented`] carrying [`crate::error::Unimplemented::StreamingSigV2`], and
/// [`AuthError::AuthorizationHeaderMalformed`] for a declaration that is not even text.
fn refuse_framed_sigv2_payload(view: &WireView<'_>) -> Result<(), AuthError> {
    let Some(raw) = view.headers().get(X_AMZ_CONTENT_SHA256_HEADER) else {
        return Ok(());
    };
    let token = raw.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    if matches!(
        token,
        STREAMING_SIGNED | STREAMING_SIGNED_TRAILER | STREAMING_UNSIGNED_TRAILER | STREAMING_ECDSA | STREAMING_ECDSA_TRAILER
    ) {
        return Err(AuthError::NotImplemented(crate::error::Unimplemented::StreamingSigV2));
    }
    Ok(())
}

/// What [`SecurityFloor::admit`] decided.
///
/// Every variant is a request that has already been through the floor. There is no variant that
/// means "not checked yet", and no way to build one.
#[non_exhaustive]
pub enum Admission<'a> {
    /// AWS-marked. Only the built-in SigV4 path may handle it.
    Sealed(SealedAws<'a>),
    /// AWS-marked as SigV2, and admitted by the [`SigV2Policy`] in force.
    ///
    /// A separate variant rather than a [`SealedAws`] carrying a family tag, because the point is
    /// that the SigV4 verifier is never handed this request: there is no conversion between the
    /// two types, so "SigV2 verified as SigV4" is not a mistake that can be made.
    SealedSigV2(SealedSigV2<'a>),
    /// No AWS credential marker, and a registered custom scheme claims it.
    Custom(CustomAuthRequest<'a>),
    /// Nothing was presented, and the operation is anonymously reachable.
    Anonymous(AnonymousAck),
}

impl fmt::Debug for Admission<'_> {
    /// Hand-written: [`AnonymousAck`] has no `Debug`, on purpose, and the other two render their
    /// shape without their headers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sealed(sealed) => f.debug_tuple("Sealed").field(sealed).finish(),
            Self::SealedSigV2(sealed) => f.debug_tuple("SealedSigV2").field(sealed).finish(),
            Self::Custom(request) => f.debug_tuple("Custom").field(request).finish(),
            Self::Anonymous(_) => f.write_str("Anonymous"),
        }
    }
}

/// The rules that run outside every verifier.
///
/// Configuration can narrow this type and cannot widen it: [`SkewWindow`] is capped at fifteen
/// minutes, the presigned ceiling is a constant, and the two switches that exist
/// ([`SecurityFloor::enable_sigv2_presigned_compatibility`] and the custom-scheme registry) only
/// add scheme surface — they cannot remove a check.
#[derive(Clone, Debug, Default)]
pub struct SecurityFloor {
    skew: SkewWindow,
    sigv2: SigV2Policy,
    failure_floor: FailureFloor,
    custom_schemes: CustomSchemeRegistry,
}

impl SecurityFloor {
    /// The default floor: a fifteen-minute window each way, SigV2 presigned off, no custom scheme.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Narrows the clock-skew window. Widening past [`SkewWindow::MAX`] is not possible.
    #[must_use]
    pub const fn with_skew_window(mut self, skew: SkewWindow) -> Self {
        self.skew = skew;
        self
    }

    /// Registers the custom authentication schemes this deployment added.
    #[must_use]
    pub fn with_custom_schemes(mut self, registry: CustomSchemeRegistry) -> Self {
        self.custom_schemes = registry;
        self
    }

    /// Accepts SigV2 presigned URLs, which is [`SigV2Policy::HeaderAndPresigned`].
    ///
    /// Presigned is the dangerous half of SigV2: a presigned URL is a bearer token that travels in
    /// referrer headers and proxy logs, SigV2 signs almost none of the query string, and MinIO
    /// #5411 was a rewritten SigV2 presigned URL that reached an admin operation. The default is
    /// the security-relevant half, and a deployment reading this method's name learns what it is
    /// turning on.
    #[must_use]
    pub const fn enable_sigv2_presigned_compatibility(self) -> Self {
        self.with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
    }

    /// Sets which SigV2 locations this deployment accepts.
    ///
    /// This is the **single** SigV2 switch. It used to be two — a three-way [`SigV2Policy`] beside
    /// a two-way presigned flag — and two switches that can disagree about whether an
    /// authentication scheme is on is the shape this repository has caught eight times.
    /// [`SecurityFloor::sigv2_presigned`] is now derived from this value rather than stored beside
    /// it, so the two cannot drift.
    #[must_use]
    pub const fn with_sigv2_policy(mut self, policy: SigV2Policy) -> Self {
        self.sigv2 = policy;
        self
    }

    /// The SigV2 policy in force, for the startup security-posture report.
    #[must_use]
    pub const fn sigv2_policy(&self) -> SigV2Policy {
        self.sigv2
    }

    /// The clock-skew window in force.
    #[must_use]
    pub const fn skew_window(&self) -> SkewWindow {
        self.skew
    }

    /// Whether SigV2 presigned URLs are accepted.
    ///
    /// Derived from [`SecurityFloor::sigv2_policy`] and never stored: there is one switch.
    #[must_use]
    pub const fn sigv2_presigned(&self) -> SigV2Presigned {
        if self.sigv2.allows(SigV2Mode::PresignedUrl) {
            SigV2Presigned::Enabled
        } else {
            SigV2Presigned::Disabled
        }
    }

    /// The registered custom schemes, for the startup security-posture report.
    #[must_use]
    pub const fn custom_schemes(&self) -> &CustomSchemeRegistry {
        &self.custom_schemes
    }

    /// The uniform latency floor every rejection owes (T6).
    #[must_use]
    pub const fn failure_floor(&self) -> FailureFloor {
        self.failure_floor
    }

    /// H3 — whether this operation accepts this shape.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccessDenied`] when the operation is privileged and the request is presigned,
    /// when the request is a SigV2 presigned URL and the compatibility switch is off, or when the
    /// shape is simply not on the operation's allow-list. One code for all three: which fence a
    /// request hit is not something an unauthenticated caller needs.
    pub fn enforce_scheme_allowed(
        &self,
        operation: &OperationFloor,
        slot: SchemeSlot,
        family: SigFamily,
    ) -> Result<(), AuthError> {
        if matches!(slot, SchemeSlot::Presigned) {
            if operation.privileged() {
                return Err(AuthError::AccessDenied);
            }
            if matches!(family, SigFamily::V2) && matches!(self.sigv2_presigned(), SigV2Presigned::Disabled) {
                return Err(AuthError::AccessDenied);
            }
        }
        if !operation.allowed_schemes().allows(slot) {
            return Err(AuthError::AccessDenied);
        }
        Ok(())
    }

    /// Runs the floor over one request, in the order the module documentation gives.
    ///
    /// The clock snapshot is a parameter, so every time-dependent rule in one admission reads one
    /// present.
    ///
    /// # Errors
    ///
    /// [`AuthError`], for any of the seven rules. The caller owes
    /// [`SecurityFloor::failure_floor`] on the way out, whichever rule produced it — the latency
    /// ladder from "rejected at parse" to "rejected at signature" is itself an oracle (T6).
    pub fn admit<'a>(&self, view: WireView<'a>, operation: &OperationFloor, now: RequestNow) -> Result<Admission<'a>, AuthError> {
        // 1. H6 — duplicates, before anything reads one of the duplicated values.
        enforce_no_duplicate_sig_params(&view)?;

        // 2. H4 — what was presented, and the two-surfaces rejection.
        let presence = detect_credentials(&view);
        if presence.is_ambiguous() {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }

        // 3. The sealing predicate.
        let Some(marker) = detect_aws_credential_marker(&view) else {
            return self.admit_without_aws_marker(view, operation, presence, now);
        };

        // 4. H3 — the operation's allow-list, before the timestamp is even read.
        let slot = match marker.location() {
            SigLocation::Query => SchemeSlot::Presigned,
            SigLocation::FormField => SchemeSlot::PostPolicy,
            _ => SchemeSlot::Header,
        };
        self.enforce_scheme_allowed(operation, slot, marker.family())?;
        if matches!(marker.family(), SigFamily::V2) {
            // Answered on its own branch rather than routed into the SigV4 verifier below: P2-06
            // owns the SigV2 string-to-sign, and a SigV2 request verified as SigV4 is a downgrade.
            // The branch is total — every path out of it is a `SealedSigV2` or an `AuthError` —
            // so a SigV2 request can never reach the `SealedAws` this function builds afterwards.
            return self.admit_sigv2(view, marker, operation, presence, now);
        }

        // 5. H1 — clock skew, on whichever path carried the timestamp.
        let signed_at = self.signed_timestamp(&view, marker.location())?;
        let clock = enforce_clock_skew(&signed_at, now, self.skew)?;

        // 6. H2 — the presigned lifetime, from the receipt step 5 produced.
        let expiry = if marker.location().is_presigned() {
            Some(enforce_presign_expiry(&view, clock)?)
        } else {
            None
        };

        Ok(Admission::Sealed(SealedAws::new(
            view,
            marker,
            clock,
            presence,
            expiry,
            operation.service(),
        )))
    }

    /// The SigV2 branch of [`SecurityFloor::admit`], and the only route to a [`SealedSigV2`].
    ///
    /// # Why this is a branch and not a fall-through
    ///
    /// Until P2-06's wiring this was one line: `Err(NotImplemented(SigV2))`. Replacing that line
    /// with nothing would have made a SigV2 request continue into the SigV4 path below, where the
    /// `Authorization` header parses as neither and the outcome depends on which rejection came
    /// first. So the refusal was replaced by a branch that returns from every path: a
    /// [`SealedSigV2`], or an error. There is no arm that falls out of it, and
    /// [`crate::Admission::SealedSigV2`] is a variant of a `#[non_exhaustive]` enum, so an
    /// assembly that does not handle SigV2 refuses the request rather than mishandling it.
    ///
    /// # Errors
    ///
    /// * [`AuthError::AccessDenied`] when the [`SigV2Policy`] does not admit this location.
    /// * [`AuthError::NotImplemented`] for the POST-form shape, which is P2-05's and is refused
    ///   here rather than half-verified.
    /// * [`AuthError::AuthorizationHeaderMalformed`] for a credential this crate cannot parse, and
    ///   [`AuthError::AuthorizationQueryParametersError`] for its presigned spelling. Both are
    ///   rejections: a presented credential that cannot be read is never an anonymous request.
    /// * [`AuthError::RequestTimeTooSkewed`] from the same H1 window SigV4 uses, and
    ///   [`AuthError::RequestExpired`] for an elapsed presigned URL.
    fn admit_sigv2<'a>(
        &self,
        view: WireView<'a>,
        marker: AwsCredentialMarker,
        operation: &OperationFloor,
        presence: CredentialPresence,
        now: RequestNow,
    ) -> Result<Admission<'a>, AuthError> {
        let mode = match marker.location() {
            SigLocation::Header => SigV2Mode::HeaderAuth,
            SigLocation::Query => SigV2Mode::PresignedUrl,
            // The POST-form SigV2 shape (`AWSAccessKeyId` and `signature` fields) belongs to
            // P2-05's policy enforcement. "Recognised and refused" is the honest answer for it;
            // verifying the signature without the field-level rules would be worse than not
            // verifying it at all.
            _ => return Err(AuthError::NotImplemented(crate::error::Unimplemented::SigV2)),
        };
        if !self.sigv2.allows(mode) {
            return Err(AuthError::AccessDenied);
        }
        refuse_framed_sigv2_payload(&view)?;
        match mode {
            SigV2Mode::PresignedUrl => {
                let access_key_id = self.sigv2_query_value(&view, AWS_ACCESS_KEY_ID_PARAM)?;
                let signature = self.sigv2_query_value(&view, SIGV2_SIGNATURE_PARAM)?;
                let expires = self.sigv2_query_value(&view, SIGV2_EXPIRES_PARAM)?;
                // Before the credential is parsed, so that an expired URL and a malformed one are
                // not distinguishable by which check ran.
                let expires_at = crate::sig_v2::parse_presigned_expires(&expires, now)?;
                let presented = crate::sig_v2::parse_presigned_credential(&access_key_id, &signature)?;
                Ok(Admission::SealedSigV2(SealedSigV2::presigned(
                    view,
                    presented,
                    now,
                    expires_at,
                    presence,
                    operation.service(),
                )))
            }
            // `SigV2Mode` is `#[non_exhaustive]`; a location added later must not be admitted by a
            // wildcard, so header authentication is the named arm and everything else is refused
            // above by the `marker.location()` match.
            _ => {
                let raw = view
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                let presented = crate::sig_v2::parse_authorization(raw)?;
                // H1, through the same `enforce_clock_skew` SigV4 reaches. SigV2's two timestamp
                // spellings are normalised into one `AmzDate` first; there is no second window,
                // no second overflow rule and no second clock reading.
                let signed_at = crate::sig_v2::signed_timestamp(view.headers())?;
                let clock = enforce_clock_skew(&signed_at, now, self.skew)?;
                Ok(Admission::SealedSigV2(SealedSigV2::header(
                    view,
                    presented,
                    clock,
                    presence,
                    operation.service(),
                )))
            }
        }
    }

    /// Reads one SigV2 query parameter that must be present exactly once.
    ///
    /// H6 has already refused a repeated `AWSAccessKeyId`, `Signature` or `Expires`, so presence
    /// is the only thing left to check. A missing one is a rejection rather than a default.
    fn sigv2_query_value(&self, view: &WireView<'_>, name: &str) -> Result<String, AuthError> {
        view.query()
            .decoded_value(name)
            .map_err(|_| AuthError::AuthorizationQueryParametersError)?
            .ok_or(AuthError::AuthorizationQueryParametersError)
    }

    /// The branch for a request that carried no AWS credential marker.
    fn admit_without_aws_marker<'a>(
        &self,
        view: WireView<'a>,
        operation: &OperationFloor,
        presence: CredentialPresence,
        now: RequestNow,
    ) -> Result<Admission<'a>, AuthError> {
        if presence.any() {
            // An AWS surface was touched without an AWS marker — a session token with no
            // signature, say. There is nothing to verify and it is not anonymous, so it is a
            // rejection. Handing it to a custom verifier would be a way to launder an AWS
            // credential surface through a third-party scheme.
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        if let Some(scheme) = self.custom_schemes.matching(&view) {
            self.enforce_scheme_allowed(operation, SchemeSlot::Header, SigFamily::V4)?;
            return Ok(Admission::Custom(CustomAuthRequest::new(view, scheme, presence, now)));
        }
        self.enforce_scheme_allowed(operation, SchemeSlot::Anonymous, SigFamily::V4)?;
        // Infallible here — `presence.any()` is false — but spelled as the fallible call it is, so
        // that the evidence still comes from the presence record and not from this branch.
        presence
            .into_evidence()
            .map(Admission::Anonymous)
            .map_err(|_| AuthError::AuthorizationHeaderMalformed)
    }

    /// Reads the signed timestamp from whichever surface this signing path uses.
    fn signed_timestamp(&self, view: &WireView<'_>, location: SigLocation) -> Result<AmzDate, AuthError> {
        match location {
            SigLocation::Query => {
                let raw = view
                    .query()
                    .decoded_value(X_AMZ_DATE)
                    .map_err(|_| AuthError::AuthorizationQueryParametersError)?
                    .ok_or(AuthError::AuthorizationQueryParametersError)?;
                AmzDate::parse(&raw).map_err(|_| AuthError::AuthorizationQueryParametersError)
            }
            SigLocation::FormField => {
                // A POST form that carries a signature but no policy signs nothing. Refused here
                // rather than left to the POST-policy stage, so that the shape cannot reach an
                // anonymous outcome on the way past.
                if !view.form_contains("policy") {
                    return Err(AuthError::AuthorizationHeaderMalformed);
                }
                let raw = view.form_value("x-amz-date").ok_or(AuthError::AuthorizationHeaderMalformed)?;
                AmzDate::parse(raw)
            }
            _ => {
                let raw = view
                    .headers()
                    .get(X_AMZ_DATE_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                AmzDate::parse(raw)
            }
        }
    }

    /// H4, the run-time half — re-checks a verdict an extension point produced.
    ///
    /// [`CredentialPresence::into_evidence`] already makes the anonymous receipt unobtainable for
    /// a request that presented credentials. This closes the remaining gap: an extension point
    /// could mint a receipt from *another* presence record and attach it to this request. So the
    /// framework compares the verdict against this request's own presence and turns the mismatch
    /// back into a rejection.
    #[must_use]
    pub fn seal_verdict(verdict: Verdict, presence: CredentialPresence) -> Verdict {
        if presence.any() && verdict.is_anonymous() {
            return Verdict::reject(AuthError::AuthorizationHeaderMalformed);
        }
        verdict
    }
}

#[cfg(test)]
#[path = "floor_tests.rs"]
mod tests;
