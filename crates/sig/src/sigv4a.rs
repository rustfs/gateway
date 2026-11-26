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

//! SigV4a (`AWS4-ECDSA-P256-SHA256`) credential, header, presigned query, region-set and scope
//! validation.
//!
//! Responsible for: [`EcdsaDerSignature`] (unprintable, uncomparable validated ASN.1 DER
//! signature bytes), [`SigV4aCredentialScope`] (4-field scope without single region),
//! [`PresentedRegionSet`] (`x-amz-region-set` / `X-Amz-Region-Set`), [`SigV4aAuthorization`],
//! [`SigV4aPresignedParams`], and [`VerifiedSigV4aScope`] minted exclusively by
//! [`enforce_sigv4a_scope`].
//! NOT responsible for: P-256 keypair derivation or ECDSA verification (see
//! [`crate::sigv4a_derive`]), SigV4 HMAC parsing (`crate::parse`), or HTTP chunk decoding
//! (`rustfs-gateway-http`).
//! Upstream: [`crate::parse`], [`crate::query`], [`crate::scope`], [`crate::clock`], `p256`.
//! Downstream: [`crate::sigv4a_derive`], [`crate::canonical`], and `rustfs-gateway`'s
//! `SigV4Authenticator`.

use smallvec::SmallVec;

use crate::clock::ClockChecked;
use crate::parse::{
    AmzDate, SCOPE_TERMINATOR, ScopeDate, ServiceReading, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNED_HEADERS,
};
use crate::query::{RawQuery, X_AMZ_SIGNATURE};
use crate::scheme::{ALGORITHM_SIGV4A, SigService};
use crate::scope::{ExpectedScope, RegionSet, ScopeRejection};
use crate::verdict::{AuthError, Identity};

/// The presigned region-set query parameter for SigV4a.
pub const X_AMZ_REGION_SET: &str = "X-Amz-Region-Set";
/// The header carrying the SigV4a region set, lowercased.
pub const X_AMZ_REGION_SET_HEADER: &str = "x-amz-region-set";
/// The algorithm line of a SigV4a streaming chunk string-to-sign.
pub const SIGV4A_CHUNK_ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256-PAYLOAD";
/// The algorithm line of a SigV4a streaming trailer string-to-sign.
pub const SIGV4A_TRAILER_ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256-TRAILER";
/// Minimum byte length of an ASN.1 DER-encoded ECDSA P-256 signature.
pub const SIGV4A_MIN_DER_LEN: usize = 8;
/// Maximum byte length of an ASN.1 DER-encoded ECDSA P-256 signature.
pub const SIGV4A_MAX_DER_LEN: usize = 72;
/// Fixed lowercase-hex width used when AWS CRT right-pads streaming SigV4a chunk/trailer signatures
/// with `'*'`.
pub const SIGV4A_PADDED_HEX_LEN: usize = SIGV4A_MAX_DER_LEN * 2;
/// Maximum number of region entries admitted in one `x-amz-region-set` value.
const MAX_PRESENTED_REGIONS: usize = 64;

/// A syntactically validated ASN.1 DER-encoded ECDSA P-256 signature presented on the wire.
///
/// Like [`crate::Signature`] and [`crate::CtBytes`], it has no `PartialEq` and no `Debug` so
/// signature bytes cannot be compared with `==` or interpolated into logs:
///
/// ```compile_fail,E0369
/// use rustfs_gateway_sig::EcdsaDerSignature;
/// fn compare(a: &EcdsaDerSignature, b: &EcdsaDerSignature) -> bool {
///     a == b // no PartialEq: does not compile
/// }
/// ```
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::EcdsaDerSignature;
/// fn log(sig: &EcdsaDerSignature) {
///     println!("{sig:?}"); // no Debug: does not compile
/// }
/// ```
#[derive(Clone)]
pub struct EcdsaDerSignature {
    der: [u8; SIGV4A_MAX_DER_LEN],
    len: u8,
}

impl EcdsaDerSignature {
    /// Decodes a lowercase-hex ASN.1 DER ECDSA P-256 signature.
    ///
    /// Rejects uppercase hex, odd lengths, `'*'` padding (padding belongs solely to streaming
    /// chunk/trailer extensions, never head `Authorization` or presigned query), raw 64-byte
    /// non-DER `(r || s)` spellings, trailing bytes, and non-canonical DER encodings.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] for any malformed hex or non-DER value.
    pub fn parse_hex(text: &str) -> Result<Self, AuthError> {
        let raw = text.as_bytes();
        if raw.len() < SIGV4A_MIN_DER_LEN * 2 || raw.len() > SIGV4A_PADDED_HEX_LEN || !raw.len().is_multiple_of(2) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let byte_len = raw.len() / 2;
        let mut der = [0u8; SIGV4A_MAX_DER_LEN];
        for (slot, pair) in der[..byte_len].iter_mut().zip(raw.chunks_exact(2)) {
            let hi = hex_nibble_lower(pair[0])?;
            let lo = hex_nibble_lower(pair[1])?;
            *slot = (hi << 4) | lo;
        }
        Self::from_der_bytes(&der[..byte_len])
    }

    /// Validates raw ASN.1 DER bytes as a canonical ECDSA P-256 signature.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] if the bytes are not a strict canonical DER
    /// P-256 signature.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() < SIGV4A_MIN_DER_LEN || bytes.len() > SIGV4A_MAX_DER_LEN {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let parsed = p256::ecdsa::Signature::from_der(bytes).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
        // Strict canonical DER check: re-encoding must match the exact presented byte length so
        // non-canonical BER lengths or trailing bytes are rejected at parse time.
        let canonical = parsed.to_der();
        if canonical.as_bytes().len() != bytes.len() {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let mut der = [0u8; SIGV4A_MAX_DER_LEN];
        der[..bytes.len()].copy_from_slice(bytes);
        let len = u8::try_from(bytes.len()).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
        Ok(Self { der, len })
    }

    /// The DER-encoded byte length. Public metadata, not key material.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Always `false`: a valid DER ECDSA signature is at least [`SIGV4A_MIN_DER_LEN`] bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrows the verified ASN.1 DER bytes for downstream streaming chunk seeding.
    ///
    /// Requires a [`crate::SignatureMatch`] proof so unverified signature bytes cannot be read
    /// outside this crate.
    #[must_use]
    pub fn verified_der_bytes(&self, _proof: &crate::SignatureMatch) -> &[u8] {
        self.as_der_bytes()
    }

    /// Borrows the validated DER bytes for cryptographic verification inside this crate.
    pub(crate) fn as_der_bytes(&self) -> &[u8] {
        &self.der[..usize::from(self.len)]
    }
}

fn hex_nibble_lower(byte: u8) -> Result<u8, AuthError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AuthError::AuthorizationHeaderMalformed),
    }
}

/// A validated `x-amz-region-set` / `X-Amz-Region-Set` value presented by a SigV4a client.
///
/// Holds a non-empty comma-separated list of region tokens, where each token is either the
/// wildcard `"*"` or a valid lowercase AWS region name ([`RegionSet::is_region_name`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedRegionSet {
    regions: Box<[Box<str>]>,
    canonical: Box<str>,
    wildcard: bool,
}

impl PresentedRegionSet {
    /// Parses a SigV4a region set (`"*"`, `"us-east-1"`, or `"us-east-1,eu-west-1"`).
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] if empty, containing empty tokens (such as
    /// trailing/leading/double commas), exceeding 64 entries, or containing any token that is
    /// neither `"*"` nor a valid lowercase region name.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        if value.is_empty() {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let mut regions: Vec<Box<str>> = Vec::new();
        let mut wildcard = false;
        for raw_token in value.split(',') {
            let token = raw_token.trim_matches([' ', '\t']);
            if token.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            if regions.len() >= MAX_PRESENTED_REGIONS {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            if token == "*" {
                wildcard = true;
            } else if !RegionSet::is_region_name(token) {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            regions.push(Box::from(token));
        }
        if regions.is_empty() {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let canonical = regions.iter().map(Box::as_ref).collect::<Vec<_>>().join(",");
        Ok(Self {
            regions: regions.into_boxed_slice(),
            canonical: Box::from(canonical),
            wildcard,
        })
    }

    /// The canonical comma-joined spelling of the validated region set.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The individual validated region tokens, in presentation order.
    #[must_use]
    pub fn regions(&self) -> &[Box<str>] {
        &self.regions
    }

    /// Whether the region set includes the multi-region wildcard `"*"`.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Whether `region` is covered by this region set (either via `"*"` or exact membership).
    #[must_use]
    pub fn covers_region(&self, region: &str) -> bool {
        self.wildcard || self.regions.iter().any(|entry| entry.as_ref() == region)
    }
}

/// The service field of a SigV4a credential scope.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SigV4aScopeService {
    Known(SigService),
    Other(Box<str>),
}

/// The four-field credential tuple a SigV4a client presented:
/// `<access-key>/<date>/<service>/aws4_request`.
///
/// Unlike SigV4's five-field [`crate::CredentialScope`], SigV4a carries no single region inside
/// the credential scope — regions travel in `x-amz-region-set` (header) or `X-Amz-Region-Set`
/// (presigned query). Keeping the two types separate makes a 5-field SigV4 scope unrepresentable
/// here and a 4-field SigV4a scope unrepresentable in [`crate::CredentialScope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigV4aCredentialScope {
    access_key_id: Identity,
    date: ScopeDate,
    service: SigV4aScopeService,
}

impl SigV4aCredentialScope {
    /// Parses the four-field SigV4a credential value (`<akid>/<YYYYMMDD>/<service>/aws4_request`).
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] unless there are exactly four `/`-separated
    /// fields, the access key id and date are well formed, the service is a known [`SigService`],
    /// and the terminator is literally [`SCOPE_TERMINATOR`].
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        Self::parse_with(value, ServiceReading::Known)
    }

    /// [`SigV4aCredentialScope::parse`] with the service field governed by `services`.
    ///
    /// # Errors
    ///
    /// As [`SigV4aCredentialScope::parse`], admitting any non-empty ASCII-graphic service name
    /// when `services` is [`ServiceReading::AnyName`].
    pub fn parse_with(value: &str, services: ServiceReading) -> Result<Self, AuthError> {
        let fields: SmallVec<[&str; 4]> = value.split('/').collect();
        let [access_key_id, date, service, terminator] = fields.as_slice() else {
            return Err(AuthError::AuthorizationHeaderMalformed);
        };
        if *terminator != SCOPE_TERMINATOR {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let service = match (SigService::parse(service), services) {
            (Ok(known), _) => SigV4aScopeService::Known(known),
            (Err(_), ServiceReading::AnyName) if !service.is_empty() && service.bytes().all(|b| b.is_ascii_graphic()) => {
                SigV4aScopeService::Other(Box::from(*service))
            }
            (Err(_), _) => return Err(AuthError::AuthorizationHeaderMalformed),
        };
        Ok(Self {
            access_key_id: Identity::new(access_key_id).map_err(AuthError::from)?,
            date: ScopeDate::parse(date)?,
            service,
        })
    }

    /// The access key id the client claims. Public metadata, safe to log.
    #[must_use]
    pub const fn access_key_id(&self) -> &Identity {
        &self.access_key_id
    }

    /// The `YYYYMMDD` day stamp the client scoped to.
    #[must_use]
    pub const fn date(&self) -> ScopeDate {
        self.date
    }

    /// The service the client scoped to, when it is one [`SigService`] names.
    #[must_use]
    pub const fn service(&self) -> Option<SigService> {
        match self.service {
            SigV4aScopeService::Known(service) => Some(service),
            SigV4aScopeService::Other(_) => None,
        }
    }

    /// The service field exactly as signed.
    #[must_use]
    pub fn service_name(&self) -> &str {
        match &self.service {
            SigV4aScopeService::Known(service) => service.as_str(),
            SigV4aScopeService::Other(name) => name,
        }
    }

    /// The scope line as it appears in the SigV4a string-to-sign:
    /// `<date>/<service>/aws4_request`.
    #[must_use]
    pub fn scope_string(&self) -> String {
        format!("{}/{}/{SCOPE_TERMINATOR}", self.date, self.service_name())
    }
}

/// A parsed SigV4a `Authorization` header (`AWS4-ECDSA-P256-SHA256 ...`).
///
/// No `Debug` and no `PartialEq`: it holds an [`EcdsaDerSignature`].
pub struct SigV4aAuthorization {
    scope: SigV4aCredentialScope,
    signed_headers: Box<str>,
    der_sig: EcdsaDerSignature,
}

impl SigV4aAuthorization {
    /// Parses `AWS4-ECDSA-P256-SHA256 Credential=…, SignedHeaders=…, Signature=…`.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] for any other algorithm (including SigV4),
    /// missing/repeated/unknown parameters, malformed 4-field scope, or invalid DER signature.
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        Self::parse_with(header, ServiceReading::Known)
    }

    /// [`SigV4aAuthorization::parse`] with the scope service governed by `services`.
    ///
    /// # Errors
    ///
    /// As [`SigV4aAuthorization::parse`], reading the credential scope with `services`.
    pub fn parse_with(header: &str, services: ServiceReading) -> Result<Self, AuthError> {
        let (algorithm, rest) = header.split_once(' ').ok_or(AuthError::AuthorizationHeaderMalformed)?;
        if algorithm != ALGORITHM_SIGV4A {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }

        let mut credential: Option<&str> = None;
        let mut signed_headers: Option<&str> = None;
        let mut sig_hex: Option<&str> = None;
        for component in rest.split(',') {
            let component = component.trim_matches(' ');
            if component.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let (key, value) = component.split_once('=').ok_or(AuthError::AuthorizationHeaderMalformed)?;
            let slot = match key {
                "Credential" => &mut credential,
                "SignedHeaders" => &mut signed_headers,
                "Signature" => &mut sig_hex,
                _ => return Err(AuthError::AuthorizationHeaderMalformed),
            };
            if slot.is_some() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            *slot = Some(value);
        }

        let credential = credential.ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let signed_headers = signed_headers.ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let sig_hex = sig_hex.ok_or(AuthError::AuthorizationHeaderMalformed)?;

        Ok(Self {
            scope: SigV4aCredentialScope::parse_with(credential, services)?,
            signed_headers: Box::from(signed_headers),
            der_sig: EcdsaDerSignature::parse_hex(sig_hex)?,
        })
    }

    /// The four-field credential scope the client presented. Not yet cross-checked.
    #[must_use]
    pub const fn scope(&self) -> &SigV4aCredentialScope {
        &self.scope
    }

    /// The raw `SignedHeaders` value.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }

    /// The presented ASN.1 DER ECDSA signature.
    #[must_use]
    pub const fn signature(&self) -> &EcdsaDerSignature {
        &self.der_sig
    }
}

/// The SigV4a parameters of a presigned URL.
///
/// Requires `X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256`, four-field `X-Amz-Credential`,
/// `X-Amz-Date`, `X-Amz-Region-Set`, `X-Amz-SignedHeaders`, and `X-Amz-Signature`.
/// No `Debug` and no `PartialEq`.
pub struct SigV4aPresignedParams {
    scope: SigV4aCredentialScope,
    date: AmzDate,
    region_set: PresentedRegionSet,
    signed_headers: Box<str>,
    der_sig: EcdsaDerSignature,
}

impl SigV4aPresignedParams {
    /// Reads and validates the six SigV4a presigned query parameters.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] if any parameter is missing, repeated,
    /// non-SigV4a, or structurally invalid.
    pub fn parse(query: &RawQuery<'_>) -> Result<Self, AuthError> {
        Self::parse_with(query, ServiceReading::Known)
    }

    /// [`SigV4aPresignedParams::parse`] with the scope service governed by `services`.
    ///
    /// # Errors
    ///
    /// As [`SigV4aPresignedParams::parse`], reading the credential scope with `services`.
    pub fn parse_with(query: &RawQuery<'_>, services: ServiceReading) -> Result<Self, AuthError> {
        let required = |name: &str| -> Result<String, AuthError> {
            query.decoded_value(name)?.ok_or(AuthError::AuthorizationHeaderMalformed)
        };
        let algorithm = required(X_AMZ_ALGORITHM)?;
        if algorithm != ALGORITHM_SIGV4A {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        Ok(Self {
            scope: SigV4aCredentialScope::parse_with(&required(X_AMZ_CREDENTIAL)?, services)?,
            date: AmzDate::parse(&required(X_AMZ_DATE)?)?,
            region_set: PresentedRegionSet::parse(&required(X_AMZ_REGION_SET)?)?,
            signed_headers: Box::from(required(X_AMZ_SIGNED_HEADERS)?.as_str()),
            der_sig: EcdsaDerSignature::parse_hex(&required(X_AMZ_SIGNATURE)?)?,
        })
    }

    /// The four-field credential scope the client presented.
    #[must_use]
    pub const fn scope(&self) -> &SigV4aCredentialScope {
        &self.scope
    }

    /// The signed timestamp.
    #[must_use]
    pub const fn date(&self) -> AmzDate {
        self.date
    }

    /// The validated `X-Amz-Region-Set` parameter.
    #[must_use]
    pub const fn region_set(&self) -> &PresentedRegionSet {
        &self.region_set
    }

    /// The raw `X-Amz-SignedHeaders` value.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }

    /// The presented ASN.1 DER ECDSA signature.
    #[must_use]
    pub const fn signature(&self) -> &EcdsaDerSignature {
        &self.der_sig
    }
}

/// A SigV4a credential scope and region set that passed H5 cross-checking.
///
/// Only [`enforce_sigv4a_scope`] constructs this type outside crate tests, and
/// [`crate::verify_sigv4a_signature`] requires one — making "verified a SigV4a signature without
/// checking the scope day, service, and `x-amz-region-set`" fail to compile:
///
/// ```compile_fail,E0451
/// use rustfs_gateway_sig::{PresentedRegionSet, ScopeDate, VerifiedSigV4aScope};
/// let date = ScopeDate::parse("20150830").expect("valid");
/// let region_set = PresentedRegionSet::parse("*").expect("valid");
/// let _ = VerifiedSigV4aScope { date, region_set, service: Box::from("s3") };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSigV4aScope {
    date: ScopeDate,
    region_set: PresentedRegionSet,
    service: Box<str>,
}

impl VerifiedSigV4aScope {
    #[cfg(test)]
    pub(crate) fn from_checked_parts(date: ScopeDate, region_set: PresentedRegionSet, service: &str) -> Self {
        Self {
            date,
            region_set,
            service: Box::from(service),
        }
    }

    /// The day stamp checked against the clock receipt.
    #[must_use]
    pub const fn date(&self) -> ScopeDate {
        self.date
    }

    /// The validated `x-amz-region-set` checked against the deployment's regions.
    #[must_use]
    pub const fn region_set(&self) -> &PresentedRegionSet {
        &self.region_set
    }

    /// The service checked against the routed operation.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The SigV4a scope string: `<date>/<service>/aws4_request`.
    #[must_use]
    pub fn scope_string(&self) -> String {
        format!("{}/{}/{SCOPE_TERMINATOR}", self.date, self.service)
    }
}

/// H5 for SigV4a — cross-checks the four-field scope and `x-amz-region-set` against the clock
/// receipt, deployment regions, and routed service.
///
/// Checks, in order:
/// 1. `presented.date()` equals `clock.signed_at().day()`.
/// 2. `region_set` is wildcard (`"*"`) or contains at least one region admitted by `expected`.
/// 3. `presented.service_name()` is admitted by `expected`.
///
/// # Errors
///
/// [`ScopeRejection`] on any disagreement. Only a region-set mismatch carries the first
/// configured remediation region.
pub fn enforce_sigv4a_scope(
    presented: &SigV4aCredentialScope,
    region_set: &PresentedRegionSet,
    clock: ClockChecked,
    expected: &ExpectedScope<'_>,
) -> Result<VerifiedSigV4aScope, ScopeRejection> {
    if presented.date() != clock.signed_at().day() {
        return Err(ScopeRejection::none());
    }
    let region_admitted = region_set.is_wildcard()
        || region_set
            .regions()
            .iter()
            .any(|region| expected.admits_region(region.as_ref()));
    if !region_admitted {
        return Err(ScopeRejection::first_configured_region(expected));
    }
    if !expected.admits_service(presented.service_name()) {
        return Err(ScopeRejection::none());
    }
    Ok(VerifiedSigV4aScope {
        date: presented.date(),
        region_set: region_set.clone(),
        service: Box::from(presented.service_name()),
    })
}
