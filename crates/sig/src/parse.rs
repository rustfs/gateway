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

//! Where the signature and its scope are read off the request, and nothing else.
//!
//! Responsible for: [`ScopeDate`] and [`AmzDate`] (the two date spellings SigV4 uses),
//! [`CredentialScope`] (the four-plus-terminator credential tuple, parsed but deliberately *not*
//! trusted), [`SigV4Authorization`] (the header form) and [`PresignedParams`] (the query form).
//! NOT responsible for: deciding whether the scope is acceptable. Nothing here compares the date
//! against the clock, the region against configuration, or the service against the routed
//! operation — that cross-check is P2-04's, is unconditional there, and this module's entire
//! contribution to it is handing over the four values unaltered.
//! Upstream: [`crate::codec`], [`crate::scheme`], [`crate::verdict`], [`crate::query`].
//! Downstream: [`crate::canonical`] for the string-to-sign, [`crate::derive`] for the signing key,
//! and P2-04 for the cross-check.
//!
//! # The mistake this module is shaped to prevent
//!
//! The credential scope is written by the client. Deriving the signing key straight from it —
//! `HMAC(secret, client_date)` then `client_region` then `client_service` — makes verification
//! succeed for whatever scope the client chose, which means a signature a legitimate SDK produced
//! for a *different service or region* replays here. That is why [`CredentialScope`] is a
//! transport type with no authority attached, why it cannot be passed to
//! [`crate::signing_key`], and why the only thing that can is [`crate::VerifiedScope`], which this
//! crate does not let anybody construct.

use core::fmt;

use smallvec::SmallVec;

use crate::codec::decode_hex_lower;
use crate::error::Unimplemented;
use crate::query::RawQuery;
use crate::scheme::{ALGORITHM_SIGV4, ALGORITHM_SIGV4A, SigFamily, SigService};
use crate::signature::{CtBytes, Signature};
use crate::verdict::{AuthError, Identity};

/// The literal that must terminate every SigV4 credential scope.
pub const SCOPE_TERMINATOR: &str = "aws4_request";

/// The query parameter names of a presigned SigV4 URL.
pub const X_AMZ_ALGORITHM: &str = "X-Amz-Algorithm";
/// The presigned credential parameter: `<access-key>/<scope>`.
pub const X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";
/// The presigned timestamp parameter, in ISO 8601 basic form.
pub const X_AMZ_DATE: &str = "X-Amz-Date";
/// The presigned signed-header allow-list parameter.
pub const X_AMZ_SIGNED_HEADERS: &str = "X-Amz-SignedHeaders";

/// The `YYYYMMDD` day stamp that appears in a credential scope.
///
/// Stored as the eight bytes, not as a calendar type: the scope is a signed string, so the exact
/// spelling matters and a round trip through a date library would let `2015-08-30` and `20150830`
/// become the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeDate([u8; 8]);

impl ScopeDate {
    /// Parses eight digits, and checks that they could name a day.
    ///
    /// The month and day ranges are checked because an out-of-range stamp has no correct answer
    /// downstream: P2-04 compares this against the request's own date, and `20159999` would
    /// compare unequal to everything and be reported as a skew failure rather than as the
    /// malformed value it is.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] unless the value is eight ASCII digits naming a
    /// month in `01..=12` and a day in `01..=31`.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let bytes: [u8; 8] = text
            .as_bytes()
            .try_into()
            .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let two = |hi: u8, lo: u8| (hi - b'0') * 10 + (lo - b'0');
        let month = two(bytes[4], bytes[5]);
        let day = two(bytes[6], bytes[7]);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        Ok(Self(bytes))
    }

    /// The eight characters, as signed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every byte was checked to be an ASCII digit at construction.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for ScopeDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `X-Amz-Date` timestamp, `YYYYMMDDTHHMMSSZ`.
///
/// Kept verbatim for the same reason as [`ScopeDate`]: line two of the string-to-sign is this
/// exact text, so re-rendering it from a parsed instant risks producing a second spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AmzDate {
    text: [u8; Self::LEN],
    day: ScopeDate,
}

impl AmzDate {
    /// The length of the ISO 8601 basic form used by SigV4.
    pub const LEN: usize = 16;

    /// Parses `YYYYMMDDTHHMMSSZ` strictly.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] for the wrong length, a missing `T` or `Z`, a
    /// non-digit, or an hour, minute or second out of range. The extended form
    /// (`2015-08-30T12:36:00Z`) is rejected: it is a different string, and this one is signed.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let bytes: [u8; Self::LEN] = text
            .as_bytes()
            .try_into()
            .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
        if bytes[8] != b'T' || bytes[15] != b'Z' {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let day = ScopeDate::parse(text.get(..8).ok_or(AuthError::AuthorizationHeaderMalformed)?)?;
        let time = &bytes[9..15];
        if !time.iter().all(u8::is_ascii_digit) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let two = |hi: u8, lo: u8| (hi - b'0') * 10 + (lo - b'0');
        let (hour, minute, second) = (two(time[0], time[1]), two(time[2], time[3]), two(time[4], time[5]));
        if hour > 23 || minute > 59 || second > 60 {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        Ok(Self { text: bytes, day })
    }

    /// The timestamp as signed. This is line two of the string-to-sign, byte for byte.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Construction admitted only ASCII digits, `T` and `Z`.
        core::str::from_utf8(&self.text).unwrap_or("")
    }

    /// The `YYYYMMDD` prefix, for P2-04's "scope date equals request date" cross-check.
    #[must_use]
    pub const fn day(&self) -> ScopeDate {
        self.day
    }
}

impl fmt::Display for AmzDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a credential scope may name an empty region: `AKID/20150830//s3/aws4_request`.
///
/// Such a scope still has exactly five fields, so it cannot be read two ways. It is
/// [`EmptyRegion::Refused`] everywhere by default; a verifier admits it only when its deployment
/// admits an empty signing region at the scope check too
/// ([`crate::ExpectedScope::accepting_empty_region`], the RustFS profile), and passes
/// [`EmptyRegion::Admitted`] to the `parse_with` constructors below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyRegion {
    /// An empty region field is malformed.
    Refused,
    /// An empty region field is a region to cross-check like any other.
    Admitted,
}

/// The credential tuple a client presented: `<access-key>/<date>/<region>/<service>/aws4_request`.
///
/// **Parsed, never trusted.** Every field here is chosen by whoever sent the request. The type
/// carries them to P2-04 for cross-checking and to the string-to-sign, which must reproduce the
/// client's own scope line — and it is deliberately not the type [`crate::signing_key`] accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialScope {
    access_key_id: Identity,
    date: ScopeDate,
    region: Box<str>,
    service: SigService,
}

impl CredentialScope {
    /// The longest region name accepted. AWS's longest today is well under half of this.
    pub const MAX_REGION_LEN: usize = 64;

    /// Parses the five-field credential value.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] unless there are exactly five `/`-separated
    /// fields, the access key id is well formed, the date is a `YYYYMMDD` stamp, the region is a
    /// non-empty ASCII-graphic name within [`CredentialScope::MAX_REGION_LEN`], the service is one
    /// of the five S3-family services, and the terminator is literally
    /// [`SCOPE_TERMINATOR`].
    ///
    /// An unknown service is a rejection and never a pass-through. A scope that names a service
    /// this gateway does not serve cannot be "close enough": the service name is one of the four
    /// HMAC steps, so accepting an unrecognised one means deriving a key from attacker-chosen
    /// input.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        Self::parse_with(value, EmptyRegion::Refused)
    }

    /// [`CredentialScope::parse`], with an empty region field admitted when `empty` says so.
    ///
    /// # Errors
    ///
    /// As [`CredentialScope::parse`]; an empty region is refused only under
    /// [`EmptyRegion::Refused`]. Every other rule — five fields, the ceiling, ASCII-graphic
    /// bytes — is the same under both.
    pub fn parse_with(value: &str, empty: EmptyRegion) -> Result<Self, AuthError> {
        let fields: SmallVec<[&str; 5]> = value.split('/').collect();
        let [access_key_id, date, region, service, terminator] = fields.as_slice() else {
            return Err(AuthError::AuthorizationHeaderMalformed);
        };
        if *terminator != SCOPE_TERMINATOR {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        let empty_refused = region.is_empty() && empty == EmptyRegion::Refused;
        if empty_refused || region.len() > Self::MAX_REGION_LEN || !region.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        Ok(Self {
            access_key_id: Identity::new(access_key_id).map_err(AuthError::from)?,
            date: ScopeDate::parse(date)?,
            region: Box::from(*region),
            service: SigService::parse(service).map_err(AuthError::from)?,
        })
    }

    /// The access key id the client claims. A public identifier, safe to log.
    #[must_use]
    pub const fn access_key_id(&self) -> &Identity {
        &self.access_key_id
    }

    /// The day stamp the client scoped to. P2-04 compares it against the request's own date.
    #[must_use]
    pub const fn date(&self) -> ScopeDate {
        self.date
    }

    /// The region the client scoped to. P2-04 checks it against the configured set.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The service the client scoped to. P2-04 checks it against the routed operation's service.
    #[must_use]
    pub const fn service(&self) -> SigService {
        self.service
    }

    /// The scope line as it appears in the string-to-sign: `<date>/<region>/<service>/aws4_request`.
    ///
    /// Rebuilt from the parsed fields rather than sliced out of the input, so that a value which
    /// parsed can only render one way.
    #[must_use]
    pub fn scope_string(&self) -> String {
        format!("{}/{}/{}/{SCOPE_TERMINATOR}", self.date, self.region, self.service)
    }
}

/// A parsed SigV4 `Authorization` header.
///
/// There is no `Debug`: the struct holds a [`Signature`], which has none, and the absence
/// propagates — so an `Authorization` header cannot reach a log line through this type.
pub struct SigV4Authorization {
    scope: CredentialScope,
    signed_headers: Box<str>,
    signature: Signature,
}

impl SigV4Authorization {
    /// Parses `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`.
    ///
    /// Exactly three parameters, each named once, no unknown name, no empty component, and a
    /// 64-character lowercase-hex signature. Anything else is a rejection.
    ///
    /// # Errors
    ///
    /// * [`AuthError::NotImplemented`] for `AWS4-ECDSA-P256-SHA256`. Recognised and refused, so
    ///   that a SigV4a request can never be handed to the SigV4 verifier — that is an algorithm
    ///   downgrade, not a fallback.
    /// * [`AuthError::AuthorizationHeaderMalformed`] for an unknown algorithm token, for SigV2 (a
    ///   different header shape entirely, parsed in P2-06), and for every structural fault above.
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        Self::parse_with(header, EmptyRegion::Refused)
    }

    /// [`SigV4Authorization::parse`], with the credential's empty region governed by `empty`.
    ///
    /// # Errors
    ///
    /// As [`SigV4Authorization::parse`], with [`CredentialScope::parse_with`]'s region rule.
    pub fn parse_with(header: &str, empty: EmptyRegion) -> Result<Self, AuthError> {
        let (algorithm, rest) = header.split_once(' ').ok_or(AuthError::AuthorizationHeaderMalformed)?;
        match SigFamily::from_algorithm(algorithm) {
            Ok(SigFamily::V4) => {}
            Ok(_) | Err(_) => {
                // `AWS4-ECDSA-P256-SHA256` is recognised and refused; `AWS` (SigV2) and anything
                // unknown are malformed *for this parser*. Neither falls through to SigV4.
                if algorithm == ALGORITHM_SIGV4A {
                    return Err(AuthError::NotImplemented(Unimplemented::SigV4a));
                }
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
        }

        let mut credential: Option<&str> = None;
        let mut signed_headers: Option<&str> = None;
        let mut signature: Option<&str> = None;
        for component in rest.split(',') {
            let component = component.trim_matches(' ');
            if component.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let (key, value) = component.split_once('=').ok_or(AuthError::AuthorizationHeaderMalformed)?;
            let slot = match key {
                "Credential" => &mut credential,
                "SignedHeaders" => &mut signed_headers,
                "Signature" => &mut signature,
                _ => return Err(AuthError::AuthorizationHeaderMalformed),
            };
            if slot.is_some() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            *slot = Some(value);
        }

        let credential = credential.ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let signed_headers = signed_headers.ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let signature = signature.ok_or(AuthError::AuthorizationHeaderMalformed)?;

        Ok(Self {
            scope: CredentialScope::parse_with(credential, empty)?,
            signed_headers: Box::from(signed_headers),
            signature: parse_hex_signature(signature)?,
        })
    }

    /// The credential scope the client presented. Not yet checked against anything.
    #[must_use]
    pub const fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    /// The raw `SignedHeaders` value, for [`crate::SignedHeaderSet::parse_and_enforce`].
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }

    /// The signature the client presented, for [`crate::Signature::ct_verify`].
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// The SigV4 parameters of a presigned URL.
///
/// Same shape as [`SigV4Authorization`], plus the timestamp, which a presigned request carries in
/// the query rather than in a header. Expiry, the privileged-operation fence and the presigned
/// body rules are P2-04 and P2-05; nothing here reads `X-Amz-Expires`.
///
/// No `Debug`, for the same reason as [`SigV4Authorization`].
pub struct PresignedParams {
    scope: CredentialScope,
    date: AmzDate,
    signed_headers: Box<str>,
    signature: Signature,
}

impl PresignedParams {
    /// Reads the five required `X-Amz-*` query parameters.
    ///
    /// # Errors
    ///
    /// * [`AuthError::NotImplemented`] for the SigV4a algorithm token.
    /// * [`AuthError::AuthorizationHeaderMalformed`] if any required parameter is missing,
    ///   repeated, or ill-formed, or if the algorithm token is unknown.
    pub fn parse(query: &RawQuery<'_>) -> Result<Self, AuthError> {
        Self::parse_with(query, EmptyRegion::Refused)
    }

    /// [`PresignedParams::parse`], with the credential's empty region governed by `empty`.
    ///
    /// # Errors
    ///
    /// As [`PresignedParams::parse`], with [`CredentialScope::parse_with`]'s region rule.
    pub fn parse_with(query: &RawQuery<'_>, empty: EmptyRegion) -> Result<Self, AuthError> {
        let required = |name: &str| -> Result<String, AuthError> {
            query.decoded_value(name)?.ok_or(AuthError::AuthorizationHeaderMalformed)
        };
        let algorithm = required(X_AMZ_ALGORITHM)?;
        if algorithm == ALGORITHM_SIGV4A {
            return Err(AuthError::NotImplemented(Unimplemented::SigV4a));
        }
        if algorithm != ALGORITHM_SIGV4 {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        Ok(Self {
            scope: CredentialScope::parse_with(&required(X_AMZ_CREDENTIAL)?, empty)?,
            date: AmzDate::parse(&required(X_AMZ_DATE)?)?,
            signed_headers: Box::from(required(X_AMZ_SIGNED_HEADERS)?.as_str()),
            signature: parse_hex_signature(&required(crate::query::X_AMZ_SIGNATURE)?)?,
        })
    }

    /// The credential scope the client presented.
    #[must_use]
    pub const fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    /// The signed timestamp.
    #[must_use]
    pub const fn date(&self) -> AmzDate {
        self.date
    }

    /// The raw `X-Amz-SignedHeaders` value.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }

    /// The signature the client presented.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

fn parse_hex_signature(text: &str) -> Result<Signature, AuthError> {
    decode_hex_lower::<32>(text)
        .map(|bytes| Signature::HmacSha256(CtBytes::from_array(bytes)))
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Unimplemented;

    const SIG: &str = "5fa00fa315 53b73ebf194267 6e86291e8372ff2a2260956d9b8aae1d763fbf31";
    const CRED: &str = "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request";

    fn hex_signature() -> String {
        SIG.replace(' ', "")
    }

    #[test]
    fn a_well_formed_authorization_header_parses() {
        let header = format!(
            "AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host;x-amz-date, Signature={}",
            hex_signature()
        );
        let parsed = SigV4Authorization::parse(&header).expect("valid");
        assert_eq!(parsed.scope().scope_string(), "20150830/us-east-1/s3/aws4_request");
        assert_eq!(parsed.scope().access_key_id().access_key_id(), "AKIDEXAMPLE");
        assert_eq!(parsed.signed_headers(), "host;x-amz-date");
        assert_eq!(parsed.signature().width(), 32);
    }

    #[test]
    fn malformed_authorization_headers_are_refused_and_never_downgraded() {
        let signature = hex_signature();
        let bad = [
            format!("AWS4-HMAC-SHA256 SignedHeaders=host, Signature={signature}"),
            format!("AWS4-HMAC-SHA256 Credential={CRED}, Signature={signature}"),
            format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host"),
            format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host, Signature={signature},"),
            format!("AWS4-HMAC-SHA256 Credential={CRED}, Credential={CRED}, SignedHeaders=host, Signature={signature}"),
            format!("AWS4-HMAC-SHA512 Credential={CRED}, SignedHeaders=host, Signature={signature}"),
            format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host, Signature={}", &signature[..63]),
        ];
        for header in &bad {
            assert_eq!(
                SigV4Authorization::parse(header).err(),
                Some(AuthError::AuthorizationHeaderMalformed),
                "must reject {header}"
            );
        }
    }

    #[test]
    fn sigv4a_is_refused_with_not_implemented_rather_than_verified_as_sigv4() {
        let header = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={CRED}, SignedHeaders=host, Signature={}",
            hex_signature()
        );
        assert_eq!(
            SigV4Authorization::parse(&header).err(),
            Some(AuthError::NotImplemented(Unimplemented::SigV4a))
        );
    }

    #[test]
    fn a_scope_must_end_in_the_terminator_and_name_a_known_service() {
        assert!(CredentialScope::parse("AKID/20150830/us-east-1/s3/aws4_request").is_ok());
        for bad in [
            "AKID/20150830/us-east-1/s3/aws4-request",
            "AKID/20150830/us-east-1/s3/AWS4_REQUEST",
            "AKID/20150830/us-east-1/ec2/aws4_request",
            "AKID/2015083/us-east-1/s3/aws4_request",
            "AKID/20151330/us-east-1/s3/aws4_request",
            "AKID/20150830//s3/aws4_request",
            "AKID/20150830/us-east-1/s3/aws4_request/extra",
            "AKID/20150830/us-east-1/s3",
        ] {
            assert!(CredentialScope::parse(bad).is_err(), "must reject {bad}");
        }
    }

    const EMPTY_REGION: &str = "AKID/20150830//s3/aws4_request";

    /// An admitted empty region is structure the parser reads one way only: five fields, and a
    /// scope line with nothing between the date and the service.
    #[test]
    fn an_admitted_empty_region_is_a_five_field_scope_and_renders_as_one() {
        let scope = CredentialScope::parse_with(EMPTY_REGION, EmptyRegion::Admitted).expect("five fields");
        assert_eq!(scope.region(), "");
        assert_eq!(scope.scope_string(), "20150830//s3/aws4_request");
        let header = format!(
            "AWS4-HMAC-SHA256 Credential={EMPTY_REGION}, SignedHeaders=host, Signature={}",
            hex_signature()
        );
        let parsed = SigV4Authorization::parse_with(&header, EmptyRegion::Admitted).expect("admitted");
        assert_eq!(parsed.scope().region(), "");
    }

    /// Negative — an empty region is refused by every default constructor and under `Refused`.
    #[test]
    fn n_an_empty_region_is_refused_unless_admitted() {
        assert!(CredentialScope::parse(EMPTY_REGION).is_err());
        assert!(CredentialScope::parse_with(EMPTY_REGION, EmptyRegion::Refused).is_err());
        let header = format!(
            "AWS4-HMAC-SHA256 Credential={EMPTY_REGION}, SignedHeaders=host, Signature={}",
            hex_signature()
        );
        assert_eq!(SigV4Authorization::parse(&header).err(), Some(AuthError::AuthorizationHeaderMalformed));
        assert_eq!(
            SigV4Authorization::parse_with(&header, EmptyRegion::Refused).err(),
            Some(AuthError::AuthorizationHeaderMalformed)
        );
    }

    /// Negative — admitting the empty region relaxes nothing else: a region field still cannot
    /// carry the separator, a space, a control byte, a non-ASCII byte, or more than the ceiling.
    #[test]
    fn n_an_admitted_empty_region_relaxes_no_other_rule() {
        let long = format!("AKID/20150830/{}/s3/aws4_request", "a".repeat(CredentialScope::MAX_REGION_LEN + 1));
        for bad in [
            "AKID/20150830/us/east-1/s3/aws4_request",
            "AKID/20150830///s3/aws4_request",
            "AKID/20150830//s3/aws4_request/",
            "AKID/20150830//sts3/aws4_request",
            "AKID/20150830//s3/aws4-request",
            "AKID//us-east-1/s3/aws4_request",
            "/20150830//s3/aws4_request",
            "AKID/20150830/us east-1/s3/aws4_request",
            "AKID/20150830/us\teast-1/s3/aws4_request",
            "AKID/20150830/us-\u{e9}ast-1/s3/aws4_request",
            long.as_str(),
        ] {
            assert!(CredentialScope::parse_with(bad, EmptyRegion::Admitted).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn the_timestamp_accepts_only_the_basic_form() {
        let date = AmzDate::parse("20150830T123600Z").expect("valid");
        assert_eq!(date.as_str(), "20150830T123600Z");
        assert_eq!(date.day().as_str(), "20150830");
        for bad in [
            "2015-08-30T12:36:00Z",
            "20150830T123600",
            "20150830t123600Z",
            "20150830T253600Z",
            "",
        ] {
            assert!(AmzDate::parse(bad).is_err(), "must reject {bad}");
        }
    }
}
