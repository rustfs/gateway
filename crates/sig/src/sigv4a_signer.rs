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

//! Client-side AWS SigV4a (`AWS4-ECDSA-P256-SHA256`) header, presigned, and streaming signer.
//!
//! Responsible for: [`SigV4aSigner`] and [`SigV4aChunkSigner`], producing real ECDSA P-256
//! `Authorization` headers, presigned queries with `X-Amz-Region-Set`, and streaming
//! `aws-chunked` frames (both unpadded and AWS CRT 144-char `'*'`-padded) for integration tests
//! and facade consumers.
//! NOT responsible for: verifying incoming requests ([`crate::sigv4a_derive`]) or decoding chunks
//! (`rustfs-gateway-http`).
//! Upstream: `p256`, `sha2`, [`crate::sigv4a`], [`crate::sigv4a_derive`], [`crate::signer`].
//! Downstream: `crates/sig` tests, `rustfs-gateway` tests, and facade re-exports.

use std::collections::BTreeSet;

use http::header::{HeaderName, HeaderValue};
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};

use crate::canonical::{CanonicalRequestSpec, UriPathCandidates};
use crate::codec::encode_hex_lower;
use crate::mode::EMPTY_PAYLOAD_SHA256_HEX;
use crate::parse::{AmzDate, ScopeDate, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNED_HEADERS};
use crate::query::{RawQuery, X_AMZ_SIGNATURE, percent_encode};
use crate::scheme::{ALGORITHM_SIGV4A, SigLocation, SigService};
use crate::signed_headers::SignedHeaderSet;
use crate::signer::{
    CHUNK_SIGNATURE_EXTENSION, SignedRequest, SignerError, SigningCredentials, SigningRequest, X_AMZ_CONTENT_SHA256_HEADER_NAME,
    X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME, X_AMZ_TRAILER_HEADER_NAME,
};
use crate::sigv4a::{
    PresentedRegionSet, SIGV4A_CHUNK_ALGORITHM, SIGV4A_PADDED_HEX_LEN, SIGV4A_TRAILER_ALGORITHM, SigV4aCredentialScope,
    X_AMZ_REGION_SET, X_AMZ_REGION_SET_HEADER,
};
use crate::sigv4a_derive::derive_p256_signing_key;
use crate::{X_AMZ_DATE_HEADER, X_AMZ_EXPIRES, X_AMZ_SECURITY_TOKEN, X_AMZ_SECURITY_TOKEN_HEADER};

/// Client-side AWS SigV4a signer holding a derived P-256 signing key.
///
/// Has no `Debug`, no `PartialEq`, and no key accessor:
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::SigV4aSigner;
/// fn leak(signer: &SigV4aSigner) {
///     println!("{signer:?}"); // no Debug: does not compile
/// }
/// ```
pub struct SigV4aSigner {
    access_key_id: Box<str>,
    session_token: Option<crate::SessionToken>,
    key: p256::ecdsa::SigningKey,
    date: ScopeDate,
    service: SigService,
    region_set: PresentedRegionSet,
}

impl SigV4aSigner {
    /// Builds a SigV4a client signer from credentials, scope day, service, and `region_set`.
    ///
    /// # Errors
    ///
    /// [`SignerError`] if `region_set` is malformed or P-256 key derivation fails.
    pub fn new(
        credentials: SigningCredentials,
        date: ScopeDate,
        service: SigService,
        region_set: &str,
    ) -> Result<Self, SignerError> {
        let parsed_regions = PresentedRegionSet::parse(region_set)?;
        let akid = credentials.access_key_id().access_key_id().to_owned();
        let token = credentials.session_token().map(crate::SessionToken::clone_secret);
        let key = derive_p256_signing_key(&akid, credentials.secret())?;
        Ok(Self {
            access_key_id: Box::from(akid),
            session_token: token,
            key,
            date,
            service,
            region_set: parsed_regions,
        })
    }

    /// Signs a request using the SigV4a `Authorization` header and `x-amz-region-set`.
    ///
    /// # Errors
    ///
    /// [`SignerError`] if the request path, headers, or decoded length are malformed.
    pub fn sign_headers(&self, request: &SigningRequest<'_>) -> Result<SignedRequest, SignerError> {
        if request.payload.requires_decoded_length() && request.decoded_content_length.is_none() {
            return Err(SignerError::DecodedContentLengthRequired);
        }
        if !request.payload.requires_decoded_length() && request.decoded_content_length.is_some() {
            return Err(SignerError::DecodedContentLengthNotAllowed);
        }
        let mut headers = request.headers.clone();
        headers.remove(http::header::AUTHORIZATION);
        headers.remove(X_AMZ_DATE_HEADER);
        headers.remove(X_AMZ_REGION_SET_HEADER);
        headers.remove(X_AMZ_CONTENT_SHA256_HEADER_NAME);
        headers.remove(X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME);
        headers.remove(X_AMZ_SECURITY_TOKEN_HEADER);
        headers.remove(X_AMZ_TRAILER_HEADER_NAME);

        headers.insert(
            HeaderName::from_static(X_AMZ_DATE_HEADER),
            HeaderValue::from_str(request.timestamp.as_str()).map_err(|_| SignerError::UnrepresentableHeader)?,
        );
        headers.insert(
            HeaderName::from_static(X_AMZ_REGION_SET_HEADER),
            HeaderValue::from_str(self.region_set.as_str()).map_err(|_| SignerError::UnrepresentableHeader)?,
        );
        headers.insert(
            HeaderName::from_static(X_AMZ_CONTENT_SHA256_HEADER_NAME),
            HeaderValue::from_str(request.payload.canonical_payload_token().as_str())
                .map_err(|_| SignerError::UnrepresentableHeader)?,
        );
        if let Some(decoded) = request.decoded_content_length {
            headers.insert(
                HeaderName::from_static(X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME),
                HeaderValue::from_str(&decoded.to_string()).map_err(|_| SignerError::UnrepresentableHeader)?,
            );
        }
        if let Some(declared) = request.payload.trailer().and_then(crate::TrailerSet::declared) {
            let joined = declared
                .names()
                .iter()
                .map(crate::TrailerName::as_str)
                .collect::<Vec<_>>()
                .join(",");
            headers.insert(
                HeaderName::from_static(X_AMZ_TRAILER_HEADER_NAME),
                HeaderValue::from_str(&joined).map_err(|_| SignerError::UnrepresentableHeader)?,
            );
        }
        if let Some(token) = &self.session_token {
            headers.insert(
                HeaderName::from_static(X_AMZ_SECURITY_TOKEN_HEADER),
                HeaderValue::from_bytes(token.expose()).map_err(|_| SignerError::UnrepresentableHeader)?,
            );
        }

        let mut names: BTreeSet<String> = headers
            .keys()
            .filter(|name| name.as_str() != "host")
            .map(|name| name.as_str().to_owned())
            .collect();
        names.insert("host".to_owned());
        let signed_list = names.into_iter().collect::<Vec<_>>().join(";");

        let mut canonical_headers = headers.clone();
        canonical_headers.remove(http::header::HOST);
        let signed = SignedHeaderSet::parse_and_enforce(&signed_list, &canonical_headers, request.wire_content_length)?;
        let paths = UriPathCandidates::new(request.path)?;
        let query = RawQuery::new(request.query);
        let spec = CanonicalRequestSpec::new(
            request.method,
            &paths,
            &query,
            &canonical_headers,
            &signed,
            request.host,
            request.payload.canonical_payload_token(),
        )
        .for_service(self.service);
        let canonical = spec
            .candidates()?
            .next()
            .ok_or(SignerError::Canonical(crate::AuthError::AuthorizationHeaderMalformed))?;
        let scope = self.credential_scope()?;
        let sts = canonical.string_to_sign_v4a(&request.timestamp, &scope);
        let der_hex = sign_der_hex(&self.key, sts.as_bytes());
        let auth_value = format!(
            "{ALGORITHM_SIGV4A} Credential={}/{}, SignedHeaders={signed_list}, Signature={der_hex}",
            self.access_key_id,
            scope.scope_string()
        );
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|_| SignerError::UnrepresentableHeader)?,
        );
        Ok(SignedRequest::from_parts(
            request.method.clone(),
            request.path.to_owned(),
            request.query.to_owned(),
            headers,
            SigLocation::Header,
            canonical.text().to_owned(),
            sts.text().to_owned(),
            der_hex,
        ))
    }

    /// Signs a presigned SigV4a URL query string with `X-Amz-Region-Set`.
    ///
    /// # Errors
    ///
    /// [`SignerError`] if `expires_seconds` is out of range or request inputs are malformed.
    pub fn presign(&self, request: &SigningRequest<'_>, expires_seconds: u32) -> Result<SignedRequest, SignerError> {
        if expires_seconds == 0 || u64::from(expires_seconds) > crate::MAX_PRESIGNED_EXPIRY_SECONDS {
            return Err(SignerError::ExpiryOutOfRange);
        }
        let mut headers = request.headers.clone();
        headers.remove(http::header::AUTHORIZATION);
        headers.remove(X_AMZ_DATE_HEADER);
        headers.remove(X_AMZ_REGION_SET_HEADER);
        headers.remove(X_AMZ_SECURITY_TOKEN_HEADER);

        let mut names: BTreeSet<String> = headers
            .keys()
            .filter(|name| name.as_str() != "host")
            .map(|name| name.as_str().to_owned())
            .collect();
        names.insert("host".to_owned());
        let signed_list = names.into_iter().collect::<Vec<_>>().join(";");

        let mut canonical_headers = headers.clone();
        canonical_headers.remove(http::header::HOST);
        let signed = SignedHeaderSet::parse_and_enforce(&signed_list, &canonical_headers, request.wire_content_length)?;

        let scope = self.credential_scope()?;
        let credential = format!("{}/{}", self.access_key_id, scope.scope_string());
        let mut query = String::new();
        if !request.query.is_empty() {
            query.push_str(request.query);
            query.push('&');
        }
        query.push_str(X_AMZ_ALGORITHM);
        query.push('=');
        query.push_str(ALGORITHM_SIGV4A);
        query.push('&');
        query.push_str(X_AMZ_CREDENTIAL);
        query.push('=');
        query.push_str(&percent_encode(credential.as_bytes()));
        query.push('&');
        query.push_str(X_AMZ_DATE);
        query.push('=');
        query.push_str(request.timestamp.as_str());
        query.push('&');
        query.push_str(X_AMZ_EXPIRES);
        query.push('=');
        query.push_str(&expires_seconds.to_string());
        query.push('&');
        query.push_str(X_AMZ_REGION_SET);
        query.push('=');
        query.push_str(&percent_encode(self.region_set.as_str().as_bytes()));
        query.push('&');
        query.push_str(X_AMZ_SIGNED_HEADERS);
        query.push('=');
        query.push_str(&percent_encode(signed_list.as_bytes()));
        if let Some(token) = &self.session_token {
            query.push('&');
            query.push_str(X_AMZ_SECURITY_TOKEN);
            query.push('=');
            query.push_str(&percent_encode(token.expose()));
        }

        let paths = UriPathCandidates::new(request.path)?;
        let raw_query = RawQuery::new(&query);
        let spec = CanonicalRequestSpec::new(
            request.method,
            &paths,
            &raw_query,
            &canonical_headers,
            &signed,
            request.host,
            request.payload.canonical_payload_token(),
        )
        .presigned()
        .for_service(self.service);
        let canonical = spec
            .candidates()?
            .next()
            .ok_or(SignerError::Canonical(crate::AuthError::AuthorizationHeaderMalformed))?;
        let sts = canonical.string_to_sign_v4a(&request.timestamp, &scope);
        let der_hex = sign_der_hex(&self.key, sts.as_bytes());
        query.push('&');
        query.push_str(X_AMZ_SIGNATURE);
        query.push('=');
        query.push_str(&der_hex);

        Ok(SignedRequest::from_parts(
            request.method.clone(),
            request.path.to_owned(),
            query,
            headers,
            SigLocation::Query,
            canonical.text().to_owned(),
            sts.text().to_owned(),
            der_hex,
        ))
    }

    /// Creates a [`SigV4aChunkSigner`] seeded from a signed request head.
    #[must_use]
    pub fn chunk_signer(&self, seed_hex: &str, timestamp: AmzDate) -> SigV4aChunkSigner {
        let scope_line = format!("{}/{}/{}", self.date, self.service.as_str(), crate::SCOPE_TERMINATOR);
        SigV4aChunkSigner {
            key: self.key.clone(),
            timestamp,
            scope_line,
            previous: seed_hex.to_owned(),
        }
    }

    fn credential_scope(&self) -> Result<SigV4aCredentialScope, SignerError> {
        let raw = format!(
            "{}/{}/{}/{}",
            self.access_key_id,
            self.date,
            self.service.as_str(),
            crate::SCOPE_TERMINATOR
        );
        Ok(SigV4aCredentialScope::parse(&raw)?)
    }
}

/// Client-side streaming SigV4a chunk and trailer signer.
///
/// Holds the derived P-256 signing key and has no `Debug`, no `PartialEq`, and no key accessor:
///
/// ```compile_fail,E0599
/// use rustfs_gateway_sig::SigV4aChunkSigner;
/// fn leak(signer: &SigV4aChunkSigner) {
///     let _ = signer.expose_key(); // no such method
/// }
/// ```
pub struct SigV4aChunkSigner {
    key: p256::ecdsa::SigningKey,
    timestamp: AmzDate,
    scope_line: String,
    previous: String,
}

impl SigV4aChunkSigner {
    /// The unpadded lowercase-hex DER signature of the previous link in the chain.
    #[must_use]
    pub fn previous_signature_hex(&self) -> &str {
        &self.previous
    }

    /// Signs one chunk (unpadded lowercase hex DER) and advances the chain.
    pub fn sign_chunk(&mut self, data: &[u8]) -> &str {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let sts = format!(
            "{SIGV4A_CHUNK_ALGORITHM}\n{}\n{}\n{}\n{EMPTY_PAYLOAD_SHA256_HEX}\n{}",
            self.timestamp.as_str(),
            self.scope_line,
            self.previous,
            encode_hex_lower(&digest)
        );
        let next = sign_der_hex(&self.key, sts.as_bytes());
        self.previous = next;
        &self.previous
    }

    /// Signs one chunk and returns the 144-char right-`'*'`-padded wire spelling used by AWS CRT.
    pub fn sign_chunk_padded(&mut self, data: &[u8]) -> String {
        pad_sigv4a_hex(self.sign_chunk(data))
    }

    /// Signs the canonical trailing-header block (`name:value\n` lines) and advances the chain.
    pub fn sign_trailer(&mut self, trailer_block: &str) -> &str {
        let digest: [u8; 32] = Sha256::digest(trailer_block.as_bytes()).into();
        let sts = format!(
            "{SIGV4A_TRAILER_ALGORITHM}\n{}\n{}\n{}\n{}",
            self.timestamp.as_str(),
            self.scope_line,
            self.previous,
            encode_hex_lower(&digest)
        );
        let next = sign_der_hex(&self.key, sts.as_bytes());
        self.previous = next;
        &self.previous
    }

    /// Signs the trailer block and returns the 144-char right-`'*'`-padded wire spelling.
    pub fn sign_trailer_padded(&mut self, trailer_block: &str) -> String {
        pad_sigv4a_hex(self.sign_trailer(trailer_block))
    }

    /// Encodes one signed `aws-chunked` frame using unpadded lowercase-hex DER.
    pub fn encode_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        let size = data.len();
        let sig_hex = self.sign_chunk(data).to_owned();
        encode_chunk_frame(size, &sig_hex, data)
    }

    /// Encodes one signed `aws-chunked` frame using AWS CRT 144-char right-`'*'`-padded DER hex.
    pub fn encode_chunk_padded(&mut self, data: &[u8]) -> Vec<u8> {
        let size = data.len();
        let sig_hex = self.sign_chunk_padded(data);
        encode_chunk_frame(size, &sig_hex, data)
    }
}

fn encode_chunk_frame(size: usize, sig_hex: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("{size:x}{CHUNK_SIGNATURE_EXTENSION}{sig_hex}\r\n").into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

fn sign_der_hex(key: &p256::ecdsa::SigningKey, message: &[u8]) -> String {
    let sig: p256::ecdsa::Signature = key.sign(message);
    let der = sig.to_der();
    encode_slice_hex_lower(der.as_bytes())
}

fn encode_slice_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn pad_sigv4a_hex(unpadded: &str) -> String {
    let mut out = String::with_capacity(SIGV4A_PADDED_HEX_LEN);
    out.push_str(unpadded);
    while out.len() < SIGV4A_PADDED_HEX_LEN {
        out.push('*');
    }
    out
}
