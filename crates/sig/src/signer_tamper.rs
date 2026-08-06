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

//! The post-signing rewrite: one canonical component, changed after a correct signature exists.
//!
//! Responsible for: [`TamperComponent`] and [`Tamper`] — the mirror of `sign.tamper` in
//! `conformance/case.schema.json` — and the rewrites that put a new value back into whichever
//! surface the component lives on, `Authorization` or the query.
//! NOT responsible for: computing anything. Nothing here signs, hashes or derives; it edits a
//! request that is already signed, which is exactly what makes the resulting case negative.
//! Upstream: [`super::SignedRequest`], whose private fields it edits as a child module.
//! Downstream: `src/signer_tests.rs` and `tests/signer_roundtrip.rs`.

use super::{
    AUTHORIZATION_HEADER, RawQuery, SigLocation, SignedRequest, SignerError, X_AMZ_CONTENT_SHA256_HEADER_NAME, X_AMZ_CREDENTIAL,
    X_AMZ_DATE, X_AMZ_DATE_HEADER, X_AMZ_SIGNATURE, X_AMZ_SIGNED_HEADERS, percent_encode, push_param, set_header,
};

/// Which canonical component a [`Tamper`] rewrites.
///
/// One variant per `sign.tamper.component` value in `conformance/case.schema.json`. The enum is
/// `#[non_exhaustive]` because the schema is the contract and this is the mirror of it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TamperComponent {
    /// The signature itself.
    Signature,
    /// The access key id inside the credential.
    AccessKey,
    /// The day inside the credential scope.
    ScopeDate,
    /// The region inside the credential scope.
    ScopeRegion,
    /// The service inside the credential scope.
    ScopeService,
    /// The `SignedHeaders` list.
    SignedHeadersList,
    /// One query parameter's value; `target` names the parameter.
    CanonicalQuery,
    /// The whole URI path.
    CanonicalPath,
    /// One header's value; `target` names the header.
    CanonicalHeaderValue,
    /// The `x-amz-content-sha256` value.
    PayloadHash,
    /// The signed timestamp, wherever it lives for this signing location.
    DateHeader,
}

/// One post-signing modification: exactly one component, described the way the case schema does.
///
/// `new_value` is required for every component except [`TamperComponent::Signature`] and
/// [`TamperComponent::PayloadHash`], where `flip_byte_at` (defaulting to the first hex digit)
/// produces a value that is still a well-formed digest and still the wrong one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tamper {
    component: TamperComponent,
    target: Option<String>,
    new_value: Option<String>,
    flip_byte_at: Option<usize>,
}

impl Tamper {
    /// Names the component to rewrite.
    #[must_use]
    pub const fn new(component: TamperComponent) -> Self {
        Self {
            component,
            target: None,
            new_value: None,
            flip_byte_at: None,
        }
    }

    /// Which query parameter or header name the component refers to.
    #[must_use]
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_owned());
        self
    }

    /// The replacement value.
    #[must_use]
    pub fn with_new_value(mut self, value: &str) -> Self {
        self.new_value = Some(value.to_owned());
        self
    }

    /// Which hex digit of a digest-shaped value to change.
    #[must_use]
    pub const fn flip_byte_at(mut self, index: usize) -> Self {
        self.flip_byte_at = Some(index);
        self
    }

    /// The component this description names.
    #[must_use]
    pub const fn component(&self) -> TamperComponent {
        self.component
    }

    fn new_value(&self) -> Result<&str, SignerError> {
        self.new_value.as_deref().ok_or(SignerError::TamperNewValueRequired)
    }

    fn target(&self) -> Result<&str, SignerError> {
        self.target.as_deref().ok_or(SignerError::TamperTargetRequired)
    }

    /// The replacement for a digest-shaped value: either the caller's, or one hex digit changed.
    fn mutated(&self, original: &str) -> Result<String, SignerError> {
        if let Some(value) = self.new_value.as_deref() {
            return Ok(value.to_owned());
        }
        let index = self.flip_byte_at.unwrap_or(0);
        let mut bytes = original.as_bytes().to_vec();
        let slot = bytes.get_mut(index).ok_or(SignerError::TamperComponentAbsent)?;
        *slot = if *slot == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).map_err(|_| SignerError::TamperComponentAbsent)
    }

    pub(super) fn apply(&self, signed: &mut SignedRequest) -> Result<(), SignerError> {
        match self.component {
            TamperComponent::Signature => {
                let value = self.mutated(&signed.signature_hex)?;
                signed.signature_hex = value.clone();
                rewrite_signature(signed, &value)
            }
            TamperComponent::AccessKey => rewrite_credential_field(signed, 0, self.new_value()?),
            TamperComponent::ScopeDate => rewrite_credential_field(signed, 1, self.new_value()?),
            TamperComponent::ScopeRegion => rewrite_credential_field(signed, 2, self.new_value()?),
            TamperComponent::ScopeService => rewrite_credential_field(signed, 3, self.new_value()?),
            TamperComponent::SignedHeadersList => rewrite_signed_headers(signed, self.new_value()?),
            TamperComponent::CanonicalQuery => {
                let target = self.target()?;
                signed.query = replace_query_param(&signed.query, target, self.new_value()?);
                Ok(())
            }
            TamperComponent::CanonicalPath => {
                signed.path = self.new_value()?.to_owned();
                Ok(())
            }
            TamperComponent::CanonicalHeaderValue => {
                let target = self.target()?.to_owned();
                set_header(&mut signed.headers, &target, self.new_value()?)
            }
            TamperComponent::PayloadHash => {
                let current = signed
                    .headers
                    .get(X_AMZ_CONTENT_SHA256_HEADER_NAME)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(SignerError::TamperComponentAbsent)?
                    .to_owned();
                let value = self.mutated(&current)?;
                set_header(&mut signed.headers, X_AMZ_CONTENT_SHA256_HEADER_NAME, &value)
            }
            TamperComponent::DateHeader => {
                let value = self.new_value()?;
                match signed.location {
                    SigLocation::Query => {
                        signed.query = replace_query_param(&signed.query, X_AMZ_DATE, value);
                        Ok(())
                    }
                    _ => set_header(&mut signed.headers, X_AMZ_DATE_HEADER, value),
                }
            }
        }
    }
}

/// Replaces one parameter's value, or appends the parameter when it is absent.
///
/// Appending is not a fallback for a missing target: "add a parameter to a URL somebody else
/// signed" is itself one of the attacks a negative case wants to express.
fn replace_query_param(query: &str, name: &str, value: &str) -> String {
    let encoded_name = percent_encode(name.as_bytes());
    let encoded_value = percent_encode(value.as_bytes());
    let mut out = String::with_capacity(query.len() + encoded_value.len());
    let mut replaced = false;
    for component in query.split('&').filter(|component| !component.is_empty()) {
        if !out.is_empty() {
            out.push('&');
        }
        let key = component.split_once('=').map_or(component, |(key, _)| key);
        if key == encoded_name || key == name {
            out.push_str(&encoded_name);
            out.push('=');
            out.push_str(&encoded_value);
            replaced = true;
        } else {
            out.push_str(component);
        }
    }
    if !replaced {
        push_param(&mut out, name, value);
    }
    out
}

/// Rewrites one `/`-separated field of the credential, wherever the credential lives.
fn rewrite_credential_field(signed: &mut SignedRequest, index: usize, value: &str) -> Result<(), SignerError> {
    let current = credential_of(signed)?;
    let mut fields: Vec<&str> = current.split('/').collect();
    let slot = fields.get_mut(index).ok_or(SignerError::TamperComponentAbsent)?;
    *slot = value;
    let rebuilt = fields.join("/");
    set_credential(signed, &rebuilt)
}

fn credential_of(signed: &SignedRequest) -> Result<String, SignerError> {
    match signed.location {
        SigLocation::Query => RawQuery::new(&signed.query)
            .decoded_value(X_AMZ_CREDENTIAL)?
            .ok_or(SignerError::TamperComponentAbsent),
        _ => authorization_field(signed, "Credential="),
    }
}

fn set_credential(signed: &mut SignedRequest, value: &str) -> Result<(), SignerError> {
    match signed.location {
        SigLocation::Query => {
            signed.query = replace_query_param(&signed.query, X_AMZ_CREDENTIAL, value);
            Ok(())
        }
        _ => set_authorization_field(signed, "Credential=", value),
    }
}

fn rewrite_signature(signed: &mut SignedRequest, value: &str) -> Result<(), SignerError> {
    match signed.location {
        SigLocation::Query => {
            signed.query = replace_query_param(&signed.query, X_AMZ_SIGNATURE, value);
            Ok(())
        }
        _ => set_authorization_field(signed, "Signature=", value),
    }
}

fn rewrite_signed_headers(signed: &mut SignedRequest, value: &str) -> Result<(), SignerError> {
    match signed.location {
        SigLocation::Query => {
            signed.query = replace_query_param(&signed.query, X_AMZ_SIGNED_HEADERS, value);
            Ok(())
        }
        _ => set_authorization_field(signed, "SignedHeaders=", value),
    }
}

/// Splits `Authorization` into its algorithm token and its three named components.
///
/// The algorithm is separated first because it is not a named component: `AWS4-HMAC-SHA256
/// Credential=…` would otherwise make the first component's name `AWS4-HMAC-SHA256 Credential`,
/// and a tamper that looked for `Credential=` would silently find nothing.
fn authorization_parts(signed: &SignedRequest) -> Result<(String, Vec<String>), SignerError> {
    let header = signed.authorization().ok_or(SignerError::TamperComponentAbsent)?;
    let (algorithm, rest) = header.split_once(' ').ok_or(SignerError::TamperComponentAbsent)?;
    let components = rest
        .split(AUTHORIZATION_SEPARATOR)
        .map(|component| component.trim_matches(' ').to_owned())
        .collect();
    Ok((algorithm.to_owned(), components))
}

fn authorization_field(signed: &SignedRequest, key: &str) -> Result<String, SignerError> {
    let (_algorithm, components) = authorization_parts(signed)?;
    for component in components {
        if let Some(value) = component.strip_prefix(key) {
            return Ok(value.to_owned());
        }
    }
    Err(SignerError::TamperComponentAbsent)
}

fn set_authorization_field(signed: &mut SignedRequest, key: &str, value: &str) -> Result<(), SignerError> {
    let (algorithm, components) = authorization_parts(signed)?;
    let mut parts: Vec<String> = Vec::with_capacity(components.len());
    let mut replaced = false;
    for component in components {
        if component.starts_with(key) {
            parts.push(format!("{key}{value}"));
            replaced = true;
        } else {
            parts.push(component);
        }
    }
    if !replaced {
        return Err(SignerError::TamperComponentAbsent);
    }
    let rebuilt = format!("{algorithm} {}", parts.join(", "));
    set_header(&mut signed.headers, AUTHORIZATION_HEADER, &rebuilt)
}

/// The separator between `Authorization` components. Spelled once, so the split and the join cannot
/// disagree about it.
const AUTHORIZATION_SEPARATOR: char = ',';
