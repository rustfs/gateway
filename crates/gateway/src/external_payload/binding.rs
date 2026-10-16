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

//! Request-local external data binding and signature coverage checks.
//!
//! Responsible for: exact signed extension fields, TLS requirements and logical size bounds.
//! NOT responsible for: parsing private control metadata or performing signature verification.
//! Upstream: trusted host assembly. Downstream: the ordinary facade pipeline and external handlers.

use super::ExternalPayloadError;
use http::{HeaderMap, HeaderName};

/// Exact request fields bound by the ordinary HTTPS SigV4 verification.
///
/// A trusted host obtains these facts from its extension codec. Construction does not authorize
/// a request: the facade requires authenticated SigV4 and both ordinary authorization stages.
#[derive(Clone)]
pub struct ExternalPayloadBinding {
    pub(super) digest: [u8; 32],
    pub(super) length: u64,
    required: HeaderMap,
}
impl ExternalPayloadBinding {
    /// Records a binding digest, logical size bound and the exact extension header values.
    ///
    /// Uploads use an exact length. Downloads may select any response within this bound.
    pub fn new(digest: [u8; 32], length: u64, required: HeaderMap) -> Result<Self, ExternalPayloadError> {
        let bytes: usize = required
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum();
        if required.is_empty()
            || required.len() > 64
            || bytes > 1024 * 1024
            || required.keys().any(|name| !name.as_str().starts_with("x-rustfs-rdma-"))
        {
            return Err(ExternalPayloadError::Transport);
        }
        Ok(Self {
            digest,
            length,
            required,
        })
    }
    /// The request binding supplied by the authenticated private control codec.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// The exact upload size or maximum selected download size.
    #[must_use]
    pub fn length_bound(&self) -> u64 {
        self.length
    }

    pub(super) fn validate_head(&self, headers: &HeaderMap, encrypted: bool, upload: bool) -> Result<(), ExternalPayloadError> {
        if !encrypted || headers.get_all("authorization").iter().count() != 1 {
            return Err(ExternalPayloadError::Transport);
        }
        let authorization = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("AWS4-HMAC-SHA256 "))
            .ok_or(ExternalPayloadError::Transport)?;
        let mut covered = authorization
            .split(',')
            .filter_map(|item| item.trim().strip_prefix("SignedHeaders="));
        let signed = covered.next().ok_or(ExternalPayloadError::Transport)?;
        if covered.next().is_some() {
            return Err(ExternalPayloadError::Transport);
        }
        let names: Vec<&str> = signed.split(';').collect();
        if names.is_empty()
            || names.windows(2).any(|pair| pair.first() >= pair.get(1))
            || names.iter().any(|name| {
                name.is_empty()
                    || name.bytes().any(|byte| byte.is_ascii_uppercase())
                    || HeaderName::from_bytes(name.as_bytes()).is_err()
            })
        {
            return Err(ExternalPayloadError::Transport);
        }
        for name in headers.keys().filter(|name| name.as_str().starts_with("x-rustfs-rdma-")) {
            if !self.required.contains_key(name) || names.binary_search(&name.as_str()).is_err() {
                return Err(ExternalPayloadError::Transport);
            }
        }
        for name in self.required.keys() {
            if headers.get_all(name).iter().ne(self.required.get_all(name).iter()) {
                return Err(ExternalPayloadError::Transport);
            }
        }
        if upload
            && headers
                .get("x-amz-content-sha256")
                .is_none_or(|value| value != "UNSIGNED-PAYLOAD")
        {
            return Err(ExternalPayloadError::Integrity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    fn head() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-rustfs-rdma-binding", HeaderValue::from_static("opaque"));
        headers.insert("x-amz-content-sha256", HeaderValue::from_static("UNSIGNED-PAYLOAD"));
        headers.insert("authorization", HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=key/20261016/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-rustfs-rdma-binding, Signature=abcd"));
        headers
    }
    fn binding() -> Result<ExternalPayloadBinding, ExternalPayloadError> {
        let mut required = HeaderMap::new();
        required.insert("x-rustfs-rdma-binding", HeaderValue::from_static("opaque"));
        ExternalPayloadBinding::new([3; 32], 8, required)
    }
    #[test]
    fn exact_signed_extension_fields_are_accepted() -> Result<(), ExternalPayloadError> {
        assert!(binding()?.validate_head(&head(), true, true).is_ok());
        Ok(())
    }
    #[test]
    fn unsigned_extension_fields_are_rejected() -> Result<(), ExternalPayloadError> {
        let mut headers = head();
        headers.insert("x-rustfs-rdma-extra", HeaderValue::from_static("unbound"));
        assert!(binding()?.validate_head(&headers, true, true).is_err());
        Ok(())
    }
    #[test]
    fn changed_bound_field_is_rejected() -> Result<(), ExternalPayloadError> {
        let mut headers = head();
        headers.insert("x-rustfs-rdma-binding", HeaderValue::from_static("changed"));
        assert!(binding()?.validate_head(&headers, true, true).is_err());
        Ok(())
    }
    #[test]
    fn missing_signature_and_cleartext_are_rejected() -> Result<(), ExternalPayloadError> {
        assert!(binding()?.validate_head(&head(), false, true).is_err());
        let mut headers = head();
        headers.remove("authorization");
        assert!(binding()?.validate_head(&headers, true, true).is_err());
        Ok(())
    }
    #[test]
    fn upload_wire_digest_cannot_replace_logical_validation() -> Result<(), ExternalPayloadError> {
        let mut headers = head();
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
        assert!(binding()?.validate_head(&headers, true, true).is_err());
        Ok(())
    }
    #[test]
    fn ambiguous_duplicate_signed_header_lists_are_rejected() -> Result<(), ExternalPayloadError> {
        let mut headers = head();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=key, SignedHeaders=host;x-rustfs-rdma-binding, SignedHeaders=host, Signature=abcd",
            ),
        );
        assert!(binding()?.validate_head(&headers, true, true).is_err());
        Ok(())
    }
}
