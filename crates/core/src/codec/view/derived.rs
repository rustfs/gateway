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

//! Codec views derived from authenticated metadata and validated body framing.
//!
//! Responsible for: carrying a settled AWS credential location and preserving metadata when
//! framed content length changes the codec's view.
//! NOT responsible for: authenticating credentials, accepting headers, or decoding chunk frames.
//! Upstream: the facade's accepted verdict and framing proof. Downstream: operation codecs.

use rustfs_gateway_sig::{AwsCredentialMarker, SigLocation, Verdict};

use super::MetaView;

impl MetaView<'_> {
    /// Carries the original AWS credential location after the request's authentication settles.
    ///
    /// The assembly must supply the accepted verdict and AWS marker from the same request's
    /// original credential view, before any stage filter rewrites headers. This method neither
    /// parses nor verifies a credential. An anonymous or rejected verdict, missing marker, or
    /// disagreement between the verdict's family/location and marker clears the fact.
    ///
    /// The default view carries no authenticated location. Query and form locations remain
    /// their actual locations; a consumer requiring header authentication must check for Header.
    #[must_use]
    pub fn with_authenticated_aws_marker(mut self, verdict: &Verdict, marker: Option<AwsCredentialMarker>) -> Self {
        self.authenticated_aws_location = match (verdict, marker) {
            (Verdict::Authenticated { scheme, .. }, Some(marker))
                if scheme.family == marker.family() && scheme.location == marker.location() =>
            {
                Some(marker.location())
            }
            _ => None,
        };
        self
    }

    /// The authenticated AWS credential's original location, independent of mutable headers.
    ///
    /// `None` means no matching authenticated AWS fact was installed. It does not distinguish
    /// anonymous admission from a view used before authentication or a non-AWS verifier.
    #[must_use]
    pub const fn authenticated_aws_location(&self) -> Option<SigLocation> {
        self.authenticated_aws_location
    }

    /// This view, with `content-length` answered by an `aws-chunked` body's object length.
    ///
    /// For a framed body the object's size is `x-amz-decoded-content-length`, not the wire
    /// `Content-Length`, which counts the chunk framing too — and which a body the transport ends
    /// (`Transfer-Encoding: chunked`, HTTP/2) does not carry at all. The assembly calls this once,
    /// with the decoded length its ingest layer validated against the signature's payload mode, so
    /// that a codec binding `Content-Length` reads the number the decoder holds the body to
    /// (rustfs/gateway#750). Every other header reads exactly as before.
    #[must_use]
    pub fn with_framed_content_length(&self, length: u64) -> Self {
        Self {
            method: self.method,
            headers: self.headers,
            query: self.query,
            bucket: self.bucket.clone(),
            key: self.key.clone(),
            names: self.names.clone(),
            copy_source_arns_unsupported: self.copy_source_arns_unsupported,
            framed_content_length: Some(length),
            integrity_optional: self.integrity_optional,
            checksum_failures_as_bad_digest: self.checksum_failures_as_bad_digest,
            checksum_reading: self.checksum_reading,
            page_size_ceiling: self.page_size_ceiling,
            ended_empty: self.ended_empty,
            rustfs_listing: self.rustfs_listing,
            strict_date_conditions: self.strict_date_conditions,
            body_literals: self.body_literals,
            empty_headers_absent: self.empty_headers_absent,
            document_reading: self.document_reading,
            rustfs_response_layout: self.rustfs_response_layout,
            document_body_ceiling: self.document_body_ceiling,
            authenticated_aws_location: self.authenticated_aws_location,
        }
    }
}
