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

//! Which requests the floor treats as AWS-signed: the sealing predicate's RustFS-profile reading
//! (rustfs/gateway#1130).
//!
//! Responsible for: [`SecurityFloor::recognize_signatures_as_legacy_rustfs`] and the predicate it
//! selects, [`SecurityFloor::credential_marker`].
//! NOT responsible for: what happens to a request once recognised (every rule of the signed path
//! runs as it does for any signed request) or not (the anonymous and custom-scheme paths, which
//! decide it as they decide any unsigned request).
//! Upstream: [`crate::verifier::detect_aws_credential_marker`]. Downstream:
//! `SecurityFloor::admit`.
//!
//! # What legacy RustFS recognises
//!
//! A query string is a presigned URL when it carries the signature — `X-Amz-Signature` for SigV4,
//! `Signature` for SigV2 — and a browser form is signed when it carries `x-amz-signature` or
//! `signature`. A request carrying only the other parameters of a presigned URL
//! (`X-Amz-Credential`, `X-Amz-Algorithm`, `AWSAccessKeyId`, …) is an anonymous request, and is
//! decided as one: legacy RustFS serves it when the bucket admits anonymous access and refuses it
//! with `AccessDenied` otherwise. The gateway's own predicate treats any of those parameters as a
//! signature attempt and refuses the unsigned request as a credential it cannot read.

use super::SecurityFloor;
use crate::floor::WireView;
use crate::query::X_AMZ_SIGNATURE;
use crate::scheme::{SigFamily, SigLocation};
use crate::verifier::{AUTHORIZATION_HEADER, AwsCredentialMarker, SIGV2_SIGNATURE_PARAM, detect_aws_credential_marker};

/// Which requests the floor treats as AWS-signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Recognition {
    /// Any AWS signing parameter, header or field marks a request as signed.
    #[default]
    Aws,
    /// Only a signature marks a query string or a form as signed, as legacy RustFS reads one.
    LegacyRustfs,
}

impl SecurityFloor {
    /// Recognises a presigned URL and a signed browser form only by their signature, as legacy
    /// RustFS does (rustfs/gateway#1130): a query string or a form carrying `X-Amz-Credential`,
    /// `X-Amz-Algorithm`, `AWSAccessKeyId` or the like without `X-Amz-Signature` / `Signature` (or
    /// the form's `x-amz-signature` / `signature`) is an anonymous request, decided as every
    /// anonymous request is — served where the bucket admits anonymous access, refused otherwise.
    ///
    /// Off by default: the gateway treats any AWS signing parameter as a signature attempt and
    /// refuses the unsigned request as a credential it cannot read (`403 InvalidAccessKeyId`, or
    /// `400 AuthorizationQueryParametersError` for an incomplete presigned URL). The switch admits
    /// nothing as signed that was not: a request it no longer treats as signed carries no
    /// signature, is authenticated as nobody, and reaches only what anonymous access reaches; one
    /// carrying a signature, a session token or an `Authorization` header is read exactly as
    /// before.
    #[must_use]
    pub const fn recognize_signatures_as_legacy_rustfs(mut self) -> Self {
        self.recognition = Recognition::LegacyRustfs;
        self
    }

    /// The sealing predicate this floor applies: [`detect_aws_credential_marker`], or legacy
    /// RustFS's reading of it under [`Self::recognize_signatures_as_legacy_rustfs`]: an
    /// `Authorization` header as before; else a query `Signature` (SigV2, which legacy RustFS asks
    /// about first) or `X-Amz-Signature`; else a form's `x-amz-signature` or `signature`.
    pub(super) fn credential_marker(&self, view: &WireView<'_>) -> Option<AwsCredentialMarker> {
        if self.recognition == Recognition::Aws || view.headers().contains_key(AUTHORIZATION_HEADER) {
            return detect_aws_credential_marker(view);
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads presigned parameters without
        // their signature as an anonymous request rather than as a broken credential, so a URL
        // stripped of its signature still reaches whatever anonymous access reaches. Kept: the
        // anonymous reading, which grants nothing anonymous access does not. The intended future
        // behaviour is the default predicate's: refused as a credential it cannot read.
        let (family, location) = if view.query_contains(SIGV2_SIGNATURE_PARAM) {
            (SigFamily::V2, SigLocation::Query)
        } else if view.query_contains(X_AMZ_SIGNATURE) {
            (SigFamily::V4, SigLocation::Query)
        } else if view.form_contains("x-amz-signature") {
            (SigFamily::V4, SigLocation::FormField)
        } else if view.form_contains("signature") {
            (SigFamily::V2, SigLocation::FormField)
        } else {
            return None;
        };
        Some(AwsCredentialMarker::new(family, location))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use http::HeaderMap;

    use super::*;
    use crate::query::RawQuery;

    fn marker(floor: &SecurityFloor, query: &str, form: Option<&[(&str, &str)]>) -> Option<(SigFamily, SigLocation)> {
        let headers = HeaderMap::new();
        let view = WireView::new(&headers, RawQuery::new(query));
        let view = match form {
            Some(fields) => view.with_form_fields(fields),
            None => view,
        };
        floor.credential_marker(&view).map(|found| (found.family(), found.location()))
    }

    /// Positive — under the legacy reading a signature still marks a query string or a form as
    /// signed, SigV2's `Signature` first, as legacy RustFS asks; and an `Authorization` header is
    /// read as before.
    #[test]
    fn a_signature_marks_a_request_as_signed() {
        let floor = SecurityFloor::new().recognize_signatures_as_legacy_rustfs();
        assert_eq!(
            marker(&floor, "X-Amz-Signature=abc&X-Amz-Credential=a", None),
            Some((SigFamily::V4, SigLocation::Query))
        );
        assert_eq!(
            marker(&floor, "X-Amz-Signature=abc&Signature=def", None),
            Some((SigFamily::V2, SigLocation::Query))
        );
        assert_eq!(
            marker(&floor, "", Some(&[("x-amz-signature", "abc")])),
            Some((SigFamily::V4, SigLocation::FormField))
        );
        assert_eq!(
            marker(&floor, "", Some(&[("signature", "abc")])),
            Some((SigFamily::V2, SigLocation::FormField))
        );
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION_HEADER, http::HeaderValue::from_static("AWS4-HMAC-SHA256 x"));
        let view = WireView::new(&headers, RawQuery::new("X-Amz-Credential=a"));
        assert_eq!(floor.credential_marker(&view).map(|found| found.location()), Some(SigLocation::Header));
    }

    /// Negative — under the legacy reading the other parameters of a presigned URL or a signed
    /// form mark nothing; under the default they are a signature attempt.
    #[test]
    fn n_the_other_parameters_mark_nothing_under_the_legacy_reading() {
        let legacy = SecurityFloor::new().recognize_signatures_as_legacy_rustfs();
        let aws = SecurityFloor::new();
        for query in [
            "X-Amz-Credential=a",
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "AWSAccessKeyId=a&Expires=1",
        ] {
            assert_eq!(marker(&legacy, query, None), None, "{query}");
            assert!(marker(&aws, query, None).is_some(), "{query}");
        }
        for field in ["x-amz-credential", "x-amz-algorithm", "AWSAccessKeyId"] {
            let fields: &[(&str, &str)] = &[(field, "a")];
            assert_eq!(marker(&legacy, "", Some(fields)), None, "{field}");
            assert!(marker(&aws, "", Some(fields)).is_some(), "{field}");
        }
    }
}
