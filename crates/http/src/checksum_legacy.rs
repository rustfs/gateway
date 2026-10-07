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

//! The RustFS profile's reading of a request body's integrity claims (rustfs/gateway#1349).
//!
//! Responsible for: [`BodyIntegrity::resolve_as_legacy_rustfs`], the obligations a request body
//! owes when its checksum declarations are read as legacy RustFS reads them — through
//! [`legacy_rustfs_request_checksum`] — with the value claim compared as the default compares it.
//! NOT responsible for: the default reading ([`BodyIntegrity::resolve_reading`]), binding the claim
//! into an input (the codec), or comparing digests (`super::BodyDigests`).
//! Upstream: the assembly that owns the body read, under the RustFS profile. Downstream:
//! `super::BodyDigests`.

use rustfs_gateway_types::{ChecksumAlgorithm, ChecksumType, ContentMd5, legacy_rustfs_request_checksum};

use super::{
    BodyIntegrity, CHECKSUM_TYPE, CONTENT_MD5, ChecksumReject, ChecksumSubject, EmptyIntegrityHeaders, HeaderName, HeaderView,
    X_AMZ_TRAILER, declared_trailer_checksum,
};

impl BodyIntegrity {
    /// Reads every integrity claim a request head carries, its checksum declarations as legacy
    /// RustFS reads them.
    ///
    /// Against [`BodyIntegrity::resolve_reading`]: `x-amz-sdk-checksum-algorithm` is not read, an
    /// `x-amz-checksum-type` legacy RustFS ignores is ignored, an unknown algorithm's value header is
    /// ignored, and — when `reads_algorithm_header` says the operation's legacy storage reader reads
    /// it — an `x-amz-checksum-algorithm` or type that reader cannot apply is refused as a mismatch,
    /// as is a full-object type on a trailer algorithm that cannot be combined. The value claim, two
    /// different value headers, a trailer declaration and `Content-MD5` read as before.
    ///
    /// # Errors
    ///
    /// [`ChecksumReject`] for a value that cannot be read, two different value headers, a
    /// declaration legacy RustFS refuses (`ChecksumMismatch`), and the trailer refusals of
    /// [`BodyIntegrity::resolve_reading`].
    pub fn resolve_as_legacy_rustfs(
        headers: &HeaderView<'_>,
        subject: ChecksumSubject,
        empty: EmptyIntegrityHeaders,
        reads_algorithm_header: bool,
    ) -> Result<Self, ChecksumReject> {
        let absent = |name: &HeaderName, value: &str| {
            empty == EmptyIntegrityHeaders::Absent && value.is_empty() && !headers.is_multi(name)
        };
        let read = |name: &HeaderName| headers.get_str(name).filter(|value| !absent(name, value));
        let trailer_checksum = match headers.get_str(&X_AMZ_TRAILER) {
            Some(value) if absent(&X_AMZ_TRAILER, value) => None,
            _ => declared_trailer_checksum(headers)?,
        };
        // An empty value header claims nothing, as everywhere under `Absent`; the algorithm and type
        // headers are read as sent, empty included, as legacy RustFS's storage reader reads them. A
        // declared trailer's checksum is read alone: no algorithm header is read beside it.
        let declares = |name: &HeaderName| *name == CHECKSUM_TYPE || name.as_str() == "x-amz-checksum-algorithm";
        let checksum = legacy_rustfs_request_checksum(
            headers
                .iter_text()
                .filter(|(name, value)| declares(name) || !absent(name, value))
                .map(|(name, value)| (name.as_str(), value)),
            reads_algorithm_header && trailer_checksum.is_none(),
        )
        .map_err(ChecksumReject::of)?;
        if checksum.is_some() && trailer_checksum.is_some() {
            return Err(ChecksumReject::HeaderAndTrailerBothPresent);
        }
        if trailer_checksum.is_some() && subject != ChecksumSubject::RequestBody {
            return Err(ChecksumReject::TrailerNotAllowed);
        }
        let trailer_type = match read(&CHECKSUM_TYPE) {
            Some(value) if trailer_checksum.is_some() => {
                let kind = ChecksumType::parse(value).map_err(|_| ChecksumReject::InvalidChecksumValue)?;
                // Legacy-compat (rustfs/backlog#2684): legacy RustFS's storage reader refuses a
                // full-object type on a trailer whose algorithm cannot be combined (with `500
                // InternalError`); this refuses it with the mismatch legacy reports for the same
                // declaration on a value header, rather than store a type the algorithm cannot
                // carry. The intended future behaviour is AWS's `InvalidRequest`.
                let combinable = matches!(
                    trailer_checksum,
                    Some(ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c | ChecksumAlgorithm::Crc64Nvme)
                );
                if kind == ChecksumType::FullObject && !combinable {
                    return Err(ChecksumReject::ChecksumMismatch);
                }
                Some(kind)
            }
            _ => None,
        };
        let md5 = match read(&CONTENT_MD5) {
            Some(value) => Some(ContentMd5::parse(value).map_err(ChecksumReject::of)?),
            None => None,
        };
        Ok(match subject {
            ChecksumSubject::RequestBody => Self {
                md5,
                checksum,
                trailer_checksum,
                trailer_type,
            },
            ChecksumSubject::NamedResource => Self {
                md5,
                checksum: None,
                trailer_checksum: None,
                trailer_type: None,
            },
            ChecksumSubject::None => Self::NONE,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use http::{HeaderMap, HeaderValue};

    const HELLO_SHA256: &str = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
    const ZERO_SHA256: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn resolve(lines: &[(&str, &str)], upload: bool) -> Result<BodyIntegrity, ChecksumReject> {
        let mut map = HeaderMap::new();
        for (name, value) in lines {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        BodyIntegrity::resolve_as_legacy_rustfs(
            &HeaderView::new(&map),
            ChecksumSubject::RequestBody,
            EmptyIntegrityHeaders::Absent,
            upload,
        )
    }

    fn verify(lines: &[(&str, &str)], body: &[u8]) -> Result<(), ChecksumReject> {
        let mut digests = resolve(lines, true)?.begin();
        digests.update(body);
        digests.verify().map(|_| ())
    }

    /// Negative — the SDK algorithm header is not read: alone it owes nothing, beside another
    /// algorithm's value that value is compared, and beside a trailer it is not compared with it.
    #[test]
    fn n_the_sdk_algorithm_header_owes_nothing() {
        assert!(
            resolve(&[("x-amz-sdk-checksum-algorithm", "CRC32")], true)
                .expect("read")
                .is_empty()
        );
        let beside = [
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("x-amz-checksum-sha256", ZERO_SHA256),
        ];
        assert_eq!(verify(&beside, b"hello"), Err(ChecksumReject::ChecksumMismatch));
        let right = [
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("x-amz-checksum-sha256", HELLO_SHA256),
        ];
        assert_eq!(verify(&right, b"hello"), Ok(()));
        let trailer = resolve(
            &[
                ("x-amz-sdk-checksum-algorithm", "SHA256"),
                ("x-amz-trailer", "x-amz-checksum-crc32"),
            ],
            true,
        );
        assert!(trailer.is_ok(), "{trailer:?}");
    }

    /// Negative — a declaration legacy refuses on an upload is a mismatch before any byte; off an
    /// upload, and beside a trailer, the algorithm header is not read; a full-object trailer type on
    /// an algorithm that cannot be combined is refused.
    #[test]
    fn n_an_upload_declaration_legacy_refuses_is_a_mismatch() {
        assert_eq!(
            resolve(&[("x-amz-checksum-algorithm", "FOO")], true).err(),
            Some(ChecksumReject::ChecksumMismatch)
        );
        assert!(resolve(&[("x-amz-checksum-algorithm", "FOO")], false).is_ok());
        assert!(resolve(&[("x-amz-checksum-algorithm", "FOO"), ("x-amz-trailer", "x-amz-checksum-crc32")], true).is_ok());
        assert_eq!(
            resolve(
                &[
                    ("x-amz-checksum-type", "FULL_OBJECT"),
                    ("x-amz-trailer", "x-amz-checksum-sha256")
                ],
                true
            )
            .err(),
            Some(ChecksumReject::ChecksumMismatch)
        );
        assert!(
            resolve(
                &[
                    ("x-amz-checksum-type", "FULL_OBJECT"),
                    ("x-amz-trailer", "x-amz-checksum-crc32")
                ],
                true
            )
            .is_ok()
        );
    }

    /// Negative — two different value headers, and a value beside a trailer, stay refused; an empty
    /// value claims nothing; an ignored type leaves the value compared.
    #[test]
    fn n_what_the_default_refuses_besides_stays_refused() {
        assert_eq!(
            resolve(&[("x-amz-checksum-crc32", "NhCmhg=="), ("x-amz-checksum-sha256", HELLO_SHA256)], true).err(),
            Some(ChecksumReject::MultipleChecksumHeaders)
        );
        assert_eq!(
            resolve(
                &[
                    ("x-amz-checksum-crc32", "NhCmhg=="),
                    ("x-amz-trailer", "x-amz-checksum-crc32")
                ],
                true
            )
            .err(),
            Some(ChecksumReject::HeaderAndTrailerBothPresent)
        );
        assert!(resolve(&[("x-amz-checksum-crc32", "")], true).expect("read").is_empty());
        assert_eq!(
            verify(&[("x-amz-checksum-type", "FOO"), ("x-amz-checksum-sha256", ZERO_SHA256)], b"hello"),
            Err(ChecksumReject::ChecksumMismatch)
        );
    }
}
