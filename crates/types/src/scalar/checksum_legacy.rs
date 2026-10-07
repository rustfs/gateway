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

//! The RustFS-profile reading of a request's checksum declarations: which declarations legacy
//! RustFS ignores and which it refuses (rustfs/gateway#1349).
//!
//! Responsible for: [`legacy_rustfs_request_checksum`], the arbitration the body verification
//! (`rustfs-gateway-http`'s `BodyIntegrity::resolve_as_legacy_rustfs`) runs under the RustFS
//! profile in place of [`super::parse_request_checksum`].
//! NOT responsible for: the default arbitration (unchanged), trailer declarations, `Content-MD5`,
//! binding the claim into an input (the codec's binder reads the same single value header), or
//! comparing a digest.
//! Upstream: [`super::checksum`]. Downstream: `rustfs-gateway-http`.
//!
//! # What legacy RustFS reads
//!
//! Legacy RustFS reads an upload's checksum in its storage reader, from the raw headers
//! (rustfs/rustfs `95268a3b9`, `crates/rio/src/checksum.rs:592-716`), and compares one on no other
//! operation. Measured on a native build of that revision, uploading `hello`:
//!
//! * `x-amz-sdk-checksum-algorithm` is never read: alone `200`; naming another algorithm than the
//!   value header present, the value header is compared (`200` right, `400 BadDigest` wrong);
//! * `x-amz-checksum-type` is read only as `FULL_OBJECT`, which an algorithm that cannot be
//!   combined (SHA-1, SHA-256, SHA-512, MD5, the XXH family) refuses with `400 BadDigest`;
//!   `COMPOSITE` and an unknown type are ignored (`200`);
//! * on an upload, `x-amz-checksum-algorithm` names the algorithm its reader compares: an algorithm
//!   it does not know is `400 BadDigest`, and so is a type other than `FULL_OBJECT`, `COMPOSITE`
//!   or empty beside it, or `FULL_OBJECT` beside an algorithm that cannot be combined.
//!
//! # What the RustFS profile keeps stricter
//!
//! The value header present is always compared, as the default reading compares it — legacy RustFS
//! skips it when `x-amz-checksum-algorithm` names another algorithm (or names none), and stores a
//! body the claim says is corrupt; nothing such is stored here. Two value headers of different
//! algorithms stay refused before the body is read: the operation's input carries one checksum
//! claim, and legacy RustFS hands its handler every one of them (and echoes each on its answer), so
//! accepting two would drop one on the way to RustFS; that stays refused until the input can carry
//! both (rustfs/gateway#1349).

use super::checksum::{ChecksumAlgorithm, ChecksumError, ChecksumSpec};

const CHECKSUM_PREFIX: &str = "x-amz-checksum-";
const CHECKSUM_ALGORITHM_HEADER: &str = "x-amz-checksum-algorithm";
const CHECKSUM_TYPE_HEADER: &str = "x-amz-checksum-type";
const CHECKSUM_MODE_HEADER: &str = "x-amz-checksum-mode";

/// Whether `algorithm` can be combined into a full-object checksum, as legacy RustFS asks it.
fn mergeable(algorithm: ChecksumAlgorithm) -> bool {
    matches!(
        algorithm,
        ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c | ChecksumAlgorithm::Crc64Nvme
    )
}

/// Reads a request's one checksum claim, with its declarations read as the RustFS profile reads
/// them.
///
/// `headers` is the request's header list as `(name, value)` pairs. `reads_algorithm_header` says
/// whether this operation's legacy storage reader reads `x-amz-checksum-algorithm` (an upload:
/// `PutObject`, `UploadPart`, with no trailer declared). A value header naming an algorithm this
/// build does not implement is ignored, as the RustFS profile ignores one everywhere.
///
/// # Errors
///
/// * [`ChecksumError::InvalidChecksumValue`] for a value that is not valid for its algorithm;
/// * [`ChecksumError::MultipleChecksumHeaders`] for two different value headers;
/// * [`ChecksumError::ChecksumMismatch`] where legacy RustFS answers `BadDigest` without comparing:
///   an `x-amz-checksum-algorithm` it does not know, or an `x-amz-checksum-type` it cannot apply.
pub fn legacy_rustfs_request_checksum<'a, I>(
    headers: I,
    reads_algorithm_header: bool,
) -> Result<Option<ChecksumSpec>, ChecksumError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut declared_algorithm: Option<&str> = None;
    let mut declared_type: Option<&str> = None;
    let mut claim: Option<ChecksumSpec> = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(CHECKSUM_ALGORITHM_HEADER) {
            declared_algorithm.get_or_insert(value);
            continue;
        }
        if name.eq_ignore_ascii_case(CHECKSUM_TYPE_HEADER) {
            declared_type.get_or_insert(value);
            continue;
        }
        // `x-amz-sdk-checksum-algorithm` does not share the prefix and is never read here.
        let is_checksum_header = name
            .get(..CHECKSUM_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CHECKSUM_PREFIX));
        if !is_checksum_header || name.eq_ignore_ascii_case(CHECKSUM_MODE_HEADER) {
            continue;
        }
        let Some(algorithm) = ChecksumAlgorithm::from_header_name(name) else {
            continue;
        };
        let spec = ChecksumSpec::parse_header(algorithm.header_name(), value)?;
        match claim {
            Some(existing) if existing != spec => return Err(ChecksumError::MultipleChecksumHeaders),
            _ => claim = Some(spec),
        }
    }
    let full_object = declared_type == Some("FULL_OBJECT");
    match declared_algorithm.filter(|_| reads_algorithm_header) {
        // Legacy-compat (rustfs/backlog#2684): on an upload legacy RustFS reads the algorithm from
        // `x-amz-checksum-algorithm`, which AWS sends only on responses, and answers `BadDigest` —
        // a mismatch code — for a name or a type it cannot read, before comparing anything. The
        // intended future behaviour is AWS's: the request names its algorithm in
        // `x-amz-sdk-checksum-algorithm`, and an unreadable declaration is `InvalidRequest`.
        Some(named) => {
            if !matches!(declared_type, None | Some("" | "FULL_OBJECT" | "COMPOSITE")) {
                return Err(ChecksumError::ChecksumMismatch);
            }
            let algorithm = if named.is_empty() {
                None
            } else {
                Some(ChecksumAlgorithm::from_wire_name(named).ok_or(ChecksumError::ChecksumMismatch)?)
            };
            if full_object && !algorithm.is_some_and(mergeable) {
                return Err(ChecksumError::ChecksumMismatch);
            }
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS refuses a full-object type on an
        // algorithm that cannot be combined with `BadDigest`, a mismatch code, before comparing.
        // The intended future behaviour is `InvalidRequest`.
        None if full_object && claim.is_some_and(|spec| !mergeable(spec.algorithm())) => {
            return Err(ChecksumError::ChecksumMismatch);
        }
        None => {}
    }
    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRC32: (&str, &str) = ("x-amz-checksum-crc32", "NhCmhg==");
    const SHA256: (&str, &str) = ("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
    const FULL: (&str, &str) = ("x-amz-checksum-type", "FULL_OBJECT");

    fn read(headers: &[(&str, &str)], upload: bool) -> Result<Option<ChecksumAlgorithm>, ChecksumError> {
        legacy_rustfs_request_checksum(headers.iter().copied(), upload).map(|spec| spec.map(|spec| spec.algorithm()))
    }

    /// Negative — the SDK algorithm header is never read: alone it claims nothing, beside another
    /// algorithm's value only that value is claimed, a name it does not know is ignored.
    #[test]
    fn n_the_sdk_algorithm_header_is_never_read() {
        assert_eq!(read(&[("x-amz-sdk-checksum-algorithm", "CRC32")], true), Ok(None));
        assert_eq!(
            read(&[("x-amz-sdk-checksum-algorithm", "CRC32"), SHA256], true),
            Ok(Some(ChecksumAlgorithm::Sha256))
        );
        assert_eq!(read(&[("x-amz-sdk-checksum-algorithm", "FOO")], false), Ok(None));
    }

    /// Negative — what legacy refuses as `BadDigest` without comparing: an unknown upload algorithm,
    /// a type it cannot read beside an algorithm, and a full-object type on an algorithm that cannot
    /// be combined, named or claimed.
    #[test]
    fn n_declarations_legacy_refuses_are_a_mismatch() {
        for (headers, upload) in [
            (&[("x-amz-checksum-algorithm", "FOO")][..], true),
            (&[("x-amz-checksum-algorithm", "CRC32"), ("x-amz-checksum-type", "FOO")][..], true),
            (&[("x-amz-checksum-algorithm", "SHA256"), FULL, SHA256][..], true),
            (&[("x-amz-checksum-algorithm", ""), FULL][..], true),
            (&[FULL, SHA256][..], true),
            (&[FULL, SHA256][..], false),
        ] {
            assert_eq!(read(headers, upload), Err(ChecksumError::ChecksumMismatch), "{headers:?} {upload}");
        }
    }

    /// Negative — a value that cannot be read, and two different values, stay refused.
    #[test]
    fn n_unreadable_and_contradicting_values_stay_refused() {
        assert_eq!(read(&[("x-amz-checksum-sha256", "bad")], false), Err(ChecksumError::InvalidChecksumValue));
        assert_eq!(read(&[CRC32, SHA256], true), Err(ChecksumError::MultipleChecksumHeaders));
        assert_eq!(
            read(&[CRC32, ("x-amz-checksum-crc32", "AAAAAA==")], false),
            Err(ChecksumError::MultipleChecksumHeaders)
        );
    }

    /// Positive — what legacy reads without refusing: a type it ignores, a combinable full-object
    /// claim, an unknown algorithm's header, an algorithm header off an upload or naming another
    /// algorithm than the value, a repeated identical value, no claim at all.
    #[test]
    fn declarations_legacy_reads_are_read() {
        for (headers, upload, claimed) in [
            (&[("x-amz-checksum-type", "FOO"), CRC32][..], true, Some(ChecksumAlgorithm::Crc32)),
            (&[("x-amz-checksum-type", "COMPOSITE"), CRC32][..], true, Some(ChecksumAlgorithm::Crc32)),
            (&[FULL, CRC32][..], true, Some(ChecksumAlgorithm::Crc32)),
            (&[FULL][..], true, None),
            (&[("x-amz-checksum-blake3", "AAAA"), CRC32][..], true, Some(ChecksumAlgorithm::Crc32)),
            (&[("x-amz-checksum-algorithm", "FOO"), CRC32][..], false, Some(ChecksumAlgorithm::Crc32)),
            (
                &[("x-amz-checksum-algorithm", "crc32"), SHA256][..],
                true,
                Some(ChecksumAlgorithm::Sha256),
            ),
            (&[CRC32, CRC32][..], false, Some(ChecksumAlgorithm::Crc32)),
            (&[][..], true, None),
        ] {
            assert_eq!(read(headers, upload), Ok(claimed), "{headers:?} {upload}");
        }
    }
}
