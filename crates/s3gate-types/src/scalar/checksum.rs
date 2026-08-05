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

//! Object integrity: the five S3 checksum algorithms, `Content-MD5`, and the packed value that
//! carries one of them through the request pipeline.
//!
//! Responsible for: naming the algorithms and their wire headers, parsing and rendering the
//! base64 wire form (including the composite `-N` suffix), selecting *the* checksum header out of
//! a request's header set with the exact error code S3 uses for each way that can go wrong,
//! computing digests through [`Checksummer`], and combining part checksums into a full-object or
//! composite value.
//! NOT responsible for: deciding *where* verification happens — a checksum computed over a body
//! that is still arriving is the P3 ingest pipeline's problem — and for trailer framing, which is
//! `s3gate-http`.
//! Upstream: [`super::base64`], [`super::error_code`]. Downstream: the P3 ingest pipeline, the
//! multipart family, and every operation that accepts `x-amz-checksum-*`.
//!
//! # Why [`ChecksumSpec`] is packed
//!
//! The obvious shape — one `Option<String>` per algorithm on every input dto — puts eleven
//! pointer-sized options plus their heap tails into a future that is held across four `await`
//! points, and that state machine is copied for every in-flight request. [`ChecksumSpec`] is one
//! fixed-size value instead: algorithm, type, and the base64 text inline. A compile-time assertion
//! below pins the size, so a future field addition cannot quietly undo it.

use std::fmt;

use bytes::Bytes;
use crc_fast::CrcAlgorithm;
use sha1::Sha1;
use sha2::Sha256;

use super::base64;
use super::error_code::ErrorCode;
use super::parse_error::{ParseError, rules};

/// The header prefix every algorithm-specific checksum header shares.
const CHECKSUM_PREFIX: &str = "x-amz-checksum-";
/// The header that names the algorithm without carrying a value.
const SDK_ALGORITHM_HEADER: &str = "x-amz-sdk-checksum-algorithm";
/// The header that distinguishes a composite checksum from a full-object one.
const CHECKSUM_TYPE_HEADER: &str = "x-amz-checksum-type";
/// The response-side algorithm name header, which carries no checksum value.
const CHECKSUM_ALGORITHM_HEADER: &str = "x-amz-checksum-algorithm";
/// Upper bound on the number of parts, which bounds the `-N` suffix.
const MAX_MULTIPART_PARTS: u32 = 10_000;
/// Inline capacity for the base64 text: base64(SHA-256) is 44 bytes, `-10000` adds 6, and the
/// remainder is headroom for an algorithm with a wider digest.
const RAW_CAPACITY: usize = 88;

/// A checksum algorithm S3 accepts on the wire.
///
/// `#[non_exhaustive]` because this set grows: CRC64NVME was added years after the other four, and
/// a downstream `match` that compiled before that addition must keep compiling after the next one.
/// It is a real `enum` rather than the `Cow` newtype the string-enumeration policy prescribes,
/// because it is the discriminant inside [`ChecksumSpec`] and must stay one byte wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChecksumAlgorithm {
    /// CRC-32/ISO-HDLC, `x-amz-checksum-crc32`.
    Crc32,
    /// CRC-32/ISCSI (Castagnoli), `x-amz-checksum-crc32c`.
    Crc32c,
    /// CRC-64/NVME, `x-amz-checksum-crc64nvme`.
    Crc64Nvme,
    /// SHA-1, `x-amz-checksum-sha1`.
    Sha1,
    /// SHA-256, `x-amz-checksum-sha256`.
    Sha256,
}

impl ChecksumAlgorithm {
    /// Every algorithm, in the order the AWS documentation lists them.
    pub const ALL: &'static [Self] = &[Self::Crc32, Self::Crc32c, Self::Crc64Nvme, Self::Sha1, Self::Sha256];

    /// The lowercase wire header that carries this algorithm's value.
    #[must_use]
    pub fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// The uppercase spelling used by `x-amz-sdk-checksum-algorithm` and the XML enumerations.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    /// Resolves a header name, case-insensitively.
    #[must_use]
    pub fn from_header_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|algo| algo.header_name().eq_ignore_ascii_case(name))
    }

    /// Resolves the `CRC32` / `SHA256` style spelling, case-insensitively.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|algo| algo.wire_name().eq_ignore_ascii_case(name))
    }

    /// The digest width in bytes. A value whose base64 decodes to any other length is not a
    /// checksum of this algorithm, whatever the header name claimed.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme => 8,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Whether the algorithm is a CRC, and therefore composable with
    /// [`ChecksumSpec::combine_full_object`].
    #[must_use]
    pub fn is_crc(self) -> bool {
        matches!(self, Self::Crc32 | Self::Crc32c | Self::Crc64Nvme)
    }

    fn crc_algorithm(self) -> Option<CrcAlgorithm> {
        match self {
            Self::Crc32 => Some(CrcAlgorithm::Crc32IsoHdlc),
            Self::Crc32c => Some(CrcAlgorithm::Crc32Iscsi),
            Self::Crc64Nvme => Some(CrcAlgorithm::Crc64Nvme),
            _ => None,
        }
    }

    /// Opens a streaming digest for this algorithm.
    #[must_use]
    pub fn checksummer(self) -> Box<dyn Checksummer> {
        match self {
            Self::Sha1 => Box::new(RustCryptoChecksummer::<Sha1>::default()),
            Self::Sha256 => Box::new(RustCryptoChecksummer::<Sha256>::default()),
            other => Box::new(CrcChecksummer::new(other)),
        }
    }
}

impl fmt::Display for ChecksumAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// Whether a multipart checksum is the checksum of the part checksums, or of the whole object.
///
/// Exhaustive: `x-amz-checksum-type` has exactly these two values, and a third would change the
/// meaning of every stored multipart checksum, so it must not slip in unnoticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ChecksumType {
    /// The checksum of the concatenated part checksums, spelled with a `-N` suffix.
    Composite,
    /// The checksum of the object's bytes, identical however the object was uploaded.
    #[default]
    FullObject,
}

impl ChecksumType {
    /// The `x-amz-checksum-type` wire spelling.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Composite => "COMPOSITE",
            Self::FullObject => "FULL_OBJECT",
        }
    }

    /// Parses `x-amz-checksum-type`.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] for any other value; an unrecognised checksum type must not be
    /// silently treated as full-object, because that changes what the stored checksum means.
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        match value {
            "COMPOSITE" => Ok(Self::Composite),
            "FULL_OBJECT" => Ok(Self::FullObject),
            _ => Err(ParseError::new(
                "ChecksumType",
                rules::AWS_CHECKSUM,
                "checksum type must be COMPOSITE or FULL_OBJECT",
            )),
        }
    }
}

/// A decoded digest, sized for the widest algorithm so that reading one allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumDigest {
    bytes: [u8; 32],
    len: u8,
}

impl ChecksumDigest {
    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// One checksum, packed: algorithm, type, and the base64 text inline.
///
/// The stored text is the wire form, including any `-N` composite suffix, so rendering never
/// re-encodes and never has to decide how to spell the suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumSpec {
    algo: ChecksumAlgorithm,
    kind: ChecksumType,
    raw: [u8; RAW_CAPACITY],
    len: u8,
}

// The performance review fixed this budget: `Req<O>` stays small only if the checksum members do
// not grow back into a pile of `Option<String>`.
const _: () = assert!(size_of::<ChecksumSpec>() <= 96);

impl ChecksumSpec {
    /// Builds a full-object checksum from raw digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChecksumError::InvalidChecksumValue`] when the digest width does not match the
    /// algorithm.
    pub fn from_digest(algo: ChecksumAlgorithm, digest: &[u8]) -> Result<Self, ChecksumError> {
        if digest.len() != algo.digest_len() {
            return Err(ChecksumError::InvalidChecksumValue);
        }
        Self::from_wire(algo, ChecksumType::FullObject, &base64::encode(digest))
    }

    /// Parses one `x-amz-checksum-<algo>` header.
    ///
    /// The composite form (`<base64>-<N>`) is recognised here, so a caller that has only the one
    /// header still learns the checksum type. An explicit `x-amz-checksum-type` header refines it
    /// through [`ChecksumSpec::with_type`].
    ///
    /// # Errors
    ///
    /// [`ChecksumError::UnknownAlgorithm`] when the header name is not a checksum header, and
    /// [`ChecksumError::InvalidChecksumValue`] when the value is not base64 of the right width, or
    /// carries a part count outside `1..=10000`.
    pub fn parse_header(name: &str, value: &str) -> Result<Self, ChecksumError> {
        let algo = ChecksumAlgorithm::from_header_name(name).ok_or(ChecksumError::UnknownAlgorithm)?;
        let (body, kind) = match value.rsplit_once('-') {
            Some((body, count)) => {
                let valid = !count.starts_with('0') && count.parse::<u32>().is_ok_and(|n| (1..=MAX_MULTIPART_PARTS).contains(&n));
                if !valid {
                    return Err(ChecksumError::InvalidChecksumValue);
                }
                (body, ChecksumType::Composite)
            }
            None => (value, ChecksumType::FullObject),
        };
        // The digest width is checked against the algorithm, which is what makes a CRC32 header
        // carrying a SHA-256 value a rejection rather than a silently accepted mismatch.
        let mut decoded = [0u8; 32];
        let written = base64::decode_into("Checksum", body, &mut decoded).map_err(|_| ChecksumError::InvalidChecksumValue)?;
        if written != algo.digest_len() {
            return Err(ChecksumError::InvalidChecksumValue);
        }
        Self::from_wire(algo, kind, value)
    }

    fn from_wire(algo: ChecksumAlgorithm, kind: ChecksumType, value: &str) -> Result<Self, ChecksumError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > RAW_CAPACITY || !value.is_ascii() {
            return Err(ChecksumError::InvalidChecksumValue);
        }
        let mut raw = [0u8; RAW_CAPACITY];
        raw[..bytes.len()].copy_from_slice(bytes);
        let len = u8::try_from(bytes.len()).map_err(|_| ChecksumError::InvalidChecksumValue)?;
        Ok(Self { algo, kind, raw, len })
    }

    /// Applies an explicit `x-amz-checksum-type`.
    ///
    /// # Errors
    ///
    /// Returns [`ChecksumError::InvalidChecksumValue`] when the header contradicts the value's own
    /// shape: a `-N` suffix is composite by construction, and a value without one cannot be.
    pub fn with_type(mut self, kind: ChecksumType) -> Result<Self, ChecksumError> {
        if kind != self.kind {
            return Err(ChecksumError::InvalidChecksumValue);
        }
        self.kind = kind;
        Ok(self)
    }

    /// The algorithm this checksum was computed with.
    #[must_use]
    pub fn algorithm(&self) -> ChecksumAlgorithm {
        self.algo
    }

    /// Whether the value is composite or full-object.
    #[must_use]
    pub fn checksum_type(&self) -> ChecksumType {
        self.kind
    }

    /// The wire value, base64 plus any `-N` suffix.
    #[must_use]
    pub fn render_base64(&self) -> &str {
        // `raw[..len]` is only ever written from an ASCII value that was validated on the way in;
        // the fallback keeps this total rather than introducing a panic path on a hot accessor.
        std::str::from_utf8(&self.raw[..usize::from(self.len)]).unwrap_or("")
    }

    /// The part count of a composite checksum, or `None` for a full-object one.
    #[must_use]
    pub fn part_count(&self) -> Option<u32> {
        if self.kind != ChecksumType::Composite {
            return None;
        }
        self.render_base64().rsplit_once('-')?.1.parse().ok()
    }

    /// Decodes the digest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChecksumError::InvalidChecksumValue`] only if the stored value was corrupted
    /// after construction, which the constructors make unreachable.
    pub fn digest(&self) -> Result<ChecksumDigest, ChecksumError> {
        let value = self.render_base64();
        let body = match self.kind {
            ChecksumType::Composite => value.rsplit_once('-').map_or(value, |(body, _)| body),
            ChecksumType::FullObject => value,
        };
        let mut bytes = [0u8; 32];
        let written = base64::decode_into("Checksum", body, &mut bytes).map_err(|_| ChecksumError::InvalidChecksumValue)?;
        let len = u8::try_from(written).map_err(|_| ChecksumError::InvalidChecksumValue)?;
        Ok(ChecksumDigest { bytes, len })
    }

    /// Combines per-part CRCs into the full-object CRC of the concatenation.
    ///
    /// Each entry is a part's checksum together with that part's length in bytes, which the CRC
    /// combination needs. This is what makes a full-object checksum available after a multipart
    /// upload without re-reading a single byte.
    ///
    /// # Errors
    ///
    /// [`ChecksumError::NotCombinable`] for an empty input, a non-CRC algorithm, a composite
    /// input, or parts that disagree about the algorithm.
    pub fn combine_full_object(parts: &[(Self, u64)]) -> Result<Self, ChecksumError> {
        let Some(((first, _), rest)) = parts.split_first() else {
            return Err(ChecksumError::NotCombinable);
        };
        let algo = first.algo;
        let crc_algo = algo.crc_algorithm().ok_or(ChecksumError::NotCombinable)?;
        if parts
            .iter()
            .any(|(spec, _)| spec.algo != algo || spec.kind == ChecksumType::Composite)
        {
            return Err(ChecksumError::NotCombinable);
        }

        let mut acc = crc_value(first)?;
        for (spec, len) in rest {
            acc = crc_fast::checksum_combine(crc_algo, acc, crc_value(spec)?, *len);
        }
        let width = algo.digest_len();
        let bytes = acc.to_be_bytes();
        Self::from_digest(algo, &bytes[8 - width..])
    }

    /// Builds the composite checksum of a multipart upload: the checksum of the concatenated part
    /// digests, suffixed with the part count.
    ///
    /// # Errors
    ///
    /// [`ChecksumError::NotCombinable`] when there are no parts, more than 10,000 of them, or the
    /// parts disagree about the algorithm.
    pub fn composite_of(parts: &[Self]) -> Result<Self, ChecksumError> {
        let Some(first) = parts.first() else {
            return Err(ChecksumError::NotCombinable);
        };
        let algo = first.algo;
        let count = u32::try_from(parts.len()).unwrap_or(u32::MAX);
        if count > MAX_MULTIPART_PARTS || parts.iter().any(|spec| spec.algo != algo) {
            return Err(ChecksumError::NotCombinable);
        }

        let mut hasher = algo.checksummer();
        for spec in parts {
            hasher.update(spec.digest()?.as_bytes());
        }
        let digest = hasher.finalize();
        let value = format!("{}-{count}", base64::encode(&digest));
        Self::from_wire(algo, ChecksumType::Composite, &value)
    }
}

fn crc_value(spec: &ChecksumSpec) -> Result<u64, ChecksumError> {
    let digest = spec.digest()?;
    let mut wide = [0u8; 8];
    let bytes = digest.as_bytes();
    if bytes.len() > 8 {
        return Err(ChecksumError::NotCombinable);
    }
    wide[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(wide))
}

/// A `Content-MD5` value.
///
/// Kept apart from [`ChecksumAlgorithm`] because it is a different protocol feature with different
/// error codes: a malformed value is `InvalidDigest`, a mismatch is `BadDigest`, and neither is
/// the `XAmzContentChecksumMismatch` that an `x-amz-checksum-*` mismatch produces. When both are
/// present both are verified, and each reports its own code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentMd5([u8; 16]);

impl ContentMd5 {
    /// Parses the base64 header value.
    ///
    /// # Errors
    ///
    /// [`ChecksumError::InvalidDigest`] when the value is not base64 of exactly sixteen bytes.
    pub fn parse(value: &str) -> Result<Self, ChecksumError> {
        let mut digest = [0u8; 16];
        let written = base64::decode_into("Content-MD5", value, &mut digest).map_err(|_| ChecksumError::InvalidDigest)?;
        if written != 16 {
            return Err(ChecksumError::InvalidDigest);
        }
        Ok(Self(digest))
    }

    /// The expected digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Checks the digest of the received body against this value.
    ///
    /// # Errors
    ///
    /// [`ChecksumError::BadDigest`] on a mismatch.
    pub fn verify(&self, actual: &[u8; 16]) -> Result<(), ChecksumError> {
        if &self.0 == actual {
            Ok(())
        } else {
            Err(ChecksumError::BadDigest)
        }
    }
}

/// Everything that can go wrong with a checksum, paired with the code S3 reports for it.
///
/// `#[non_exhaustive]`: the variants are matched by callers but constructed here, and new
/// integrity features have historically arrived with new error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumError {
    /// More than one distinct `x-amz-checksum-*` header was sent.
    MultipleChecksumHeaders,
    /// `x-amz-sdk-checksum-algorithm` named an algorithm whose value header is absent.
    AlgorithmDeclaredWithoutValue,
    /// The header is not a checksum header this implementation knows.
    UnknownAlgorithm,
    /// The value is not base64, is the wrong width for its algorithm, or has a bad `-N` suffix.
    InvalidChecksumValue,
    /// `Content-MD5` is not valid base64 of sixteen bytes.
    InvalidDigest,
    /// `Content-MD5` did not match the body.
    BadDigest,
    /// An `x-amz-checksum-*` value did not match the body.
    ChecksumMismatch,
    /// The parts cannot be combined: wrong algorithm, mixed algorithms, or none supplied.
    NotCombinable,
}

impl ChecksumError {
    /// The S3 error code a client sees for this failure.
    ///
    /// The three mismatch codes are deliberately distinct. Clients branch on them: `BadDigest`
    /// tells an uploader its `Content-MD5` was wrong, `XAmzContentChecksumMismatch` tells it the
    /// newer checksum header was wrong, and collapsing them loses the distinction the SDKs use to
    /// decide what to retry.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidDigest => ErrorCode::INVALID_DIGEST,
            Self::BadDigest => ErrorCode::BAD_DIGEST,
            Self::ChecksumMismatch => ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH,
            _ => ErrorCode::INVALID_REQUEST,
        }
    }

    /// The message S3 sends alongside the code.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::MultipleChecksumHeaders => "Expecting a single x-amz-checksum- header",
            Self::AlgorithmDeclaredWithoutValue => {
                "The algorithm named by x-amz-sdk-checksum-algorithm has no corresponding checksum header"
            }
            Self::UnknownAlgorithm => "The checksum algorithm is not supported",
            Self::InvalidChecksumValue => "The checksum value is not valid for the named algorithm",
            Self::InvalidDigest => "The Content-MD5 you specified is not valid",
            Self::BadDigest => "The Content-MD5 you specified did not match what we received",
            Self::ChecksumMismatch => "The checksum you specified did not match what we received",
            Self::NotCombinable => "These part checksums cannot be combined",
        }
    }
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ChecksumError {}

/// Picks the one checksum a request declares, out of all its headers.
///
/// `headers` is the request's header list as `(name, value)` pairs; names are matched
/// case-insensitively. The rules encoded here are the ones S3 enforces before a handler runs:
///
/// - two *different* `x-amz-checksum-*` headers are a rejection, not a choice;
/// - a repeated header with an identical value is one header, not two;
/// - `x-amz-sdk-checksum-algorithm` without its value header is a rejection;
/// - `x-amz-checksum-type` must agree with the value's own shape.
///
/// # Errors
///
/// See [`ChecksumError`]; every variant returned here maps to `400 InvalidRequest`.
pub fn parse_request_checksum(headers: &[(&str, &str)]) -> Result<Option<ChecksumSpec>, ChecksumError> {
    let mut found: Option<(ChecksumAlgorithm, &str)> = None;
    let mut declared: Option<ChecksumAlgorithm> = None;
    let mut declared_type: Option<ChecksumType> = None;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case(SDK_ALGORITHM_HEADER) {
            declared = Some(ChecksumAlgorithm::from_wire_name(value).ok_or(ChecksumError::UnknownAlgorithm)?);
            continue;
        }
        if name.eq_ignore_ascii_case(CHECKSUM_TYPE_HEADER) {
            declared_type = Some(ChecksumType::parse(value).map_err(|_| ChecksumError::InvalidChecksumValue)?);
            continue;
        }
        if name.eq_ignore_ascii_case(CHECKSUM_ALGORITHM_HEADER) {
            continue;
        }
        let is_checksum_header = name
            .get(..CHECKSUM_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CHECKSUM_PREFIX));
        if !is_checksum_header {
            continue;
        }
        let algo = ChecksumAlgorithm::from_header_name(name).ok_or(ChecksumError::UnknownAlgorithm)?;
        match found {
            Some((seen_algo, seen_value)) if seen_algo != algo || seen_value != *value => {
                return Err(ChecksumError::MultipleChecksumHeaders);
            }
            _ => found = Some((algo, value)),
        }
    }

    let Some((algo, value)) = found else {
        return match declared {
            Some(_) => Err(ChecksumError::AlgorithmDeclaredWithoutValue),
            None => Ok(None),
        };
    };
    if declared.is_some_and(|d| d != algo) {
        return Err(ChecksumError::AlgorithmDeclaredWithoutValue);
    }

    let spec = ChecksumSpec::parse_header(algo.header_name(), value)?;
    match declared_type {
        Some(kind) => spec.with_type(kind).map(Some),
        None => Ok(Some(spec)),
    }
}

/// A streaming digest.
///
/// Hand-written rather than reusing a `digest` trait because the CRC backend and the SHA backends
/// are built against two different major versions of `digest`, which coexist in the tree but share
/// no trait. Object safety matters: the ingest pipeline stores one of these per in-flight request
/// without knowing the algorithm at compile time.
pub trait Checksummer: Send + Sync {
    /// Feeds the next slice of the payload.
    fn update(&mut self, buf: &[u8]);
    /// Consumes the digest and returns it in wire byte order.
    fn finalize(self: Box<Self>) -> Bytes;
    /// The digest width in bytes.
    fn size(&self) -> u64;
}

struct CrcChecksummer {
    algo: ChecksumAlgorithm,
    digest: crc_fast::Digest,
}

impl CrcChecksummer {
    fn new(algo: ChecksumAlgorithm) -> Self {
        // `crc_algorithm` is total over the CRC variants; ISO-HDLC is a safe stand-in that can
        // only be reached if a non-CRC algorithm were routed here, which the caller prevents.
        let crc = algo.crc_algorithm().unwrap_or(CrcAlgorithm::Crc32IsoHdlc);
        Self {
            algo,
            digest: crc_fast::Digest::new(crc),
        }
    }
}

impl Checksummer for CrcChecksummer {
    fn update(&mut self, buf: &[u8]) {
        self.digest.update(buf);
    }

    fn finalize(self: Box<Self>) -> Bytes {
        let width = self.algo.digest_len();
        let value = self.digest.finalize();
        Bytes::copy_from_slice(&value.to_be_bytes()[8 - width..])
    }

    fn size(&self) -> u64 {
        self.algo.digest_len() as u64
    }
}

#[derive(Default)]
struct RustCryptoChecksummer<D: sha2::Digest + Send + Sync + Default> {
    inner: D,
}

impl<D: sha2::Digest + Send + Sync + Default + 'static> Checksummer for RustCryptoChecksummer<D> {
    fn update(&mut self, buf: &[u8]) {
        sha2::Digest::update(&mut self.inner, buf);
    }

    fn finalize(self: Box<Self>) -> Bytes {
        Bytes::copy_from_slice(&self.inner.finalize())
    }

    fn size(&self) -> u64 {
        <D as sha2::Digest>::output_size() as u64
    }
}
