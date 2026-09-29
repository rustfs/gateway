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

//! Object integrity: the ten S3 checksum algorithms, `Content-MD5`, and the packed value that
//! carries one of them through the request pipeline.
//!
//! Responsible for: naming the algorithms and their wire headers, parsing and rendering the
//! base64 wire form (including the composite `-N` suffix), selecting *the* checksum header out of
//! a request's header set with the exact error code S3 uses for each way that can go wrong,
//! opening digests through [`Checksummer`], and combining part checksums into a full-object or
//! composite value.
//! NOT responsible for: deciding *where* verification happens — a checksum computed over a body
//! that is still arriving is the P3 ingest pipeline's problem — and for trailer framing, which is
//! `rustfs-gateway-http`.
//! Upstream: [`super::base64`], [`super::error_code`]. Downstream: the P3 ingest pipeline, the
//! multipart family, and every operation that accepts `x-amz-checksum-*`.
//!
//! # Why [`ChecksumSpec`] is packed
//!
//! The obvious shape — one `Option<String>` per algorithm on every input dto — puts eleven
//! pointer-sized options plus their heap tails into a future that is held across four `await`
//! points, and that state machine is copied for every in-flight request. [`ChecksumSpec`] is one
//! fixed-size value instead: the algorithm and the base64 text inline. A compile-time assertion
//! below pins the size, so a future field addition cannot quietly undo it.

use std::fmt;

use crc_fast::CrcAlgorithm;

use super::base64;
use super::checksummer::{self, Checksummer};
use super::error_code::ErrorCode;
use super::parse_error::{ParseError, rules};
use crate::placeholder::WirePlaceholder;

/// The header prefix every algorithm-specific checksum header shares.
const CHECKSUM_PREFIX: &str = "x-amz-checksum-";
/// The header that names the algorithm without carrying a value.
const SDK_ALGORITHM_HEADER: &str = "x-amz-sdk-checksum-algorithm";
/// The header that distinguishes a composite checksum from a full-object one.
const CHECKSUM_TYPE_HEADER: &str = "x-amz-checksum-type";
/// The response-side algorithm name header, which carries no checksum value.
const CHECKSUM_ALGORITHM_HEADER: &str = "x-amz-checksum-algorithm";
/// The read-side opt-in header, which asks for a checksum back and declares none.
const CHECKSUM_MODE_HEADER: &str = "x-amz-checksum-mode";
/// Upper bound on the number of parts, which bounds the `-N` suffix.
const MAX_MULTIPART_PARTS: u32 = 10_000;
/// Inline capacity for the base64 text: base64(SHA-512), the widest digest, is 88 bytes and a
/// composite `-10000` suffix adds 6.
const RAW_CAPACITY: usize = 94;

/// A checksum algorithm S3 accepts on the wire.
///
/// `#[non_exhaustive]` because this set grows: CRC64NVME was added years after the other four, the
/// five after `Sha256` arrived in 2026-04 (rustfs/gateway#751), and a downstream `match` that compiled before that addition must keep compiling after the next one.
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
    /// SHA-512, `x-amz-checksum-sha512`.
    Sha512,
    /// MD5, `x-amz-checksum-md5`. Not `Content-MD5`: see [`ContentMd5`].
    Md5,
    /// XXH64 with seed 0, `x-amz-checksum-xxhash64`.
    XxHash64,
    /// XXH3 64-bit, `x-amz-checksum-xxhash3`.
    XxHash3,
    /// XXH3 128-bit, `x-amz-checksum-xxhash128`.
    XxHash128,
}

impl ChecksumAlgorithm {
    /// Every algorithm: the original five, then the five added in 2026-04 in model order.
    pub const ALL: &'static [Self] = &[
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
        Self::Sha512,
        Self::Md5,
        Self::XxHash64,
        Self::XxHash3,
        Self::XxHash128,
    ];

    /// The lowercase wire header that carries this algorithm's value.
    #[must_use]
    pub fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Sha512 => "x-amz-checksum-sha512",
            Self::Md5 => "x-amz-checksum-md5",
            Self::XxHash64 => "x-amz-checksum-xxhash64",
            Self::XxHash3 => "x-amz-checksum-xxhash3",
            Self::XxHash128 => "x-amz-checksum-xxhash128",
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
            Self::Sha512 => "SHA512",
            Self::Md5 => "MD5",
            Self::XxHash64 => "XXHASH64",
            Self::XxHash3 => "XXHASH3",
            Self::XxHash128 => "XXHASH128",
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
            Self::Crc64Nvme | Self::XxHash64 | Self::XxHash3 => 8,
            Self::Md5 | Self::XxHash128 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Whether the algorithm is a CRC, and therefore composable with
    /// [`ChecksumSpec::combine_full_object`].
    #[must_use]
    pub fn is_crc(self) -> bool {
        matches!(self, Self::Crc32 | Self::Crc32c | Self::Crc64Nvme)
    }

    pub(super) fn crc_algorithm(self) -> Option<CrcAlgorithm> {
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
        checksummer::open(self)
    }

    /// The calculator target `crc-fast` selected for this CRC on the current host.
    ///
    /// This reports the implementation actually selected by `crc-fast`, rather than inferring it
    /// from CPU features. `None` is returned for every algorithm that is not a CRC.
    #[must_use]
    pub fn crc_acceleration_target(self) -> Option<String> {
        self.crc_algorithm().map(crc_fast::get_calculator_target)
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
    bytes: [u8; 64],
    len: u8,
}

impl ChecksumDigest {
    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Default for ChecksumDigest {
    /// A zero-width digest — a placeholder that is **invalid on the wire**, and exists for one
    /// reason.
    ///
    /// ADR-0004 P10: a required member of a generated dto uses a bare type, and every generated
    /// dto derives `Default` so that `..Default::default()` keeps compiling when AWS adds a
    /// member. No algorithm produces a zero-byte digest, so this value cannot be a checksum any
    /// client sent or this implementation computed.
    ///
    /// **The decoding path never produces it.** Treat a value that compares equal to this one as
    /// a bug, never as a digest — in particular, never let one satisfy an integrity check.
    fn default() -> Self {
        Self {
            bytes: [0u8; 64],
            len: 0,
        }
    }
}

impl WirePlaceholder for ChecksumDigest {
    fn is_wire_placeholder(&self) -> bool {
        self.len == 0
    }
}

/// One checksum, packed: the algorithm and the base64 text inline. The checksum type is read off
/// the text rather than stored: a composite value, and only a composite value, carries the `-N`
/// suffix, and base64 has no `-`. That keeps the widest value (a composite SHA-512) inside the budget.
///
/// The stored text is the wire form, including any `-N` composite suffix, so rendering never
/// re-encodes and never has to decide how to spell the suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumSpec {
    algo: ChecksumAlgorithm,
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
        let mut decoded = [0u8; 64];
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
        let spec = Self { algo, raw, len };
        if spec.checksum_type() != kind {
            return Err(ChecksumError::InvalidChecksumValue);
        }
        Ok(spec)
    }

    /// Applies an explicit `x-amz-checksum-type`.
    ///
    /// # Errors
    ///
    /// Returns [`ChecksumError::InvalidChecksumValue`] when the header contradicts the value's own
    /// shape: a `-N` suffix is composite by construction, and a value without one cannot be.
    pub fn with_type(self, kind: ChecksumType) -> Result<Self, ChecksumError> {
        if kind != self.checksum_type() {
            return Err(ChecksumError::InvalidChecksumValue);
        }
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
        if self.raw[..usize::from(self.len)].contains(&b'-') {
            ChecksumType::Composite
        } else {
            ChecksumType::FullObject
        }
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
        if self.checksum_type() != ChecksumType::Composite {
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
        let body = match self.checksum_type() {
            ChecksumType::Composite => value.rsplit_once('-').map_or(value, |(body, _)| body),
            ChecksumType::FullObject => value,
        };
        let mut bytes = [0u8; 64];
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
            .any(|(spec, _)| spec.algo != algo || spec.checksum_type() == ChecksumType::Composite)
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

impl Default for ChecksumSpec {
    /// An empty wire value — a placeholder that is **invalid on the wire**, and exists for one
    /// reason.
    ///
    /// ADR-0004 P10: a required member of a generated dto uses a bare type, and every generated
    /// dto derives `Default` so that `..Default::default()` keeps compiling when AWS adds a
    /// member. [`ChecksumSpec::parse_header`] rejects an empty value, so this cannot be a spec any
    /// header carried. The algorithm it names is arbitrary and carries no meaning; only the empty
    /// value does.
    ///
    /// **The decoding path never produces it.** Treat a value that compares equal to this one as
    /// a bug, never as a checksum — in particular, never let one satisfy an integrity check.
    fn default() -> Self {
        Self {
            algo: ChecksumAlgorithm::Crc32,
            raw: [0u8; RAW_CAPACITY],
            len: 0,
        }
    }
}

impl WirePlaceholder for ChecksumSpec {
    fn is_wire_placeholder(&self) -> bool {
        self.len == 0
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

    /// Opens the streaming digest [`ContentMd5::verify`] expects to be handed.
    ///
    /// It is an associated function of this type and not a free constructor elsewhere so that the
    /// only MD5 a verifier can reach is the one the comparison takes. [`ChecksumAlgorithm::Md5`]
    /// is the `x-amz-checksum-md5` algorithm S3 added in 2026-04; `Content-MD5` stays a separate
    /// protocol feature with its own error codes (`InvalidDigest`, `BadDigest`), so the two are
    /// verified independently when a request carries both.
    #[must_use]
    pub fn digester() -> Md5Digest {
        Md5Digest::default()
    }
}

/// A streaming MD5 over a request body.
///
/// Separate from [`Checksummer`] because its output width is fixed at sixteen bytes and
/// [`ContentMd5::verify`] takes exactly that array: routing it through a `Bytes` of unknown length
/// would put a width check between the digest and the comparison, and a width check that fails
/// open is how a shorter digest ends up compared against a prefix.
#[derive(Default)]
pub struct Md5Digest(md5::Md5);

impl Md5Digest {
    /// Feeds the next run of body bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        md5::Digest::update(&mut self.0, bytes);
    }

    /// Closes the digest.
    #[must_use]
    pub fn finish(self) -> [u8; 16] {
        md5::Digest::finalize(self.0).into()
    }
}

impl fmt::Debug for Md5Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The running state is not rendered: a partial digest of a body is still a fact about the
        // body, and this type appears in the error paths of a request pipeline.
        f.write_str("Md5Digest")
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

/// Whether one request header names a checksum algorithm this build does not implement: an
/// `x-amz-checksum-<name>` header that is neither an algorithm nor one of the three headers that
/// declare no digest, or an `x-amz-sdk-checksum-algorithm` whose value is no algorithm.
///
/// These are exactly the headers [`parse_request_checksum`] refuses with
/// [`ChecksumError::UnknownAlgorithm`]; a caller that must ignore them instead, as legacy RustFS
/// does (rustfs/backlog#1677), leaves them out of what it hands the arbitration.
#[must_use]
pub fn names_unknown_checksum_algorithm(name: &str, value: &str) -> bool {
    if name.eq_ignore_ascii_case(SDK_ALGORITHM_HEADER) {
        return ChecksumAlgorithm::from_wire_name(value).is_none();
    }
    let digestless = [CHECKSUM_TYPE_HEADER, CHECKSUM_ALGORITHM_HEADER, CHECKSUM_MODE_HEADER];
    name.get(..CHECKSUM_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CHECKSUM_PREFIX))
        && !digestless.iter().any(|header| name.eq_ignore_ascii_case(header))
        && ChecksumAlgorithm::from_header_name(name).is_none()
}

/// Picks the one checksum a request declares, out of all its headers.
///
/// **This is the arbitration authority.** Every layer that needs to know which checksum a request
/// claims calls this function; a second implementation of the same decision is how one component
/// verifies a claim another component discarded. `headers` is the request's header list as
/// `(name, value)` pairs, and it is an iterator rather than a slice so a caller holding a borrowed
/// header view can pass it without materialising a `Vec` on the request path.
///
/// Names are matched case-insensitively. The rules encoded here are the ones S3 enforces before a
/// handler runs:
///
/// - two *different* `x-amz-checksum-*` headers are a rejection, not a choice;
/// - a repeated header with an identical value is one header, not two;
/// - `x-amz-sdk-checksum-algorithm` without its value header is a rejection;
/// - `x-amz-checksum-type` must agree with the value's own shape;
/// - a value that is not base64 of the algorithm's width is a rejection, **not** a header to skip.
///
/// Three headers share the `x-amz-checksum-` prefix and declare no digest —
/// `x-amz-checksum-algorithm`, `x-amz-checksum-type` and `x-amz-checksum-mode`. They are named
/// here rather than pattern-matched away: the prefix is otherwise a closed set of algorithms, and
/// an unknown member of it is refused rather than ignored, so a fourth such header added by AWS
/// must arrive as a compile-and-test change and not as a silently accepted unknown.
///
/// # Errors
///
/// See [`ChecksumError`]; every variant returned here maps to `400 InvalidRequest`.
pub fn parse_request_checksum<'a, I>(headers: I) -> Result<Option<ChecksumSpec>, ChecksumError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
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
        if name.eq_ignore_ascii_case(CHECKSUM_ALGORITHM_HEADER) || name.eq_ignore_ascii_case(CHECKSUM_MODE_HEADER) {
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
            Some((seen_algo, seen_value)) if seen_algo != algo || seen_value != value => {
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
