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

//! Streaming digests for the ten S3 checksum algorithms.
//!
//! Responsible for: the object-safe [`Checksummer`] trait and one backend per algorithm family —
//! `crc-fast` for the three CRCs, RustCrypto for SHA-1, SHA-256, SHA-512 and MD5, and `twox-hash`
//! for the three XXHash variants — each finalising to the wire byte order S3 uses.
//! NOT responsible for: which algorithm a request names, parsing or rendering a value, or comparing
//! a digest against a claim ([`super::checksum`] owns all three).
//! Upstream: [`super::checksum::ChecksumAlgorithm`], which is the only caller of [`open`].
//! Downstream: the ingest pipeline in `rustfs-gateway-http`, through
//! [`super::checksum::ChecksumAlgorithm::checksummer`].
//!
//! # Byte order
//!
//! The CRCs and the XXHash values are integers, and S3 renders every integer digest big-endian
//! before base64. The hash functions (SHA-*, MD5) already produce bytes, which are passed through.

use std::hash::Hasher as _;

use bytes::Bytes;
use crc_fast::CrcAlgorithm;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use twox_hash::{XxHash3_64, XxHash3_128, XxHash64};

use super::checksum::ChecksumAlgorithm;

/// A streaming digest.
///
/// Hand-written rather than reusing a `digest` trait because the CRC backend, the RustCrypto
/// backends and the XXHash backend share no trait. Object safety matters: the ingest pipeline
/// stores one of these per in-flight request without knowing the algorithm at compile time.
pub trait Checksummer: Send + Sync {
    /// Feeds the next slice of the payload.
    fn update(&mut self, buf: &[u8]);
    /// Consumes the digest and returns it in wire byte order.
    fn finalize(self: Box<Self>) -> Bytes;
    /// The digest width in bytes.
    fn size(&self) -> u64;
}

/// Opens the streaming digest for `algo`.
pub(super) fn open(algo: ChecksumAlgorithm) -> Box<dyn Checksummer> {
    match algo {
        ChecksumAlgorithm::Sha1 => Box::new(RustCryptoChecksummer::<Sha1>::default()),
        ChecksumAlgorithm::Sha256 => Box::new(RustCryptoChecksummer::<Sha256>::default()),
        ChecksumAlgorithm::Sha512 => Box::new(RustCryptoChecksummer::<Sha512>::default()),
        ChecksumAlgorithm::Md5 => Box::new(RustCryptoChecksummer::<Md5>::default()),
        // S3's XXHASH64 is XXH64 with seed 0; XXHASH3 and XXHASH128 are the unseeded XXH3 64-bit
        // and 128-bit variants.
        ChecksumAlgorithm::XxHash64 => Box::new(XxChecksummer::H64(XxHash64::with_seed(0))),
        ChecksumAlgorithm::XxHash3 => Box::new(XxChecksummer::H3(XxHash3_64::new())),
        ChecksumAlgorithm::XxHash128 => Box::new(XxChecksummer::H128(XxHash3_128::new())),
        crc => Box::new(CrcChecksummer::new(crc)),
    }
}

struct CrcChecksummer {
    algo: ChecksumAlgorithm,
    digest: crc_fast::Digest,
}

impl CrcChecksummer {
    fn new(algo: ChecksumAlgorithm) -> Self {
        // `crc_algorithm` is total over the CRC variants; ISO-HDLC is a safe stand-in that can
        // only be reached if a non-CRC algorithm were routed here, which `open` prevents.
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

/// The three XXHash variants, one enum rather than three types because they differ only in which
/// `finish` is called and how wide its integer is.
enum XxChecksummer {
    H64(XxHash64),
    H3(XxHash3_64),
    H128(XxHash3_128),
}

impl Checksummer for XxChecksummer {
    fn update(&mut self, buf: &[u8]) {
        match self {
            Self::H64(hasher) => hasher.write(buf),
            Self::H3(hasher) => hasher.write(buf),
            Self::H128(hasher) => hasher.write(buf),
        }
    }

    fn finalize(self: Box<Self>) -> Bytes {
        match *self {
            Self::H64(hasher) => Bytes::copy_from_slice(&hasher.finish().to_be_bytes()),
            Self::H3(hasher) => Bytes::copy_from_slice(&hasher.finish().to_be_bytes()),
            Self::H128(hasher) => Bytes::copy_from_slice(&hasher.finish_128().to_be_bytes()),
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::H64(_) | Self::H3(_) => 8,
            Self::H128(_) => 16,
        }
    }
}
