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

//! CRC-32/ISO-HDLC, because `x-amz-checksum-crc32` is one.
//!
//! Responsible for: the digest the fixture backend reports for a part it was told to hold, so a
//! case that opens a multipart upload with `x-amz-checksum-algorithm: CRC32` gets a checksum of
//! the bytes it sent rather than a value invented to satisfy the assertion.
//! NOT responsible for: verifying anything a request claimed. The framework under test parses and
//! checks request checksums; a second checker here would agree with itself and prove nothing.
//! Upstream: nothing. Downstream: `crate::fixture`.
//!
//! # Why this is written out again
//!
//! `rustfs-gateway-types` computes this already, behind [`ChecksumAlgorithm::checksummer`] — but
//! the trait that call returns, `Checksummer`, is not among the facade's re-exports, so the method
//! on the returned box cannot be called from outside the workspace. Every backend that wants to
//! answer `x-amz-checksum-*` therefore vendors an implementation, exactly as this file does. That
//! is a facade gap and not a suite decision, and it is recorded here rather than worked around
//! silently. The same reasoning as [`crate::md5`] applies on top of it: a suite that computed an
//! expectation with the implementation's own primitive could not detect a fault in that primitive.
//!
//! [`ChecksumAlgorithm::checksummer`]: rustfs_gateway::ChecksumAlgorithm

/// The reflected CRC-32 polynomial, `0x04C1_1DB7` bit-reversed.
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// Returns the raw big-endian CRC-32 digest of `data`.
///
/// Big-endian because that is the order S3 base64-encodes into the header, and a digest assembled
/// the other way round is a valid CRC of nothing.
#[must_use]
pub fn digest(data: &[u8]) -> [u8; 4] {
    checksum(data).to_be_bytes()
}

/// Returns the CRC-32 of `data` as a number.
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= POLYNOMIAL;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check value RFC 1952 and every CRC catalogue publish for this parameterisation.
    #[test]
    fn the_published_check_vector_matches() {
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn the_empty_input_is_zero() {
        assert_eq!(checksum(b""), 0);
        assert_eq!(digest(b""), [0, 0, 0, 0]);
    }

    /// The byte order is the one that goes on the wire, not the platform's.
    #[test]
    fn the_digest_is_big_endian() {
        assert_eq!(digest(b"123456789"), [0xCB, 0xF4, 0x39, 0x26]);
    }

    /// Negative — a one-byte change changes the digest, so a checksum cannot silently agree with
    /// bytes it did not cover.
    #[test]
    fn a_one_byte_change_changes_the_digest() {
        assert_ne!(checksum(b"part one payload"), checksum(b"part one payloaD"));
    }
}
