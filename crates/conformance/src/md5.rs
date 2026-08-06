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

//! MD5, because an S3 entity tag is one.
//!
//! Responsible for: the digest the fixture backend stamps on an object it was told to hold, so a
//! case can write `if-match: "5d41402abc4b2a76b9719d911017c592"` against a body it declared as
//! `"hello"` and mean it. Here rather than borrowed from the framework under test for the reason
//! [`crate::sha256`] gives: a suite that computes an expectation with the implementation's own
//! primitive cannot detect a fault in that primitive.
//! NOT responsible for: authenticating anything. MD5 is broken for every purpose except the one
//! S3 froze it into, and nothing in this crate may reach for it from a security decision.
//! Upstream: nothing. Downstream: `crate::fixture`.

/// Per-round left-rotation amounts.
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)`, the constants RFC 1321 tabulates.
const SINE_CONSTANTS: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// Returns the lowercase hexadecimal MD5 digest of `data`.
#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    let digest = digest(data);
    let mut out = String::with_capacity(32);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Returns the raw MD5 digest of `data`.
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn digest(data: &[u8]) -> [u8; 16] {
    let mut message = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_le_bytes());

    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in message.chunks_exact(64) {
        let mut words = [0_u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            let bytes: [u8; 4] = block.get(start..start + 4).unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]);
            *word = u32::from_le_bytes(bytes);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for index in 0..64 {
            let (mixed, word_index) = match index / 16 {
                0 => ((b & c) | (!b & d), index),
                1 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                2 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let sum = a
                .wrapping_add(mixed)
                .wrapping_add(SINE_CONSTANTS.get(index).copied().unwrap_or(0))
                .wrapping_add(words.get(word_index).copied().unwrap_or(0));
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(SHIFTS.get(index).copied().unwrap_or(0)));
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0_u8; 16];
    for (index, word) in state.iter().enumerate() {
        let start = index * 4;
        if let Some(slot) = out.get_mut(start..start + 4) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_input_matches_the_published_vector() {
        assert_eq!(hex_digest(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    /// The vector the corpus itself depends on: `c-etag-0001` writes this digest by hand.
    #[test]
    fn the_hello_vector_matches_the_one_the_corpus_writes_by_hand() {
        assert_eq!(hex_digest(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn a_multi_block_input_matches() {
        let input = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(hex_digest(input), "9e107d9d372bb6826bd81d3542a419d6");
    }

    /// Negative — a one-byte change changes the digest, so an entity tag cannot silently collide
    /// with the body it is meant to distinguish.
    #[test]
    fn a_one_byte_change_changes_the_digest() {
        assert_ne!(hex_digest(b"hello world"), hex_digest(b"hello worlD"));
    }

    /// The padding boundary: a 56-byte input needs a whole extra block.
    #[test]
    fn an_input_at_the_padding_boundary_matches() {
        let input = vec![b'a'; 56];
        assert_eq!(hex_digest(&input), "3b0c8ac703f828b04c6c197006d17218");
    }
}
