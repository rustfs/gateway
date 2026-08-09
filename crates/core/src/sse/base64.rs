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

//! One strict base64 decoder for the SSE header family, with no lenient spelling of anything.
//!
//! Responsible for: turning the base64 text of a customer key, a key digest and an encryption
//! context into bytes, or refusing it — standard alphabet only, exact padding, no whitespace, no
//! trailing bytes, and no non-zero bits left over in the final character.
//! NOT responsible for: what the bytes mean ([`super::key`] and [`super::headers`]), encoding
//! anything (nothing here re-emits a value), or general-purpose base64 for other families —
//! `rustfs_gateway_types`' `Content-MD5` codec and `rustfs_gateway_sig::codec` each own theirs.
//! Upstream: nothing. Downstream: [`super::key`], [`super::headers`].
//!
//! # Why a strict decoder rather than a tolerant one
//!
//! A tolerant decoder maps many strings onto one byte sequence. That matters twice here. The key
//! digest is *compared* against a digest this service computes, and two spellings of one digest
//! mean a client can choose which bytes the comparison runs over. The key itself is *material*: a
//! decoder that accepted `AAA` and `AAA=` and `AAA ` as one key would let the same key arrive
//! under several signatures, and the signature is what stops a middlebox swapping it.
//!
//! # Why this is not `rustfs_gateway_sig::codec::decode_base64_sha256`
//!
//! That function decodes exactly 32 bytes and is named for the digest it decodes. This family
//! needs 16 as well (the key digest) and a bounded variable length (the encryption context), and
//! generalising a function in `crates/sig` is a cross-crate refactor this task may not make. The
//! two are held together instead by `differential_tests` below: for every 32-byte spelling the
//! suite tries, this decoder and that one must agree on accept-or-refuse, so the second
//! implementation cannot quietly become more tolerant than the first.

/// Why a base64 value was refused.
///
/// The variants exist so this module's own tests can say which rule fired. Nothing outside turns
/// one into a client-visible message: [`super::SseRejection`] answers with a constant sentence
/// that names the header and never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A character outside `A-Za-z0-9+/`, or padding somewhere other than the end.
    Alphabet,
    /// The text length is not a multiple of four, or the padding count is not zero, one or two.
    Padding,
    /// The final character carries bits that the decoded length does not use. Accepting these
    /// gives every value up to 64 spellings.
    NonCanonical,
    /// The value decodes to more bytes than the caller has room for. Refused rather than
    /// truncated: truncation lets a caller pick how many bytes a later comparison covers.
    TooLong,
    /// The value decodes to fewer bytes than the caller requires.
    TooShort,
}

/// The standard RFC 4648 §4 alphabet, and nothing else. URL-safe input is refused.
fn value_of(byte: u8) -> Result<u8, Base64Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64Error::Alphabet),
    }
}

/// Decodes `input` into `out`, returning how many bytes were written.
///
/// Every rule this family relies on is here, in one pass:
///
/// * the length is a multiple of four, so an unpadded value is refused;
/// * padding is zero, one or two `=` characters, at the very end and nowhere else;
/// * every other character is in the standard alphabet — whitespace, newlines and the URL-safe
///   `-`/`_` are all `Alphabet` refusals, not something to skip;
/// * the bits the last character contributes beyond the decoded length must be zero;
/// * running out of room in `out` is a refusal, never a truncation.
///
/// # Errors
///
/// [`Base64Error`] naming the rule that fired.
pub fn decode_into(input: &str, out: &mut [u8]) -> Result<usize, Base64Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(Base64Error::Padding);
    }
    // Count the padding at the tail, then require that no `=` appears before it. Written with
    // `get` and `checked_sub` rather than indexing: this crate denies `clippy::indexing_slicing`,
    // and the input here is a header value a caller chose.
    let mut padding = 0usize;
    while padding < 2 {
        let Some(index) = bytes.len().checked_sub(padding + 1) else { break };
        if bytes.get(index) != Some(&b'=') {
            break;
        }
        padding += 1;
    }
    let data = bytes.get(..bytes.len().saturating_sub(padding)).unwrap_or_default();
    if data.contains(&b'=') {
        return Err(Base64Error::Padding);
    }

    let mut written = 0usize;
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        accumulator = (accumulator << 6) | u32::from(value_of(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Masked to eight bits, so the conversion cannot fail; `try_from` keeps the
            // no-`unwrap` rule without inventing a fallback value.
            let full = u8::try_from((accumulator >> bits) & 0xff).map_err(|_| Base64Error::Alphabet)?;
            let slot = out.get_mut(written).ok_or(Base64Error::TooLong)?;
            *slot = full;
            written += 1;
        }
    }
    if bits != 0 && (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(Base64Error::NonCanonical);
    }
    Ok(written)
}

/// Decodes a value that must be exactly `N` bytes.
///
/// The width is part of the contract, not a hint: a 31- or 33-byte customer key is a malformed
/// request, and zero-padding or truncating it would hand the caller control of the comparison
/// width. The output is a stack array, so no heap buffer holding key material is left behind for
/// a `Drop` that cannot reach it.
///
/// # Errors
///
/// [`Base64Error`] naming the rule that fired; [`Base64Error::TooShort`] when the value is
/// well-formed base64 of fewer than `N` bytes.
pub fn decode_exact<const N: usize>(input: &str) -> Result<[u8; N], Base64Error> {
    let mut out = [0u8; N];
    let written = decode_into(input, &mut out)?;
    if written != N {
        return Err(Base64Error::TooShort);
    }
    Ok(out)
}

/// Decodes a value of unknown length, up to `max_bytes`.
///
/// Used for the encryption context, which has no fixed width. The ceiling is applied *at the
/// limit* rather than after the fact: `decode_into` refuses at the byte that would not fit, so a
/// caller cannot make this service allocate for a value it was always going to refuse.
///
/// # Errors
///
/// [`Base64Error`] naming the rule that fired.
pub fn decode_bounded(input: &str, max_bytes: usize) -> Result<Vec<u8>, Base64Error> {
    let mut out = vec![0u8; max_bytes];
    let written = decode_into(input, &mut out)?;
    out.truncate(written);
    Ok(out)
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `ops/shared/encryption.rs`.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A 32-byte key, base64 of 44 characters with one `=`.
    const KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    /// A 16-byte digest, base64 of 24 characters with two `=`.
    const MD5_B64: &str = "AAECAwQFBgcICQoLDA0ODw==";

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_canonical_thirty_two_byte_value_decodes_to_its_bytes() {
        let decoded = decode_exact::<32>(KEY_B64).expect("canonical");
        assert_eq!(decoded, core::array::from_fn::<u8, 32, _>(|i| u8::try_from(i).unwrap_or(0)));
    }

    #[test]
    fn a_canonical_sixteen_byte_value_decodes_to_its_bytes() {
        let decoded = decode_exact::<16>(MD5_B64).expect("canonical");
        assert_eq!(decoded, core::array::from_fn::<u8, 16, _>(|i| u8::try_from(i).unwrap_or(0)));
    }

    #[test]
    fn a_bounded_value_decodes_and_reports_its_own_length() {
        // `eyJhIjoiYiJ9` is twelve characters with no padding: nine bytes, `{"a":"b"}`.
        let decoded = decode_bounded("eyJhIjoiYiJ9", 64).expect("canonical");
        assert_eq!(decoded, br#"{"a":"b"}"#);
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_the_url_safe_alphabet_is_refused_rather_than_translated() {
        // `+` and `/` carry meaning in the standard alphabet; `-` and `_` are a different encoding
        // of the same bytes, and two spellings of one key is the comparison bypass this refuses.
        let url_safe = "--__AwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(decode_exact::<32>(url_safe), Err(Base64Error::Alphabet));
    }

    #[test]
    fn n_whitespace_anywhere_is_refused() {
        for spelling in [
            " AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= ",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n",
            "AAEC AwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        ] {
            assert!(decode_exact::<32>(spelling).is_err(), "accepted {spelling:?}");
        }
    }

    #[test]
    fn n_missing_padding_is_refused() {
        assert_eq!(decode_exact::<32>(KEY_B64.trim_end_matches('=')), Err(Base64Error::Padding));
        assert_eq!(decode_exact::<16>(MD5_B64.trim_end_matches('=')), Err(Base64Error::Padding));
    }

    #[test]
    fn n_extra_padding_is_refused() {
        assert!(decode_exact::<32>(&format!("{KEY_B64}====")).is_err());
        assert!(decode_exact::<16>(&format!("{MD5_B64}====")).is_err());
    }

    #[test]
    fn n_interior_padding_is_refused() {
        let interior = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBka=BwdHh8=";
        assert_eq!(decode_exact::<32>(interior), Err(Base64Error::Padding));
    }

    #[test]
    fn n_non_canonical_trailing_bits_are_refused() {
        // The final data character of a 16-byte value contributes two bits; the other four must be
        // zero. `D` is 3, which sets them.
        let non_canonical = "AAECAwQFBgcICQoLDA0ODD==";
        assert_eq!(decode_exact::<16>(non_canonical), Err(Base64Error::NonCanonical));
    }

    #[test]
    fn n_a_value_one_byte_too_long_is_refused_and_not_truncated() {
        // 33 bytes: `decode_into` runs out of room and says so rather than keeping the first 32.
        let thirty_three = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
        assert_eq!(decode_exact::<32>(thirty_three), Err(Base64Error::TooLong));
    }

    #[test]
    fn n_a_value_one_byte_too_short_is_refused_and_not_zero_padded() {
        // 31 bytes.
        let thirty_one = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==";
        assert_eq!(decode_exact::<32>(thirty_one), Err(Base64Error::TooShort));
    }

    #[test]
    fn n_the_empty_string_is_refused_rather_than_decoding_to_nothing() {
        assert_eq!(decode_exact::<32>(""), Err(Base64Error::Padding));
        assert_eq!(decode_bounded("", 64), Err(Base64Error::Padding));
    }

    #[test]
    fn n_a_length_that_is_not_a_multiple_of_four_is_refused() {
        for spelling in ["A", "AA", "AAA", "AAAAA"] {
            assert_eq!(decode_exact::<32>(spelling), Err(Base64Error::Padding), "accepted {spelling:?}");
        }
    }

    #[test]
    fn n_a_bounded_value_over_the_ceiling_is_refused_at_the_ceiling() {
        // Eight encoded characters are six bytes; a five-byte ceiling refuses.
        assert_eq!(decode_bounded("AAECAwQF", 5), Err(Base64Error::TooLong));
        assert!(decode_bounded("AAECAwQF", 6).is_ok());
    }

    /// Negative — the second implementation may not be more tolerant than the first.
    ///
    /// `rustfs_gateway_sig::codec::decode_base64_sha256` is this repository's other strict
    /// 32-byte base64 decoder. Two decoders for one rule is the s3s #499-versus-#632 shape, and
    /// the mitigation available without a cross-crate refactor is to make a divergence loud: for
    /// every spelling below the two must agree on accept-or-refuse, and on the bytes when both
    /// accept.
    #[test]
    fn n_the_thirty_two_byte_decoder_agrees_with_the_signature_crate_spelling_for_spelling() {
        let spellings = [
            KEY_B64,
            KEY_B64.trim_end_matches('='),
            " AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "--__AwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
            "",
            "AAAA",
        ];
        for spelling in spellings {
            let mine = decode_exact::<32>(spelling);
            let theirs = rustfs_gateway_sig::codec::decode_base64_sha256(spelling);
            assert_eq!(
                mine.is_ok(),
                theirs.is_ok(),
                "the two strict decoders disagree about {spelling:?}: mine {mine:?}, sig {theirs:?}"
            );
            if let (Ok(mine), Ok(theirs)) = (mine, theirs) {
                assert_eq!(mine, theirs, "same verdict, different bytes for {spelling:?}");
            }
        }
    }
}
