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

//! The continuation-token codec: a page position, authenticated to the listing it came from.
//!
//! Responsible for: minting a continuation token that only this process can produce, reading one
//! back, and refusing every value that this process did not mint *for the listing now asking*.
//! NOT responsible for: what a position means, how a page is cut, or the client-facing ceiling on
//! a cursor's length — that ceiling is [`rustfs_gateway::MAX_CURSOR_BYTES`] and it is applied here
//! by calling the contract rather than by restating it.
//! Upstream: [`crate::sha256`] for the compression function, `rustfs_gateway`'s [`CursorSpec`] for
//! the wire ceiling. Downstream: [`crate::fixture`], which is the only minter, and
//! `fuzz/fuzz_targets/opaque_token.rs`, which is the only other reader.
//!
//! # What was wrong with the token this replaces
//!
//! The token was `hex(position) + "-" + sha256(position)[..8]`. Both halves are functions of the
//! position and of nothing else, so *every* input to it is public: a client that guesses the
//! construction mints a self-consistent token for any position it likes, and the reader — which
//! recomputes the digest over the value it just decoded and compares — accepts it, because
//! recomputing the digest is exactly what the forger did. A digest computed over attacker-supplied
//! data with no secret in it detects corruption and authenticates nothing.
//!
//! What that buys an attacker is a listing whose start key they choose. Against this fixture that
//! is a jump to an offset; against a backend that resolves the position into a path, a key prefix
//! or a bucket-relative cursor, the same value is a read primitive the client steers. The whole
//! reason `crate::fixture`'s cursor is not a verbatim marker is to make that class of bug
//! observable, and an unkeyed checksum leaves it exactly as observable as no checksum at all —
//! `c-list-0032`'s one-byte alteration goes red either way, which is why it could not see this.
//!
//! # The three properties this module holds
//!
//! 1. **Unforgeable.** The tag is HMAC-SHA-256 under a secret that exists only in this process's
//!    memory, so the forger's recomputation is missing the one input it cannot read.
//! 2. **Bound to its listing.** The tag covers a [`TokenScope`] — the operation, the bucket, the
//!    prefix and the delimiter — as well as the position, so a token minted for one listing is not
//!    a token for another. Without this a genuine token is a *transferable* capability: mint one
//!    in a bucket you may read, replay it against a listing you are steering.
//! 3. **Compared in constant time.** [`ct_eq`] and never `==`, and the secret has no `PartialEq`
//!    at all, which is `AGENTS.md`'s rule for key material and applies to a MAC key like any other.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustfs_gateway::CursorSpec;

/// The cursor contract every token is read under before a single byte of it is decoded.
///
/// The ceiling ([`rustfs_gateway::MAX_CURSOR_BYTES`]) and the refusal of a byte that cannot be
/// written back into a response document are the exported rule, and this is a call rather than a
/// second copy for the reason `c-list-0030` exists: a ceiling written twice is a ceiling two
/// implementations hold at two different values.
const CONTINUATION_CURSOR: CursorSpec = CursorSpec::opaque("continuation-token");

/// The length of the authentication tag as it appears in a token, in hex digits.
///
/// Sixteen bytes of a thirty-two byte HMAC. Truncating an HMAC is sanctioned (RFC 2104 §5) and 128
/// bits is far past the point where guessing is a strategy; the whole digest would only make the
/// token longer. What matters is that the comparison is over the truncated tag on *both* sides —
/// comparing a client's short tag against a prefix of the real one is the same length-extension
/// mistake in a different costume.
const TAG_HEX_LEN: usize = 32;

/// The byte that separates the encoded position from its tag.
///
/// Split from the *right*, so a position whose own hex encoding somehow contained one could not
/// move the boundary. Hex never contains it, which is the point of encoding the position at all.
const TAG_SEPARATOR: char = '-';

/// Distinguishes one fixture's secret from another's in the same process.
static SECRET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The HMAC key a single backend instance mints and verifies its tokens under.
///
/// Deliberately not `Clone`-into-anything-observable, not `PartialEq`, and its `Debug` prints no
/// bytes. `AGENTS.md` forbids deriving `PartialEq` on key material precisely so that a comparison
/// against it cannot be written accidentally; a MAC key is key material.
pub struct TokenSecret {
    key: [u8; 32],
}

impl std::fmt::Debug for TokenSecret {
    /// Prints that a secret exists and nothing about what it is.
    ///
    /// `crate::fixture::Fixture` derives `Debug`, so this value is one `{:?}` away from a test
    /// log at all times. A key that reaches a log is a key an attacker reads instead of guesses,
    /// which would return this module to exactly the state it was written to leave.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenSecret(<redacted>)")
    }
}

impl Default for TokenSecret {
    /// [`TokenSecret::generate`]. `crate::fixture::Fixture` derives `Default`, and the default a
    /// derive would otherwise want here is a key of zeroes — which is to say a key every client
    /// already has. A default that is a published constant is not a weaker secret, it is no secret
    /// at all, so the default is the generator.
    fn default() -> TokenSecret {
        TokenSecret::generate()
    }
}

impl TokenSecret {
    /// Mints a secret no client can predict and no other instance shares.
    ///
    /// Four independent inputs, none of which is sufficient alone. [`RandomState`] is seeded once
    /// per process from the operating system and is what makes this unpredictable *between* runs;
    /// the wall clock and the process id widen that; the counter is what makes two fixtures built
    /// in the same process — which is every `cargo test` run of this crate — hold different keys,
    /// so a token minted against one is not a token against the other. The address of a fresh
    /// allocation is the fourth, and it is the one that survives a platform where the clock is
    /// coarse.
    ///
    /// This is not a cryptographic random number generator and does not claim to be one. It is the
    /// seed for a test backend's MAC key, in a crate whose whole design rule is that it carries no
    /// third-party dependency; what it has to beat is a client that knows the source code, and
    /// per-process operating-system entropy beats that.
    #[must_use]
    pub fn generate() -> TokenSecret {
        let counter = SECRET_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u128, |elapsed| elapsed.as_nanos());
        let heap = Box::new(0_u8);
        let address = std::ptr::from_ref::<u8>(&*heap) as usize;

        let mut seed = Vec::with_capacity(96);
        seed.extend_from_slice(b"rustfs-gateway-conformance/continuation-token/v1");
        seed.extend_from_slice(&counter.to_le_bytes());
        seed.extend_from_slice(&nanos.to_le_bytes());
        seed.extend_from_slice(&(address as u64).to_le_bytes());
        seed.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
        for salt in 0_u64..4 {
            let mut hasher = RandomState::new().build_hasher();
            hasher.write_u64(salt);
            hasher.write(&seed);
            seed.extend_from_slice(&hasher.finish().to_le_bytes());
        }

        TokenSecret {
            key: crate::sha256::digest(&seed),
        }
    }

    /// Builds a secret from bytes a caller chose, for tests that need two runs to agree.
    ///
    /// Not reachable from the fixture: a backend that let a client influence its key would have no
    /// key. It exists so a property test can mint under one known secret and verify under another,
    /// which is the assertion that the tag depends on the key at all.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> TokenSecret {
        TokenSecret {
            key: crate::sha256::digest(bytes),
        }
    }

    /// Mints a token that resumes `position` within `scope`.
    ///
    /// The position travels hex-encoded and in the clear. That is deliberate and it is not the
    /// property this codec provides: S3's own tokens are a recognisable encoding of a position
    /// too, and confidentiality of the key you just listed is not a guarantee anybody is relying
    /// on. What must hold is that the value cannot be *changed* — including changed into a
    /// position for a different listing — which is what the tag is for.
    #[must_use]
    pub fn mint(&self, scope: &TokenScope, position: &str) -> String {
        let body = encode_hex(position.as_bytes());
        let tag = encode_hex(&self.tag(scope, position));
        let tag = tag.get(..TAG_HEX_LEN).unwrap_or(tag.as_str());
        format!("{body}{TAG_SEPARATOR}{tag}")
    }

    /// Reads a token back, or `None` for anything this secret did not mint for this scope.
    ///
    /// The order of the checks is a contract, not an implementation detail. The wire ceiling is
    /// applied *first*, before the hex body is decoded, so the work the ceiling exists to prevent
    /// is never done — `c-list-0030` is the case that separates the two orderings by bounding the
    /// response time. Everything after it is total: no index that can be out of range, no decode
    /// that can panic, and one constant-time comparison at the end.
    #[must_use]
    pub fn read(&self, scope: &TokenScope, token: &str) -> Option<String> {
        let token = CONTINUATION_CURSOR.accept(token).ok()?;
        let (body, claimed) = token.rsplit_once(TAG_SEPARATOR)?;
        // Length is checked before the comparison rather than inside it: `ct_eq` answers false for
        // a length mismatch, but a *short* tag that compared equal against a prefix of the real one
        // would be a forgery, and refusing the wrong length outright is the way not to write that.
        if claimed.len() != TAG_HEX_LEN {
            return None;
        }
        let position = String::from_utf8(decode_hex(body)?).ok()?;
        // The encoding must be the one this codec produces, not merely one that decodes to the
        // same bytes. `decode_hex` reads either case, so without this line `612F...` and `612f...`
        // are two distinct tokens for one position — a token that has more than one spelling is a
        // token an intermediary can rewrite without invalidating, and it makes the fuzz target's
        // central property ("anything accepted is exactly what minting produces") false.
        if encode_hex(position.as_bytes()) != body {
            return None;
        }
        let expected = encode_hex(&self.tag(scope, &position));
        let expected = expected.get(..TAG_HEX_LEN)?;
        if !ct_eq(expected.as_bytes(), claimed.as_bytes()) {
            return None;
        }
        Some(position)
    }

    /// HMAC-SHA-256 over the scope and the position, both length-prefixed.
    fn tag(&self, scope: &TokenScope, position: &str) -> [u8; 32] {
        let mut message = scope.encoded.clone();
        push_field(&mut message, position.as_bytes());
        hmac_sha256(&self.key, &message)
    }
}

/// The listing a token belongs to: everything a resumed page must agree with.
///
/// A position alone is not a capability anybody should hand out. `a/2.txt` means one thing in the
/// bucket that issued it and something else in every other bucket, under every other prefix, and
/// with a different delimiter in play — and a token authenticated over the position alone is valid
/// in all of them. Binding the scope is what turns "a token this service minted" into "a token this
/// service minted *for this listing*", which is the only version of the claim worth making.
///
/// Fields are length-prefixed rather than joined with a separator. A separator that can appear
/// inside a bucket name, a prefix or a delimiter lets two different scopes encode to the same
/// bytes, and two scopes with one tag is the same hole under a different name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenScope {
    encoded: Vec<u8>,
}

impl TokenScope {
    /// The scope of a listing over one bucket.
    ///
    /// `operation` separates `ListObjects` from `ListObjectsV2` from anything added later, so a
    /// token minted by one is not read by another even where their positions coincide.
    #[must_use]
    pub fn bucket_listing(operation: &str, bucket: &str, prefix: &str, delimiter: Option<&str>) -> TokenScope {
        let mut encoded = Vec::new();
        push_field(&mut encoded, operation.as_bytes());
        push_field(&mut encoded, bucket.as_bytes());
        push_field(&mut encoded, prefix.as_bytes());
        // An absent delimiter and an empty one are different listings, so they must encode
        // differently: the tag is prefixed with a discriminant rather than with nothing.
        match delimiter {
            Some(value) => {
                push_field(&mut encoded, b"delimiter");
                push_field(&mut encoded, value.as_bytes());
            }
            None => push_field(&mut encoded, b"no-delimiter"),
        }
        TokenScope { encoded }
    }

    /// The scope of a listing over the buckets themselves, which has no bucket to name.
    #[must_use]
    pub fn account_listing(operation: &str, prefix: &str) -> TokenScope {
        let mut encoded = Vec::new();
        push_field(&mut encoded, operation.as_bytes());
        push_field(&mut encoded, prefix.as_bytes());
        TokenScope { encoded }
    }
}

/// Appends one length-prefixed field to a message under construction.
fn push_field(message: &mut Vec<u8>, field: &[u8]) {
    message.extend_from_slice(&(field.len() as u64).to_le_bytes());
    message.extend_from_slice(field);
}

/// Compares two byte strings without letting the time taken depend on where they differ.
///
/// The loop reads every byte of both, accumulating differences instead of returning at the first
/// one, and [`std::hint::black_box`] stands between the accumulator and the compiler so that the
/// early exit cannot be reintroduced by an optimiser that has noticed the answer is already
/// decided. It is not the reason this module is safe — a forger who cannot compute the tag cannot
/// use a timing signal to find it in any practical number of attempts — but writing the leaky
/// version here is how the leaky version ends up copied into somewhere it does matter.
#[must_use]
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
        difference = std::hint::black_box(difference);
    }
    difference == 0
}

/// The block size of SHA-256, in bytes, which is what HMAC pads its key to.
const HMAC_BLOCK: usize = 64;

/// HMAC-SHA-256 (RFC 2104), over this crate's own SHA-256.
///
/// Hand-written for the reason every primitive in this crate is: a suite that verifies an
/// implementation using that implementation's own primitives cannot detect a fault in them, and
/// this crate is meant to run against foreign servers where no such primitive is available at all.
/// [`crate::sha256`] states it is not responsible for anything reachable from a security decision,
/// and that stays true — this function is a *separate* construction over its compression, and the
/// security decision is here.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        block[..32].copy_from_slice(&crate::sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(HMAC_BLOCK + message.len());
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner = crate::sha256::digest(&inner);

    let mut outer = Vec::with_capacity(HMAC_BLOCK + 32);
    outer.extend(block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner);
    crate::sha256::digest(&outer)
}

/// Lowercase hex, the encoding a token's position travels in.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    char::from_digit(u32::from(value), 16).unwrap_or('0')
}

/// Reads lowercase or uppercase hex, or `None` for anything that is not a whole number of bytes of
/// it.
#[must_use]
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = char::from(*pair.first()?).to_digit(16)?;
        let low = char::from(*pair.get(1)?).to_digit(16)?;
        out.push(((high * 16) + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
// Test code only. The crate denies these so that no request path can panic; a test that cannot
// assert an `Ok` says less than it should.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scope() -> TokenScope {
        TokenScope::bucket_listing("ListObjectsV2", "conf-list", "", None)
    }

    #[test]
    fn a_minted_token_reads_back_as_the_position_it_was_minted_for() {
        let secret = TokenSecret::generate();
        let token = secret.mint(&scope(), "a/2.txt");
        assert_eq!(secret.read(&scope(), &token).as_deref(), Some("a/2.txt"));
    }

    /// The empty position is a legal one — it is what an empty bucket's first page resumes from —
    /// and it must survive the round trip rather than collapsing into "no token".
    #[test]
    fn the_empty_position_survives_the_round_trip() {
        let secret = TokenSecret::generate();
        let token = secret.mint(&scope(), "");
        assert_eq!(secret.read(&scope(), &token).as_deref(), Some(""));
    }

    /// Negative, and the reason this module exists: the tag a client can compute from public
    /// information is not the tag this codec checks.
    ///
    /// The forged value is the *old* token format for `a/2.txt` — hex, a separator, and the first
    /// eight hex digits of its unkeyed SHA-256 — which the codec this replaces accepted, because
    /// every input to it was public.
    #[test]
    fn a_token_forged_from_the_unkeyed_digest_is_refused() {
        let secret = TokenSecret::generate();
        let position = "a/2.txt";
        let digest = crate::sha256::hex_digest(position.as_bytes());
        let forged = format!("{}-{}", encode_hex(position.as_bytes()), &digest[..8]);
        assert_eq!(secret.read(&scope(), &forged), None, "an unkeyed checksum authenticates nothing");

        // And the same forgery at the length the real tag has, so the refusal is not merely the
        // length check answering.
        let forged = format!("{}-{}", encode_hex(position.as_bytes()), &digest[..TAG_HEX_LEN]);
        assert_eq!(secret.read(&scope(), &forged), None);
    }

    /// Negative: the tag depends on the key, so another instance's token is not this one's.
    #[test]
    fn a_token_minted_under_another_secret_is_refused() {
        let mine = TokenSecret::generate();
        let theirs = TokenSecret::generate();
        let token = theirs.mint(&scope(), "a/2.txt");
        assert_eq!(mine.read(&scope(), &token), None);
        assert_eq!(theirs.read(&scope(), &token).as_deref(), Some("a/2.txt"), "the control direction");
    }

    /// Negative: a genuine token is not a transferable capability. Every component of the scope
    /// changes the tag, so a token is only valid for the listing that issued it.
    #[test]
    fn a_genuine_token_is_refused_by_every_other_listing() {
        let secret = TokenSecret::generate();
        let issued = TokenScope::bucket_listing("ListObjectsV2", "conf-list", "a/", Some("/"));
        let token = secret.mint(&issued, "a/2.txt");
        assert_eq!(secret.read(&issued, &token).as_deref(), Some("a/2.txt"), "the control direction");

        for other in [
            TokenScope::bucket_listing("ListObjects", "conf-list", "a/", Some("/")),
            TokenScope::bucket_listing("ListObjectsV2", "conf-other", "a/", Some("/")),
            TokenScope::bucket_listing("ListObjectsV2", "conf-list", "b/", Some("/")),
            TokenScope::bucket_listing("ListObjectsV2", "conf-list", "a/", Some(":")),
            TokenScope::bucket_listing("ListObjectsV2", "conf-list", "a/", None),
            TokenScope::account_listing("ListBuckets", "a/"),
        ] {
            assert_eq!(secret.read(&other, &token), None, "a token crossed into {other:?}");
        }
    }

    /// Negative: an absent delimiter and an empty one are different listings and must not share a
    /// tag. Without the discriminant both would encode to a zero-length field.
    #[test]
    fn an_absent_delimiter_is_not_an_empty_one() {
        let secret = TokenSecret::generate();
        let absent = TokenScope::bucket_listing("ListObjectsV2", "conf-list", "", None);
        let empty = TokenScope::bucket_listing("ListObjectsV2", "conf-list", "", Some(""));
        assert_ne!(absent, empty);
        let token = secret.mint(&absent, "a/2.txt");
        assert_eq!(secret.read(&empty, &token), None);
    }

    /// Negative: the length-prefixed encoding refuses to let two different scopes produce one
    /// message. Concatenating the fields with no length would make these two identical.
    #[test]
    fn two_scopes_cannot_be_spliced_into_one_message() {
        let left = TokenScope::bucket_listing("ListObjectsV2", "conf", "-list/a", None);
        let right = TokenScope::bucket_listing("ListObjectsV2", "conf-list", "/a", None);
        assert_ne!(left, right, "the encodings collided");

        let secret = TokenSecret::generate();
        let token = secret.mint(&left, "x");
        assert_eq!(secret.read(&right, &token), None);
    }

    /// Negative: every one-byte alteration of a genuine token is refused, in both halves of it.
    #[test]
    fn every_single_byte_alteration_is_refused() {
        let secret = TokenSecret::generate();
        let token = secret.mint(&scope(), "a/2.txt");
        for index in 0..token.len() {
            for replacement in ['0', '9', 'a', 'f', 'X'] {
                let mut altered: Vec<char> = token.chars().collect();
                if altered[index] == replacement {
                    continue;
                }
                altered[index] = replacement;
                let altered: String = altered.into_iter().collect();
                assert_eq!(secret.read(&scope(), &altered), None, "{altered} was honoured");
            }
        }
    }

    /// Negative: the wire ceiling is the contract's, and it is applied before anything is decoded.
    #[test]
    fn a_token_over_the_wire_ceiling_is_refused_before_it_is_decoded() {
        let secret = TokenSecret::generate();
        let over = "a".repeat(rustfs_gateway::MAX_CURSOR_BYTES + 1);
        assert_eq!(secret.read(&scope(), &over), None);
    }

    /// Negative: a byte that cannot be written back into a response document is refused, and so is
    /// a value that is not a token at all.
    #[test]
    fn malformed_values_are_refused_rather_than_read_as_a_position() {
        let secret = TokenSecret::generate();
        for raw in [
            "../../etc/passwd",
            "\u{ff}\u{fe}\u{0}\u{1}",
            "",
            "-",
            "--",
            "zz-00000000000000000000000000000000",
            "612f322e747874",
            "612f322e747874-",
            "612f322e74787-00000000000000000000000000000000",
        ] {
            assert_eq!(secret.read(&scope(), raw), None, "{raw:?} was read as a position");
        }
    }

    /// A truncated tag must not be compared against a prefix of the real one.
    #[test]
    fn a_truncated_tag_is_refused_rather_than_prefix_matched() {
        let secret = TokenSecret::generate();
        let token = secret.mint(&scope(), "a/2.txt");
        let (body, tag) = token.rsplit_once('-').expect("a minted token carries a tag");
        for keep in 0..tag.len() {
            let short = format!("{body}-{}", &tag[..keep]);
            assert_eq!(secret.read(&scope(), &short), None, "{short} was honoured");
        }
        assert_eq!(secret.read(&scope(), &token).as_deref(), Some("a/2.txt"), "the control direction");
    }

    /// Two secrets built in the same process differ, which is what stops a token minted against
    /// one fixture from being read by the next one in the same test binary.
    #[test]
    fn two_generated_secrets_are_not_the_same_secret() {
        let first = TokenSecret::generate();
        let second = TokenSecret::generate();
        let token = first.mint(&scope(), "a/2.txt");
        assert_eq!(second.read(&scope(), &token), None);
    }

    /// The secret never prints itself.
    #[test]
    fn a_secret_does_not_print_its_key() {
        let secret = TokenSecret::from_bytes(b"a key nobody should ever read in a log");
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "TokenSecret(<redacted>)");
        assert!(!rendered.contains("key"), "the rendering mentions the key material");
    }

    /// RFC 4231 test case 1, so the HMAC is the published construction and not something that only
    /// agrees with itself. A MAC that is self-consistent and wrong is still unforgeable, but it is
    /// no longer reviewable against anything.
    #[test]
    fn the_hmac_matches_the_published_vector() {
        let key = [0x0b_u8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(encode_hex(&tag), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    /// RFC 4231 test case 3, which uses a key longer than the message, and case 6, whose key is
    /// longer than the block and must therefore be hashed down first — the branch nothing else
    /// here reaches.
    #[test]
    fn the_hmac_matches_the_published_vector_for_a_long_key() {
        let tag = hmac_sha256(&[0xaa_u8; 131], b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(encode_hex(&tag), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    /// Both directions of the constant-time comparison, including the lengths.
    #[test]
    fn the_constant_time_comparison_answers_both_ways() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"), "a difference in the last byte");
        assert!(!ct_eq(b"abcd", b"Abcd"), "a difference in the first byte");
        assert!(!ct_eq(b"abcd", b"abc"), "a prefix is not equal");
        assert!(!ct_eq(b"abc", b"abcd"), "and neither is an extension");
    }

    /// Negative: one position has exactly one token. An uppercase body decodes to the same bytes
    /// and must still be refused, or the token is malleable.
    #[test]
    fn a_non_canonical_encoding_of_the_same_position_is_refused() {
        let secret = TokenSecret::generate();
        let token = secret.mint(&scope(), "a/2.txt");
        let (body, tag) = token.rsplit_once('-').expect("a minted token carries a tag");
        let shouted = format!("{}-{tag}", body.to_uppercase());
        assert_ne!(shouted, token, "the position has no uppercase hex digits to shout");
        assert_eq!(secret.read(&scope(), &shouted), None);
        assert_eq!(secret.read(&scope(), &token).as_deref(), Some("a/2.txt"), "the control direction");
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(encode_hex(b"a/2.txt"), "612f322e747874");
        assert_eq!(decode_hex("612f322e747874").as_deref(), Some(&b"a/2.txt"[..]));
        assert_eq!(decode_hex("abc"), None, "an odd number of digits is not hex");
        assert_eq!(decode_hex("zz"), None);
    }
}
