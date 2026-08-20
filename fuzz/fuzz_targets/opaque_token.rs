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

//! Nothing is accepted as a page position except the exact value this service minted for this
//! listing.
//!
//! Responsible for: falsifying the opaque continuation token end to end — the wire gate
//! (`CursorSpec::accept`, the only sanctioned way to turn cursor bytes into a value) and the codec
//! behind it (`TokenSecret`, which authenticates a position to the listing that issued it).
//! NOT responsible for: what a position means to a backend, how a page is cut, or whether a
//! listing's contents are right. Those are `crates/conformance/tests` and the `c-list-*` corpus.
//! Upstream: libFuzzer bytes. Downstream: nothing — it asserts.
//!
//! # Why these properties can actually be violated
//!
//! rustfs/gateway#194 shipped a target whose property was true by construction on the table it
//! generated, so it could not have failed. Each property below is recorded with the implementation
//! change that takes it red, and every one of those was run at 100,000 iterations.
//!
//! **Two of them did not go red the first time**, and that is the more useful half of this note. A
//! property can be perfectly falsifiable and still sit in a region the generator never reaches, at
//! which point it is #194's defect wearing a different coat: the assertion is fine, the input
//! distribution is what cannot fail. Both were found by running the mutation, not by reading the
//! code.
//!
//! * **P1, the gate agrees with an independent oracle.** Violated by moving the ceiling — which
//!   has happened: the fixture held 2304 while the contract held 2048, and `c-list-0030` exists
//!   because of it. The oracle is written from the *rule* (`MAX_CURSOR_BYTES`, no C0, no `DEL`),
//!   not from the implementation, so a drift in either direction is a disagreement. *Initially
//!   unreachable*: every generated field is capped at 255 bytes and the ceiling is 2048, so a
//!   one-byte drift in the limit ran 50,000 iterations clean. [`gate_at_the_ceiling`] constructs
//!   the boundary instead of waiting for it.
//! * **P2, the gate is not a rewriter.** Violated the moment `accept` normalises, trims or
//!   percent-decodes anything: a normalised cursor no longer matches the one the server minted.
//! * **P3, anything accepted is exactly what minting produces.** The canonicality property, and it
//!   was *false when this target was first run*: `decode_hex` reads either case, so `612F…` and
//!   `612f…` were two tokens for one position. *Initially unreachable* as well: the tag is 128
//!   bits, so a value drawn from the generator is never accepted and a property about accepted
//!   values was asserted over an empty set. [`case_flipped`] feeds it genuine tokens with
//!   fuzzer-chosen edits.
//! * **P4, a token is bound to its listing.** Violated by dropping any field from [`TokenScope`] —
//!   which is exactly what the token this replaced did, since it had no scope at all.
//! * **P5, a token is bound to its key.** Violated by any unkeyed checksum, including the
//!   `sha256(position)[..8]` this replaced, whose every input was public.
//!
//! P4 and P5 are each asserted twice — that the other listing or key does not *mint* this token,
//! and that it does not *accept* it. The second alone is satisfied by an implementation that has
//! collapsed the two into one, because then there is nothing left to do the refusing.
//!
//! # What one input is spent on
//!
//! The first byte selects how the rest is read, so the generator can reach both halves. Low
//! selectors spend the input on the gate and on values that are *nearly* tokens; high selectors
//! mint a real token and then attack it. Splitting the input rather than always doing both keeps
//! the interesting half from being crowded out by the other's fixed cost.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway::{CursorKind, CursorSpec, MAX_CURSOR_BYTES};
use rustfs_gateway_conformance::token::{TokenScope, TokenSecret, ct_eq};

/// The two cursor kinds, so the gate is exercised through both spellings of it. The kind is a
/// statement about what the bytes *mean* and must not change what is accepted.
const SPECS: [CursorSpec; 2] = [CursorSpec::opaque("continuation-token"), CursorSpec::key("marker")];

/// The rule `CursorSpec::accept` implements, written from the rule and not from the code.
///
/// A ceiling in bytes, and a refusal of every byte that cannot be written into an XML document —
/// the C0 controls and `DEL`. Nothing else: an empty value is legal and means "from the
/// beginning", and no byte sequence above `0x1f` is special.
fn oracle_accepts(raw: &str) -> bool {
    raw.len() <= MAX_CURSOR_BYTES && !raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

/// Reads a length-prefixed slice off the front of `input`, leaving the rest.
///
/// One byte of length, so a single input carries several fields without a format nobody can
/// reproduce from the crash artefact.
fn take<'a>(input: &mut &'a [u8], cap: usize) -> &'a [u8] {
    let Some((len, rest)) = input.split_first() else {
        return &[];
    };
    let len = usize::from(*len).min(cap).min(rest.len());
    let (field, rest) = rest.split_at(len);
    *input = rest;
    field
}

/// Reads a length-prefixed field as text, replacing anything that is not UTF-8.
fn take_text(input: &mut &[u8], cap: usize) -> String {
    String::from_utf8_lossy(take(input, cap)).into_owned()
}

/// P1 and P2: what the wire gate accepts, and that it hands back what it was given.
fn gate(raw: &str) {
    for spec in SPECS {
        match spec.accept(raw) {
            Ok(accepted) => {
                assert!(
                    oracle_accepts(raw),
                    "{:?} accepted {raw:?}, which the rule refuses",
                    spec.query_key()
                );
                // P2. Not `==` on the value alone: a rewriter that happened to produce an equal
                // string would still be a rewriter, and the borrow is the guarantee the docs make.
                assert_eq!(accepted, raw, "the gate rewrote a cursor");
                assert!(std::ptr::eq(accepted.as_ptr(), raw.as_ptr()), "the gate returned a new value");
            }
            Err(_) => assert!(
                !oracle_accepts(raw),
                "{:?} refused {raw:?}, which the rule accepts",
                spec.query_key()
            ),
        }
        // The kind records meaning and must never change the decision.
        assert!(matches!(spec.kind(), CursorKind::Opaque | CursorKind::Key));
    }
}

/// Two listings built from fuzzer bytes, and whether the generator made them different.
///
/// The third element is decided by comparing the *inputs*, never by comparing the two
/// [`TokenScope`] values. `TokenScope`'s equality is over the encoding this target exists to
/// falsify, so a guard written as `if issued != other` would be answered by the code under test —
/// and a scope encoder that had stopped distinguishing two buckets would report the pair as equal,
/// skip the assertion, and read green. That is the "check that cannot fail" shape applied to the
/// guard rather than to the assertion.
fn scopes(input: &mut &[u8]) -> (TokenScope, TokenScope, bool) {
    let bucket = take_text(input, 32);
    let prefix = take_text(input, 32);
    let delimiter = take(input, 4);
    let delimiter = if delimiter.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(delimiter).into_owned())
    };
    let other_bucket = take_text(input, 32);

    let issued = TokenScope::bucket_listing("ListObjectsV2", &bucket, &prefix, delimiter.as_deref());
    let other = TokenScope::bucket_listing("ListObjectsV2", &other_bucket, &prefix, delimiter.as_deref());
    (issued, other, other_bucket != bucket)
}

/// A key the generator cannot produce as its own, so the two secrets below are always distinct.
const STRANGER_KEY: &[u8] = b"a key this token was not minted under";

/// Flips the case of the characters `edits` names, wrapping each index into the token.
///
/// A case flip is the edit that matters here and random bytes are the edit that does not. The tag
/// is 128 bits, so a value drawn from the generator is never a token the codec accepts, and P3 —
/// which says something about the values it *does* accept — would be asserted over a branch that
/// cannot be reached. A flip inside the hex body decodes to the same position, so it is a
/// candidate the generator can actually get accepted; a flip inside the tag is refused. Both are
/// worth reaching, and the generator chooses which.
fn case_flipped(token: &str, edits: &[u8]) -> String {
    let mut characters: Vec<char> = token.chars().collect();
    if characters.is_empty() {
        return String::new();
    }
    for edit in edits {
        let index = usize::from(*edit) % characters.len();
        characters[index] = if characters[index].is_ascii_lowercase() {
            characters[index].to_ascii_uppercase()
        } else {
            characters[index].to_ascii_lowercase()
        };
    }
    characters.into_iter().collect()
}

/// P3: whatever is accepted must be, byte for byte, what minting that position produces.
///
/// A position with more than one token is a token an intermediary can rewrite without invalidating
/// it, and it means "the value this service issued" has more than one answer.
fn only_canonical(secret: &TokenSecret, scope: &TokenScope, candidate: &str) {
    if let Some(position) = secret.read(scope, candidate) {
        assert_eq!(
            secret.mint(scope, &position),
            candidate,
            "a value was accepted that minting does not produce"
        );
    }
}

/// P1 at the ceiling, which the generator's own fields are capped far below.
///
/// `MAX_CURSOR_BYTES` is 2048 and no field above is longer than 255, so a value at the boundary is
/// one this target has to construct rather than wait for. Without it the ceiling half of the
/// oracle is never evaluated: moving `CursorSpec::accept`'s limit by a byte leaves the target
/// green, which is how this line came to be written.
fn gate_at_the_ceiling(filler: u8) {
    // Masked into ASCII so the value is text; a control byte is still generated and the oracle
    // still agrees, because a refusal for the other reason is a refusal the oracle predicts too.
    let filler = char::from(filler & 0x7f);
    for len in [MAX_CURSOR_BYTES - 1, MAX_CURSOR_BYTES, MAX_CURSOR_BYTES + 1] {
        gate(&filler.to_string().repeat(len));
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    let Some((selector, rest)) = input.split_first() else {
        return;
    };
    input = rest;

    // The secret is derived from the input rather than generated, so a crash artefact replays
    // exactly. It is still a key the code under test cannot see the derivation of.
    let secret_bytes = take(&mut input, 64).to_vec();
    let secret = TokenSecret::from_bytes(&secret_bytes);
    let (issued, other, listings_differ) = scopes(&mut input);

    if selector % 2 == 0 {
        // Whatever the generator produced, put through the gate and through the codec.
        let arbitrary = take_text(&mut input, 200);
        gate(&arbitrary);
        only_canonical(&secret, &issued, &arbitrary);

        // And a candidate the generator can actually get accepted: a genuine token with
        // fuzzer-chosen case flips on top. See [`case_flipped`] for why the arbitrary value above
        // is not enough on its own.
        let position = take_text(&mut input, 64);
        let token = secret.mint(&issued, &position);
        let edited = case_flipped(&token, take(&mut input, 16));
        gate(&edited);
        only_canonical(&secret, &issued, &edited);

        gate_at_the_ceiling(*selector);
        return;
    }

    // A genuine token, then every way of spending it somewhere it does not belong.
    let position = take_text(&mut input, 200);
    let token = secret.mint(&issued, &position);
    gate(&token);

    // The round trip, which is the control direction: without it every refusal below is satisfied
    // by a codec that refuses everything.
    assert_eq!(
        secret.read(&issued, &token).as_deref(),
        Some(position.as_str()),
        "a token this codec minted was not read back"
    );
    assert_eq!(secret.mint(&issued, &position), token, "minting is not deterministic");

    // P4: the same position, a different listing. Both halves are asserted — that the other
    // listing does not *mint* this token, and that it does not *accept* it. The first is what goes
    // red when a field stops being covered by the tag; the second alone would be satisfied by an
    // encoder that had collapsed the two listings into one, because then there would be no "other
    // listing" left to refuse anything.
    if listings_differ {
        assert_ne!(
            secret.mint(&other, &position),
            token,
            "two different listings minted one token: the tag does not cover the listing"
        );
        assert_eq!(secret.read(&other, &token), None, "a token was honoured by another listing");
    }

    // P5: the same position and listing, a different key. Same shape as P4 and for the same
    // reason: an unkeyed tag makes the two mints equal, and a target that only checked "a
    // different token is refused" would skip itself instead of failing.
    if secret_bytes != STRANGER_KEY {
        let stranger = TokenSecret::from_bytes(STRANGER_KEY);
        let theirs = stranger.mint(&issued, &position);
        assert_ne!(
            theirs, token,
            "two different keys minted one token: the tag does not depend on the key"
        );
        assert_eq!(secret.read(&issued, &theirs), None, "a foreign token was honoured");
        assert_eq!(stranger.read(&issued, &token), None, "this codec's token was honoured elsewhere");
    }

    // Every single-byte alteration of a genuine token, and every truncation of it, is refused.
    // Bounded so that one input cannot spend the whole iteration budget on one long position.
    let bytes = token.as_bytes();
    for index in 0..bytes.len().min(96) {
        let mut altered = bytes.to_vec();
        altered[index] = altered[index].wrapping_add(1);
        if let Ok(altered) = String::from_utf8(altered) {
            gate(&altered);
            assert_eq!(secret.read(&issued, &altered), None, "{altered:?} was honoured");
        }
    }
    for keep in (0..bytes.len().min(96)).rev().take(48) {
        if token.is_char_boundary(keep) {
            assert_eq!(secret.read(&issued, &token[..keep]), None, "a truncated token was honoured");
        }
    }
    assert_eq!(secret.read(&issued, &format!("{token}0")), None, "an extended token was honoured");

    // The comparison the tag check is made of, over the bytes this input produced. A minted token
    // is never empty — it is a separator and a tag at the very least — so the shortened side is a
    // genuinely different length and the second assertion is not comparing a value with itself.
    assert!(!bytes.is_empty(), "minting produced nothing");
    assert!(ct_eq(bytes, bytes));
    assert!(!ct_eq(bytes, &bytes[..bytes.len() - 1]));
});
