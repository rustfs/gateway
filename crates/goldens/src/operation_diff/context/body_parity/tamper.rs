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

//! Body parity, the refusal rows both stacks agree on: a bad chunk signature, an altered chunk, a
//! body cut inside a signed chunk, a bad trailer signature, a decoded length that disagrees with
//! the body, and a body that does not hash to its signed digest.
//!
//! Responsible for: pinning, per row, both answers, the bytes each handler was handed before the
//! refusal (the verified prefix, never a byte of the chunk that failed), that neither handler saw
//! end of body, and the gateway's connection verdict; and, for the decoded length, the one place
//! the two revisions differ — the baseline accepts what 0.17.0 and the gateway refuse.
//! NOT responsible for: rows where the stacks disagree (`divergences`).
//! Upstream: the harness in `super`. Downstream: nothing.

use rustfs_gateway_types::compat::OracleRevision;

use super::super::super::SEAM_REVISION;
use super::{BodyEnd, Lookup, Mode, Pair, Tamper, Upload, both};

fn object() -> Vec<u8> {
    (0..45_u8).collect()
}

/// Both refused with `answer`, after handing their handlers exactly `prefix`, and neither saw end
/// of body; the gateway's verdict on the connection is `closes`.
fn refused_alike(upload: &Upload, answer: (u16, Option<&str>), prefix: &[u8], closes: bool) -> Pair {
    let pair = both(upload).expect("both stacks answer");
    for (name, side) in [("gateway", &pair.gateway), ("s3s", &pair.oracle)] {
        assert_eq!(side.answer(), answer, "{name}: {:?} {:?}: {side:?}", upload.mode, upload.tamper);
        assert_eq!(side.bytes(), prefix, "{name}: {:?} {:?}", upload.mode, upload.tamper);
        assert!(
            side.ended().is_some_and(|end| end != BodyEnd::Eof),
            "{name}: {:?} {:?} reached end of body",
            upload.mode,
            upload.tamper
        );
    }
    assert_eq!(pair.gateway.closes, Some(closes), "{:?} {:?}", upload.mode, upload.tamper);
    pair
}

const SIGNATURE: (u16, Option<&str>) = (403, Some("SignatureDoesNotMatch"));
const INCOMPLETE: (u16, Option<&str>) = (400, Some("IncompleteBody"));

#[test]
fn a_bad_chunk_signature_or_an_altered_chunk_is_refused_alike_after_the_same_verified_prefix() {
    for mode in Mode::CHUNK_SIGNED {
        for index in [0, 2, 5] {
            for tamper in [Tamper::ChunkSignature(index), Tamper::ChunkData(index)] {
                let upload = Upload::new(mode, &object()).tampered(tamper);
                let pair = refused_alike(&upload, SIGNATURE, upload.before_chunk(index), true);
                // Nothing reaches a trailer source on either side: s3s never fills its handle.
                assert_eq!(pair.gateway.trailer(), Lookup::NoSource);
                assert_eq!(pair.oracle.trailer(), Lookup::Pending);
            }
        }
    }
}

#[test]
fn a_body_cut_inside_a_signed_chunk_is_incomplete_on_both() {
    for mode in Mode::CHUNK_SIGNED {
        for index in [2, 5] {
            let upload = Upload::new(mode, &object()).tampered(Tamper::CutInsideChunk(index));
            refused_alike(&upload, INCOMPLETE, upload.before_chunk(index), true);
        }
    }
}

#[test]
fn a_bad_trailer_signature_is_refused_alike_and_publishes_no_trailer() {
    let upload = Upload::new(Mode::SignedTrailer, &object()).tampered(Tamper::TrailerSignature);
    let pair = refused_alike(&upload, SIGNATURE, &upload.object, true);
    assert_eq!(pair.gateway.trailer(), Lookup::NoSource);
    assert_eq!(pair.oracle.trailer(), Lookup::Pending);
}

/// A declared decoded length one byte either side of the body. The gateway refuses both, holding
/// the handler to the declaration: one short hands it the chunks that fit and refuses the chunk that
/// would pass it, closing; one long hands it everything and refuses at end of body, with the wire
/// body complete. 0.17.0 answers the same with the same bytes; the baseline accepts both, and one
/// short it hands the handler more bytes than its `ContentLength`.
#[test]
fn a_decoded_length_that_disagrees_with_the_body_is_refused_by_the_gateway_and_by_the_candidate() {
    let object = object();
    for mode in Mode::FRAMED {
        for (delta, prefix, closes) in [(1_i64, &object[..], false), (-1, &object[..40], true)] {
            let upload = Upload::new(mode, &object).tampered(Tamper::DecodedLength(delta));
            let pair = both(&upload).expect("both stacks answer");
            let declared = 45 + delta;
            assert_eq!(pair.gateway.answer(), INCOMPLETE, "{mode:?} {delta}");
            assert_eq!(pair.gateway.bytes(), prefix, "{mode:?} {delta}");
            assert_eq!(pair.gateway.content_length(), Some(declared));
            assert_eq!(pair.gateway.closes, Some(closes), "{mode:?} {delta}");
            assert_eq!(pair.oracle.content_length(), Some(declared));
            if SEAM_REVISION == OracleRevision::Baseline {
                assert!(pair.oracle.accepted(), "{mode:?} {delta}: {:?}", pair.oracle);
                assert_eq!(pair.oracle.bytes(), &object[..], "{mode:?} {delta}");
            } else {
                assert_eq!(pair.oracle.answer(), INCOMPLETE, "{mode:?} {delta}");
                assert_eq!(pair.oracle.bytes(), prefix, "{mode:?} {delta}");
                assert!(pair.oracle.ended().is_some_and(|end| end != BodyEnd::Eof));
            }
        }
    }
}

/// c-sig-0596: a header-signed body that does not hash to its signed `x-amz-content-sha256`. The
/// gateway compared the digest only for presigned requests until this slice found it; now both
/// refuse, and neither handler sees end of body. (What each hands over first is rd-body-0008.)
#[test]
fn a_body_that_does_not_hash_to_its_signed_digest_is_refused_on_both() {
    for pieces in [&[][..], &[7][..], &[1][..]] {
        let upload = Upload::new(Mode::FullSha256, &object())
            .tampered(Tamper::PayloadDigest)
            .pieces(pieces);
        let pair = both(&upload).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("XAmzContentSHA256Mismatch")), "{pieces:?}");
        assert_eq!(pair.gateway.closes, Some(false), "the body arrived exactly as framed");
        assert!(pair.gateway.ended().is_some_and(|end| end != BodyEnd::Eof));
        assert_eq!(pair.oracle.ended(), Some(BodyEnd::Failed("Sha256Mismatch".to_owned())), "{pieces:?}");
        assert_eq!(pair.oracle.code.as_deref(), Some("XAmzContentSHA256Mismatch"));
    }
}
