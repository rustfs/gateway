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

//! Body parity, the divergences: every place the two stacks hand a PutObject handler a different
//! body, trailer or verdict for the same signed upload, each a named test carrying its ruling id
//! (`migration_inventory/request_divergences.rs`).
//!
//! Responsible for: pinning what each side does, under both compiled revisions (they agree on
//! every row here). NOT responsible for: rows the stacks agree on (`matrix`, `tamper`).
//! Upstream: the harness in `super`. Downstream: the register.
//!
//! The common thread: s3s decodes and authenticates aws-chunked but leaves integrity and framing
//! completeness past the chunk chain to the implementation; the gateway settles both before a
//! handler may see end of body. Where s3s accepts, the RustFS A4 adapter (`TrailerSource`,
//! rustfs/backlog#1735) is what refuses — or nothing does.

use super::{Lookup, Mode, Tamper, Trailers, Upload, both, crc32_base64};

fn object() -> Vec<u8> {
    (0..45_u8).collect()
}

// ── named divergences ─────────────────────────────────────────────────────────────────────────

/// A checksum trailer that does not match the decoded body — its value altered, or (unsigned) a
/// data byte altered under a correct value. The gateway refuses before end of body; s3s ends the
/// body and hands the app body the wrong value to find.
///
/// Ruling: `rd-body-0001`
#[test]
fn a_checksum_trailer_that_does_not_match_the_body_is_refused_only_by_the_gateway() {
    let object = object();
    let rows = [
        (Mode::SignedTrailer, Tamper::TrailerChecksum),
        (Mode::UnsignedTrailer, Tamper::TrailerChecksum),
        (Mode::UnsignedTrailer, Tamper::ChunkData(2)),
    ];
    for (mode, tamper) in rows {
        let pair = both(&Upload::new(mode, &object).tampered(tamper)).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("XAmzContentChecksumMismatch")), "{mode:?} {tamper:?}");
        assert_eq!(pair.gateway.closes, Some(false));
        assert!(!pair.gateway.accepted());
        assert!(pair.oracle.accepted(), "{mode:?} {tamper:?}: {:?}", pair.oracle);
        let delivered = crc32_base64(pair.oracle.bytes());
        match pair.oracle.trailer() {
            Lookup::Present(value) => assert_ne!(value, delivered, "{mode:?} {tamper:?}"),
            other => panic!("{mode:?} {tamper:?}: s3s published no trailer: {other:?}"),
        }
    }
}

/// A trailer declared by `x-amz-trailer` that never arrives: the body ends after the terminal chunk.
/// The gateway refuses; s3s ends the body with its handle unfilled, which the A4 adapter reads as
/// `Pending` at end of body and rio refuses.
///
/// Ruling: `rd-body-0002`
#[test]
fn a_declared_trailer_that_never_arrives_is_refused_only_by_the_gateway() {
    for (mode, answer, closes) in [
        (Mode::SignedTrailer, (403, Some("SignatureDoesNotMatch")), true),
        (Mode::UnsignedTrailer, (400, Some("InvalidRequest")), false),
    ] {
        let pair = both(&Upload::new(mode, &object()).tampered(Tamper::MissingTrailer)).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), answer, "{mode:?}");
        assert_eq!(pair.gateway.closes, Some(closes), "{mode:?}");
        assert!(pair.oracle.accepted(), "{mode:?}: {:?}", pair.oracle);
        assert_eq!(pair.oracle.trailer(), Lookup::Pending, "{mode:?}");
    }
}

/// The wire body stops five bytes early, after the last data chunk, with `Content-Length` saying
/// so. The gateway requires the terminal chunk and a complete trailer section; s3s accepts a signed
/// body whose terminal chunk is cut, hands the unsigned trailer's cut value on, and refuses only the
/// signed trailer, whose signature no longer verifies.
///
/// Ruling: `rd-body-0003`
#[test]
fn a_body_cut_short_after_its_last_data_chunk_is_accepted_only_by_s3s() {
    let object = object();
    for mode in Mode::FRAMED {
        let pair = both(&Upload::new(mode, &object).tampered(Tamper::Truncate(5))).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("IncompleteBody")), "{mode:?}");
        assert_eq!(pair.gateway.closes, Some(true), "{mode:?}");
        match mode {
            Mode::Signed => assert!(pair.oracle.accepted(), "{:?}", pair.oracle),
            Mode::UnsignedTrailer => {
                assert!(pair.oracle.accepted(), "{:?}", pair.oracle);
                assert_eq!(pair.oracle.trailer(), Lookup::Present("17zzxQ=".to_owned()));
                assert_ne!(crc32_base64(&object), "17zzxQ=");
            }
            _ => assert_eq!(pair.oracle.answer(), (403, Some("SignatureDoesNotMatch"))),
        }
    }
}

/// A chunk of one mebibyte and one byte. The gateway refuses it at its size line, before one data
/// byte is read or delivered and after one transport piece; s3s buffers signed chunks up to 256 MiB
/// and streams unsigned ones of any size.
///
/// Ruling: `rd-body-0004`
#[test]
fn a_chunk_over_one_mebibyte_is_refused_only_by_the_gateway() {
    let piece = 16 * 1024;
    for mode in Mode::FRAMED {
        let object = vec![7_u8; 2 * 1024 * 1024 + 1];
        let upload = Upload::new(mode, &object).chunked(1024 * 1024 + 1).pieces(&[piece]);
        let pair = both(&upload).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("InvalidChunkSizeError")), "{mode:?}");
        assert_eq!(pair.gateway.closes, Some(true));
        assert!(pair.gateway.bytes().is_empty());
        assert_eq!(pair.gateway.wire.delivered, piece as u64, "{mode:?}: read past the refused header");
        assert!(pair.oracle.accepted(), "{mode:?}: {:?}", pair.oracle);
    }
}

/// Twenty-two one-byte chunks. The gateway allows a decoded body of `n` bytes at most
/// `ceil(n / 1 KiB) + 16` chunk lines, and framing overhead of five per cent once past 4 KiB; the
/// seventeenth line is refused. s3s accepts any number of chunks.
///
/// Ruling: `rd-body-0005`
#[test]
fn a_micro_chunk_flood_is_refused_only_by_the_gateway() {
    let object = object();
    for mode in Mode::FRAMED {
        let upload = Upload::new(mode, &object[..22]).chunked(1);
        let pair = both(&upload).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("InvalidRequest")), "{mode:?}");
        assert_eq!(pair.gateway.closes, Some(true));
        assert_eq!(pair.gateway.bytes(), &object[..17], "{mode:?}");
        assert!(pair.oracle.accepted(), "{mode:?}: {:?}", pair.oracle);
        assert_eq!(pair.oracle.bytes(), &object[..22]);
    }
}

/// The trailer fields a handler reads after a signed trailer: the gateway includes the verified
/// `x-amz-trailer-signature`; s3s strips it.
///
/// Ruling: `rd-body-0006`
#[test]
fn the_gateway_hands_the_verified_trailer_signature_to_the_handler_and_s3s_does_not() {
    let pair = both(&Upload::new(Mode::SignedTrailer, &object())).expect("both stacks answer");
    let names = |trailers: Option<&Trailers>| trailers.map(|trailers| trailers.names().join(","));
    assert_eq!(
        names(pair.gateway.handler.as_ref().map(|view| &view.trailers)).as_deref(),
        Some("x-amz-checksum-crc32,x-amz-trailer-signature")
    );
    assert_eq!(
        names(pair.oracle.handler.as_ref().map(|view| &view.trailers)).as_deref(),
        Some("x-amz-checksum-crc32")
    );
}

/// The trailer view of an upload that declares none. After end of body the gateway hands an empty
/// set (every lookup `Missing`); s3s hands a handle that stays `Pending` forever for the untrailered
/// streaming mode, and no handle for a plain body.
///
/// Ruling: `rd-body-0007`
#[test]
fn an_upload_without_a_trailer_leaves_the_s3s_handle_pending_or_absent() {
    for (mode, oracle) in [
        (Mode::Signed, Trailers::Pending),
        (Mode::Unsigned, Trailers::Absent),
        (Mode::FullSha256, Trailers::Absent),
    ] {
        let pair = both(&Upload::new(mode, &object())).expect("both stacks answer");
        let trailers = |side: &super::Side| side.handler.as_ref().map(|view| view.trailers.clone());
        assert_eq!(trailers(&pair.gateway), Some(Trailers::Fields(Vec::new())), "{mode:?}");
        assert_eq!(trailers(&pair.oracle), Some(oracle), "{mode:?}");
    }
}

/// A body that does not hash to its signed SHA-256 (c-sig-0596). Both refuse; before refusing the
/// gateway hands its handler every byte and fails in place of end of body, where s3s withholds the
/// final transport piece.
///
/// Ruling: `rd-body-0008`
#[test]
fn a_payload_digest_refusal_follows_every_unverified_byte_only_on_the_gateway() {
    let object = object();
    for (pieces, withheld) in [(&[][..], 45), (&[7][..], 3), (&[1][..], 1)] {
        let upload = Upload::new(Mode::FullSha256, &object)
            .tampered(Tamper::PayloadDigest)
            .pieces(pieces);
        let pair = both(&upload).expect("both stacks answer");
        assert_eq!(pair.gateway.bytes().len(), 45, "{pieces:?}");
        assert_eq!(pair.oracle.bytes().len(), 45 - withheld, "{pieces:?}");
        assert!(!pair.gateway.accepted() && !pair.oracle.accepted());
    }
}

/// A body cut inside the last data chunk of an unsigned trailer upload. Both answer
/// `IncompleteBody`; the gateway hands its handler only the complete chunks, s3s streams the part of
/// the cut chunk that arrived.
///
/// Ruling: `rd-body-0009`
#[test]
fn an_unsigned_chunk_cut_short_is_streamed_in_part_only_by_s3s() {
    let object = object();
    let upload = Upload::new(Mode::UnsignedTrailer, &object).tampered(Tamper::CutInsideChunk(5));
    let pair = both(&upload).expect("both stacks answer");
    assert_eq!(pair.gateway.answer(), (400, Some("IncompleteBody")));
    assert_eq!(pair.oracle.answer(), (400, Some("IncompleteBody")));
    assert_eq!(pair.gateway.closes, Some(true));
    assert_eq!(pair.gateway.bytes(), &object[..40]);
    assert_eq!(pair.oracle.bytes(), &object[..42]);
}

/// A declared decoded length the wire body cannot hold: 45 decoded bytes in 33 bytes of unsigned
/// framing. The gateway refuses at the head, before its handler and before reading a byte; s3s
/// reads the body and fails it as incomplete.
///
/// Ruling: `rd-body-0010`
#[test]
fn a_decoded_length_the_wire_cannot_hold_is_refused_at_the_head_only_by_the_gateway() {
    let upload = Upload::new(Mode::UnsignedTrailer, &object()).tampered(Tamper::CutInsideChunk(2));
    let pair = both(&upload).expect("both stacks answer");
    assert_eq!(pair.gateway.answer(), (400, Some("InvalidRequest")));
    assert!(pair.gateway.handler.is_none(), "{:?}", pair.gateway);
    assert_eq!(pair.gateway.wire.delivered, 0);
    assert_eq!(pair.gateway.closes, Some(false));
    assert_eq!(pair.oracle.answer(), (400, Some("IncompleteBody")));
    assert_eq!(pair.oracle.bytes().len(), 20);
}

/// A checksum trailer whose value is not base64 at all. The gateway refuses it in place of end of
/// body; the legacy stack ends the body and publishes the value, which legacy RustFS's storage
/// reader then fails to decode as `500 InternalError` (observed on a legacy RustFS build).
///
/// Ruling: `rd-body-0011`
#[test]
fn an_unreadable_checksum_trailer_is_refused_only_by_the_gateway() {
    for mode in [Mode::SignedTrailer, Mode::UnsignedTrailer] {
        let upload = Upload::new(mode, &object()).tampered(Tamper::TrailerValueUnreadable);
        let pair = both(&upload).expect("both stacks answer");
        assert_eq!(pair.gateway.answer(), (400, Some("InvalidRequest")), "{mode:?}: {:?}", pair.gateway);
        assert!(!pair.gateway.accepted(), "{mode:?}");
        assert!(pair.oracle.accepted(), "{mode:?}: {:?}", pair.oracle);
        assert_eq!(pair.oracle.trailer(), Lookup::Present("not base64!".to_owned()), "{mode:?}");
    }
}
