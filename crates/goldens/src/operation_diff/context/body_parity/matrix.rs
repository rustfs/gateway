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

//! Body parity, the zero-diff rows: every payload mode, untampered, reaches both handlers alike;
//! and where the trailer handoff to a RustFS app body stands under this revision.
//!
//! Responsible for: pinning, for `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, its `-TRAILER` form,
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, `UNSIGNED-PAYLOAD` and a full SHA-256, that both handlers
//! read the same decoded bytes — each wire byte read once, nothing after end of body — the same
//! decoded `ContentLength`, and the same checksum trailer value; that a one-mebibyte chunk (botocore's
//! aws-chunked default) passes on both; and that the seam carries an untrailered upload to the app
//! body unchanged while refusing a trailered one, closed, until s3s can mint a trailer handle.
//! NOT responsible for: refusals (`tamper`), divergences (`divergences`), generated inputs
//! (`properties`).
//! Upstream: the harness in `super`. Downstream: nothing.

use super::{BodyEnd, Lookup, Mode, Pair, Trailers, Upload, both, crc32_base64, through_seam};

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

/// Both stacks accept `upload` and hand their handlers exactly its object.
fn same_on_both(upload: &Upload) -> Pair {
    let pair = both(upload).expect("both stacks answer");
    let length = i64::try_from(upload.object.len()).expect("a fixture length");
    for (name, side) in [("gateway", &pair.gateway), ("s3s", &pair.oracle)] {
        assert!(side.accepted(), "{name}: {:?} {:?}: {side:?}", upload.mode, upload.pieces);
        assert_eq!(side.bytes(), upload.object.as_slice(), "{name}: {:?}", upload.mode);
        assert_eq!(side.content_length(), Some(length), "{name}: {:?}", upload.mode);
        assert_eq!(
            (side.wire.delivered, side.wire.eof, side.wire.polled_after_eof),
            (pair.wire_length, 1, 0),
            "{name}: {:?} read the wire body other than once",
            upload.mode
        );
    }
    assert_eq!(pair.gateway.closes, None, "an accepted upload leaves the connection to the transport");
    pair
}

#[test]
fn every_payload_mode_hands_both_handlers_the_same_bytes_and_decoded_length() {
    for mode in Mode::ALL {
        for length in [0, 1, 8, 45, 64] {
            same_on_both(&Upload::new(mode, &object(length)));
        }
    }
}

/// The A4 contract a RustFS `TrailerSource` is written against: the handle is `Pending` when the
/// app body starts, and holds the value once the decoded body has ended. The gateway hands its
/// handler no handle at all; the fields arrive with end of body.
#[test]
fn a_checksum_trailer_reaches_both_handlers_with_the_same_value() {
    for mode in Mode::TRAILERED {
        for length in [0, 45] {
            let upload = Upload::new(mode, &object(length));
            let pair = same_on_both(&upload);
            let expected = Lookup::Present(crc32_base64(&upload.object));
            assert_eq!(pair.gateway.trailer(), expected, "{mode:?}");
            assert_eq!(pair.oracle.trailer(), expected, "{mode:?}");
            let at_mount = |pair: &Pair| pair.oracle.handler.as_ref().map(|view| view.trailers_at_mount.clone());
            assert_eq!(at_mount(&pair), Some(Trailers::Pending), "{mode:?}: the A4 mount contract");
            let gateway_at_mount = pair.gateway.handler.as_ref().map(|view| view.trailers_at_mount.clone());
            assert_eq!(gateway_at_mount, Some(Trailers::Absent));
        }
    }
}

#[test]
fn the_same_bytes_arrive_whatever_the_transport_split() {
    let splits: [&[usize]; 5] = [&[1], &[1, 3, 7], &[16], &[85, 86, 87], &[200]];
    for mode in Mode::ALL {
        for pieces in splits {
            same_on_both(&Upload::new(mode, &object(45)).pieces(pieces));
        }
    }
}

/// botocore frames aws-chunked uploads in one-mebibyte chunks; the gateway's default ceiling is
/// exactly that, and a chunk at the ceiling passes on both stacks.
#[test]
fn a_one_mebibyte_chunk_is_accepted_on_both() {
    for mode in Mode::FRAMED {
        let upload = Upload::new(mode, &object(2 * 1024 * 1024 + 1))
            .chunked(1024 * 1024)
            .pieces(&[16 * 1024]);
        same_on_both(&upload);
    }
}

// ── the trailer handoff ───────────────────────────────────────────────────────────────────────

/// The RustFS adapter's path for an upload with no trailer: the seam's context and input carry the
/// same bytes and decoded length the app body would get from s3s.
#[test]
fn the_seam_carries_an_untrailered_upload_to_the_app_body_unchanged() {
    for mode in [Mode::Signed, Mode::Unsigned, Mode::FullSha256] {
        let upload = Upload::new(mode, &object(45));
        let (status, view) = through_seam(&upload).expect("the adapter's handler runs");
        assert_eq!(status, 200, "{mode:?}: {view:?}");
        assert_eq!(view.context, Ok(()), "{mode:?}");
        assert_eq!(view.content_length, Some(45), "{mode:?}");
        assert_eq!(view.bytes, upload.object, "{mode:?}");
        assert_eq!(view.end, BodyEnd::Eof, "{mode:?}");
    }
}

/// Where the trailer handoff stands (rustfs/backlog#1762, rustfs/backlog#1752): no pinned s3s —
/// the baseline nor 0.17.0, the revision RustFS links — lets anything but its own aws-chunked
/// decoder mint `s3s::TrailingHeaders` (a `pub(crate)` field, filled by the `pub(crate)`
/// `AwsChunkedStream::trailing_headers_handle`), so `S3Request::trailing_headers` cannot carry the
/// fields a gateway body ends with. Both halves of the seam refuse rather than drop them: the
/// context names `trailing_headers`, and the body hands the app body every byte and then an error
/// in place of end of body, so a RustFS app body that verifies trailing checksums never commits.
#[test]
fn a_trailered_upload_is_refused_by_the_seam_after_every_byte_and_before_end_of_body() {
    for mode in Mode::TRAILERED {
        let upload = Upload::new(mode, &object(45));
        let (status, view) = through_seam(&upload).expect("the adapter's handler runs");
        let context = view.context.clone().expect_err("declared trailers are refused");
        assert!(context.contains("trailing_headers"), "{mode:?}: {context}");
        assert_eq!(view.bytes, upload.object, "{mode:?}: every byte reaches the app body");
        match &view.end {
            BodyEnd::Failed(reason) => assert!(reason.contains("cannot carry trailer fields"), "{mode:?}: {reason}"),
            BodyEnd::Eof => panic!("{mode:?}: the seam ended a trailered body as if it had no trailer"),
        }
        assert_eq!(status, 400, "{mode:?}");
    }
}
