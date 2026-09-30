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

//! Body parity, the RustFS profile (rustfs/gateway#1148): what a RustFS app body behind the RustFS
//! profile's adapter is handed of a signed upload — its bytes, its length, its trailer handle when
//! it starts and once the body ended, and its checksum members — against what the legacy stack
//! hands it, for every payload mode; and the checksums RustFS answers with from each.
//!
//! Responsible for: the trailer hand-off across the seam (`LegacyTrailers`) and the legacy reading
//! of the upload's checksum algorithm, proven on the pieces both stacks receive.
//! NOT responsible for: the gateway's own handler view, whose differences stay pinned in
//! `divergences` (`rd-body-0006`, `rd-body-0007`), or the refusals (`matrix`, `tamper`).
//! Upstream: the harness in `super`. Downstream: nothing.

use super::{Checksums, HandlerView, Mode, TRAILER, Trailers, Upload, crc32_base64, through_legacy_seam};

/// The checksum header of each echoed algorithm, in [`Checksums::named`] order.
const ECHOED: [(&str, &str); 5] = [
    ("CRC32", "x-amz-checksum-crc32"),
    ("CRC32C", "x-amz-checksum-crc32c"),
    ("SHA1", "x-amz-checksum-sha1"),
    ("SHA256", "x-amz-checksum-sha256"),
    ("CRC64NVME", "x-amz-checksum-crc64nvme"),
];

/// The checksums legacy RustFS answers an upload with, from what its body was handed
/// (`apply_trailing_checksums`, `rustfs/src/app/object/shared.rs:583-615` on rustfs/rustfs
/// `3268c42e00`; `UploadPart` reads the same way, `rustfs/src/app/multipart_usecase.rs:1443-1475`):
/// each as handed, but the one of the handed algorithm, which a filled handle replaces with its
/// field of that name — with nothing when the field is missing — and an unfilled or absent handle
/// leaves as handed.
fn echoed(checksums: &Checksums, trailers: &Trailers) -> [Option<String>; 5] {
    let mut echoed = checksums.named.clone();
    let Some(algorithm) = checksums.algorithm.as_deref() else {
        return echoed;
    };
    let Some(index) = ECHOED.iter().position(|(name, _)| *name == algorithm) else {
        return echoed;
    };
    if let Trailers::Fields(fields) = trailers {
        echoed[index] = fields
            .iter()
            .find(|(field, _)| field == ECHOED[index].1)
            .map(|(_, value)| value.clone());
    }
    echoed
}

fn object() -> Vec<u8> {
    (0..45_u8).collect()
}

/// Every mode and header variant the rows below send: the bare upload; the algorithm named in the
/// header legacy RustFS reads; an SDK's upload, which names it in the header the model binds and
/// carries its checksum in the trailer the mode declares, or else in a header; and — on a mode
/// without a trailer — the algorithm legacy RustFS reads with its checksum as a header.
fn uploads() -> Vec<(String, Upload)> {
    let object = object();
    let checksum = crc32_base64(&object);
    let mut uploads = Vec::new();
    for mode in Mode::ALL {
        let upload = || Upload::new(mode, &object);
        uploads.push((format!("{mode:?}"), upload()));
        uploads.push((format!("{mode:?} naming CRC32"), upload().header("x-amz-checksum-algorithm", "CRC32")));
        let sdk = upload().header("x-amz-sdk-checksum-algorithm", "CRC32");
        let sdk = if mode.trailer() {
            sdk
        } else {
            sdk.header(TRAILER, checksum.clone())
        };
        uploads.push((format!("{mode:?} as an SDK sends it"), sdk));
        if !mode.trailer() {
            uploads.push((
                format!("{mode:?} with a CRC32 header checksum"),
                upload()
                    .header("x-amz-checksum-algorithm", "CRC32")
                    .header(TRAILER, checksum.clone()),
            ));
        }
    }
    uploads
}

/// Every mode and header variant: the RustFS body behind the RustFS profile's adapter is handed
/// what the legacy stack hands it — the bytes, the length, the trailer handle in the same state
/// when it starts and once the body ended (no handle for a plain body, one left unfilled for an
/// aws-chunked body without a trailer, the fields but the trailer signature otherwise), and the
/// checksum members, the algorithm read as the legacy decoder reads it.
#[test]
fn the_rustfs_profile_hands_every_upload_over_as_the_legacy_stack_hands_it() {
    for (name, upload) in uploads() {
        let (view, oracle) = through_legacy_seam(&upload).unwrap_or_else(|error| panic!("{name}: {error}"));
        let view: HandlerView = view.unwrap_or_else(|error| panic!("{name}: the seam refused: {error}"));
        assert_eq!(view.bytes, oracle.bytes, "{name}");
        assert_eq!(view.content_length, oracle.content_length, "{name}");
        assert_eq!(view.end, oracle.end, "{name}");
        assert_eq!(view.trailers_at_mount, oracle.trailers_at_mount, "{name}");
        assert_eq!(view.trailers, oracle.trailers, "{name}");
        assert_eq!(view.checksums, oracle.checksums, "{name}");
    }
}

/// The states themselves, per mode, as the legacy stack leaves them.
#[test]
fn each_mode_leaves_the_trailer_handle_in_the_legacy_state() {
    let object = object();
    let filled = Trailers::Fields(vec![(TRAILER.to_owned(), crc32_base64(&object))]);
    for (mode, at_mount, at_end) in [
        (Mode::Signed, Trailers::Pending, Trailers::Pending),
        (Mode::SignedTrailer, Trailers::Pending, filled.clone()),
        (Mode::UnsignedTrailer, Trailers::Pending, filled.clone()),
        (Mode::Unsigned, Trailers::Absent, Trailers::Absent),
        (Mode::FullSha256, Trailers::Absent, Trailers::Absent),
    ] {
        let (view, oracle) = through_legacy_seam(&Upload::new(mode, &object)).expect("both stacks hand it over");
        let view = view.expect("the seam converts");
        assert_eq!((&view.trailers_at_mount, &view.trailers), (&at_mount, &at_end), "{mode:?}");
        assert_eq!((&oracle.trailers_at_mount, &oracle.trailers), (&at_mount, &at_end), "{mode:?}");
    }
}

/// The data the RustFS body writes from the hand-off: the checksums it answers the upload with are
/// the ones it answers behind the legacy stack, for every mode and header variant. The trailer's
/// checksum replaces the header's only once the section arrived, so the unfilled handle of an
/// aws-chunked upload without a trailer must stay unfilled for the header's checksum to be kept.
#[test]
fn the_rustfs_profile_answers_the_checksums_legacy_rustfs_answers() {
    for (name, upload) in uploads() {
        let (view, oracle) = through_legacy_seam(&upload).unwrap_or_else(|error| panic!("{name}: {error}"));
        let view = view.unwrap_or_else(|error| panic!("{name}: the seam refused: {error}"));
        let (Some(checksums), Some(legacy)) = (&view.checksums, &oracle.checksums) else {
            panic!("{name}: both sides record their checksum members");
        };
        assert_eq!(echoed(checksums, &view.trailers), echoed(legacy, &oracle.trailers), "{name}");
    }
}

/// Negative — the model tells the states apart: an unfilled handle keeps the header's checksum, a
/// filled one without the field answers none, a filled one with it answers the trailer's.
#[test]
fn n_the_echo_model_tells_every_handle_state_apart() {
    let checksums = Checksums {
        algorithm: Some("CRC32".to_owned()),
        named: [Some("header".to_owned()), None, None, None, None],
    };
    let kept = [Some("header".to_owned()), None, None, None, None];
    assert_eq!(echoed(&checksums, &Trailers::Pending), kept);
    assert_eq!(echoed(&checksums, &Trailers::Absent), kept);
    assert_eq!(echoed(&checksums, &Trailers::Fields(Vec::new())), [None, None, None, None, None]);
    let trailer = Trailers::Fields(vec![(TRAILER.to_owned(), "trailer".to_owned())]);
    assert_eq!(echoed(&checksums, &trailer), [Some("trailer".to_owned()), None, None, None, None]);
    let unnamed = Checksums {
        algorithm: None,
        ..checksums.clone()
    };
    assert_eq!(echoed(&unnamed, &trailer), kept);
}
