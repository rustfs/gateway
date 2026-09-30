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

//! Seam rows for an aws-chunked upload's trailer section (rustfs/gateway#1148): the trailer handle
//! each stack hands a RustFS upload body, read once the body ended, and the checksum algorithm that
//! body echoes the trailer's checksum by.
//!
//! Responsible for: `PutObject` and `UploadPart` uploads that declare a checksum trailer, signed
//! as an SDK signs them, with the algorithm named in each header or none, and a declaration
//! neither stack hands over. NOT responsible for: the chunk-signed modes, which the replay cannot
//! sign (the goldens body parity diff covers them, and the handle's states), anonymous uploads,
//! whose framing only the gateway decodes (rustfs/gateway#1060), or judging (`tests/seam.rs`).
//! Upstream: none. Downstream: `super`.

use super::{Expect, SeamRow, row};
use crate::request::RawRequest;
use crate::samples::UPLOAD_ID;

/// `hello` in one chunk, with its CRC32 trailer.
const BODY: &[u8] = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:NhCmhg==\r\n\r\n";

/// The trailer declaration of [`BODY`].
const DECLARED: &str = "x-amz-checksum-crc32";

/// A `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload of [`BODY`] to `target`, declaring `declared` and
/// carrying `extra` header lines, before signing.
fn trailer_upload(target: &str, declared: &str, extra: &[(&str, &str)]) -> RawRequest {
    extra.iter().fold(
        RawRequest::put(target, BODY)
            .header("content-encoding", "aws-chunked")
            .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            .header("x-amz-trailer", declared)
            .header("x-amz-decoded-content-length", "5"),
        |request, (name, value)| request.header(name, value),
    )
}

/// [`trailer_upload`] declaring [`DECLARED`], signed as an SDK signs it: the only admission under
/// which the legacy stack decodes the framing and attaches a trailer handle.
fn signed(target: &str, extra: &[(&str, &str)]) -> RawRequest {
    signed_declaring(target, DECLARED, extra)
}

fn signed_declaring(target: &str, declared: &str, extra: &[(&str, &str)]) -> RawRequest {
    let request = trailer_upload(target, declared, extra);
    // A signing failure leaves the row unsigned, and it then fails on its differences.
    crate::sign::signed(&request).unwrap_or(request)
}

/// The gateway strips `aws-chunked` from an object's stored `Content-Encoding` and RustFS strips it
/// too (`sd-0033`): every signed `PutObject` here differs there and nowhere else.
const STRIPPED: Expect = Expect::Differs(&["sd-0033"]);

pub(super) fn rows() -> Vec<SeamRow> {
    let part = format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}");
    vec![
        row("put-object-trailer-upload", signed("/bucket/k", &[]), STRIPPED),
        row(
            "put-object-trailer-upload-as-an-sdk-sends-it",
            signed("/bucket/k", &[("x-amz-sdk-checksum-algorithm", "CRC32")]),
            STRIPPED,
        ),
        row(
            "put-object-trailer-upload-naming-its-algorithm",
            signed("/bucket/k", &[("x-amz-checksum-algorithm", "CRC32")]),
            STRIPPED,
        ),
        // The header legacy RustFS reads wins over the declaration, whatever it names.
        row(
            "put-object-trailer-upload-naming-another-algorithm",
            signed(
                "/bucket/k",
                &[
                    ("x-amz-checksum-algorithm", "SHA256"),
                    ("x-amz-sdk-checksum-algorithm", "CRC32"),
                ],
            ),
            STRIPPED,
        ),
        // A part has no stored encoding.
        row("upload-part-trailer-upload", signed(&part, &[]), Expect::Identical),
        row(
            "upload-part-trailer-upload-as-an-sdk-sends-it",
            signed(&part, &[("x-amz-sdk-checksum-algorithm", "CRC32")]),
            Expect::Identical,
        ),
        // Two checksum trailers declared: neither stack hands the upload to a RustFS body.
        row(
            "put-object-trailer-upload-declaring-two-checksums",
            signed_declaring("/bucket/k", "x-amz-checksum-crc32,x-amz-checksum-sha1", &[]),
            Expect::NeitherHandsOver,
        ),
    ]
}
