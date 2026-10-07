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

//! A checksum-algorithm declaration as the RustFS-profile launcher reads it (rustfs/gateway#1349).
//!
//! Responsible for: an `x-amz-checksum-algorithm` sent on two lines answering `400 InvalidRequest`
//! and an `x-amz-trailer` declaration naming two checksums answering `400 InvalidArgument`, each in
//! legacy RustFS's sentence, on the operations legacy RustFS reads them on, with nothing stored,
//! applied or deleted by a refused write; and the requests legacy RustFS serves being served.
//! NOT responsible for: the rule itself (`rustfs-gateway`'s
//! `builder::view_policy::checksum_declarations`) or the integrity arbitration
//! (`rustfs-gateway-http`).
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.
//!
//! Legacy behaviour, from source (rustfs/rustfs `95268a3b9`): the protocol library RustFS serves S3
//! with reads the checksum-algorithm member through `parse_checksum_algorithm_header` on 33
//! operations, refusing a repeated optional header as `duplicate header: <name>` (`InvalidRequest`)
//! and a declaration naming a second checksum as `invalid header: x-amz-trailer: <value>`
//! (`InvalidArgument`), when it decodes the request; `CompleteMultipartUpload` and every read never
//! call it.

use super::*;

use super::hand_signer::HandSigned;

const ALGORITHM: &str = "x-amz-checksum-algorithm";
const TRAILER: &str = "x-amz-trailer";
const TWO_CHECKSUMS: &str = "x-amz-checksum-crc32,x-amz-checksum-sha256";
const DUPLICATE: &str = "duplicate header: x-amz-checksum-algorithm";
const INVALID_TRAILER: &str = "invalid header: x-amz-trailer: \"x-amz-checksum-crc32,x-amz-checksum-sha256\"";
const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
const DELETE: &[u8] = b"<Delete><Object><Key>kept</Key></Object></Delete>";

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.split_once(&format!("<{name}>"))
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value)
}

/// Asserts a `400` with `code` and `message`, the message read with the XML text escapes it
/// carries on the wire (`&quot;`, `&amp;`) undone — both stacks write a quote as `&quot;`.
fn assert_refused(response: &WireResponse, code: &str, message: &str, what: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{what}: {body}");
    assert_eq!(element(&body, "Code"), Some(code), "{what}: {body}");
    let written = element(&body, "Message").map(|text| text.replace("&quot;", "\"").replace("&amp;", "&"));
    assert_eq!(written.as_deref(), Some(message), "{what}: {body}");
}

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/declared", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/declared/kept", Bytes::from_static(b"kept"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

async fn send(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: &'static [u8],
    extra: &[(&str, &str)],
) -> WireResponse {
    exchange(service, signed(MAIN_KEY, MAIN_SECRET, method, target, Bytes::from_static(body), extra)).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

async fn upload_id(service: &S3Service, key: &str) -> String {
    let created = send(service, http::Method::POST, &format!("/declared/{key}?uploads"), b"", &[]).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    element(&body_of(&created), "UploadId").expect("an upload id").to_owned()
}

/// Negative — an upload declaring its algorithm twice is refused with legacy's duplicate-header
/// answer and stores nothing, whether the two lines agree or not.
#[tokio::test]
async fn n_an_upload_declaring_its_algorithm_twice_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (index, second) in ["CRC32", "SHA256"].into_iter().enumerate() {
        let target = format!("/declared/twice-{index}");
        let refused = send(
            &service,
            http::Method::PUT,
            &target,
            b"hello",
            &[(ALGORITHM, "CRC32"), (ALGORITHM, second)],
        )
        .await;
        assert_refused(&refused, "InvalidRequest", DUPLICATE, second);
        assert_eq!(get(&service, &target).await.status(), 404, "{second}");
    }
    let overwrite = send(
        &service,
        http::Method::PUT,
        "/declared/kept",
        b"other",
        &[(ALGORITHM, "CRC32"), (ALGORITHM, "CRC32")],
    )
    .await;
    assert_refused(&overwrite, "InvalidRequest", DUPLICATE, "overwrite");
    assert_eq!(get(&service, "/declared/kept").await.body().as_ref(), b"kept");
}

/// Negative — a part declaring its algorithm twice is refused, and the upload holds no part.
#[tokio::test]
async fn n_a_part_declaring_its_algorithm_twice_is_not_stored() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let upload = upload_id(&service, "parted").await;
    let target = format!("/declared/parted?partNumber=1&uploadId={upload}");
    let refused = send(
        &service,
        http::Method::PUT,
        &target,
        b"part",
        &[(ALGORITHM, "CRC32"), (ALGORITHM, "CRC32")],
    )
    .await;
    assert_refused(&refused, "InvalidRequest", DUPLICATE, "UploadPart");
    let parts = get(&service, &format!("/declared/parted?uploadId={upload}")).await;
    assert_eq!(parts.status(), 200, "{}", body_of(&parts));
    assert!(!body_of(&parts).contains("<Part>"), "{}", body_of(&parts));
}

/// Negative — the buffered writes and the copy legacy reads the member on refuse it too, and
/// apply nothing: no tag set, no deletion, no copy, no upload.
#[tokio::test]
async fn n_other_writes_declaring_the_algorithm_twice_apply_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let twice = [(ALGORITHM, "CRC32"), (ALGORITHM, "CRC32")];

    let tagging = send(&service, http::Method::PUT, "/declared/kept?tagging", TAGGING, &twice).await;
    assert_refused(&tagging, "InvalidRequest", DUPLICATE, "PutObjectTagging");
    let tags = get(&service, "/declared/kept?tagging").await;
    assert!(!body_of(&tags).contains("<Tag>"), "{}", body_of(&tags));

    let delete = send(&service, http::Method::POST, "/declared?delete", DELETE, &twice).await;
    assert_refused(&delete, "InvalidRequest", DUPLICATE, "DeleteObjects");
    assert_eq!(get(&service, "/declared/kept").await.body().as_ref(), b"kept");

    let copy = [
        (ALGORITHM, "CRC32"),
        (ALGORITHM, "CRC32"),
        ("x-amz-copy-source", "/declared/kept"),
    ];
    let copied = send(&service, http::Method::PUT, "/declared/copy", b"", &copy).await;
    assert_refused(&copied, "InvalidRequest", DUPLICATE, "CopyObject");
    assert_eq!(get(&service, "/declared/copy").await.status(), 404);

    let created = send(&service, http::Method::POST, "/declared/multi?uploads", b"", &twice).await;
    assert_refused(&created, "InvalidRequest", DUPLICATE, "CreateMultipartUpload");
    let uploads = get(&service, "/declared?uploads").await;
    assert!(!body_of(&uploads).contains("<Upload>"), "{}", body_of(&uploads));
}

/// A header-signed `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload of `hello` to `path` whose
/// `x-amz-trailer` declaration is `declared`, its trailer section carrying `hello`'s CRC-32, and
/// `extra` sent signed beside it.
fn trailed(path: &'static str, declared: &'static str, extra: &[(&'static str, &'static str)]) -> http::Request<Bytes> {
    let mut framed = b"5\r\nhello\r\n0\r\n".to_vec();
    framed.extend_from_slice(b"x-amz-checksum-crc32:NhCmhg==\r\n\r\n");
    let mut signer = HandSigned::new(http::Method::PUT, path, Bytes::from(framed))
        .declaring("STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .sending("content-encoding", "aws-chunked", true)
        .sending("x-amz-decoded-content-length", "5", true)
        .sending(TRAILER, declared, true);
    for (name, value) in extra {
        signer = signer.sending(name, value, true);
    }
    signer.request()
}

/// Negative — an upload whose `x-amz-trailer` names two different checksums is refused with
/// legacy's invalid-header answer, quoting the declaration, and stores nothing.
#[tokio::test]
async fn n_an_upload_declaring_two_trailer_checksums_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let refused = exchange(&service, trailed("/declared/trailed", TWO_CHECKSUMS, &[])).await;
    assert_refused(&refused, "InvalidArgument", INVALID_TRAILER, "two checksums");
    assert_eq!(get(&service, "/declared/trailed").await.status(), 404);
}

/// Negative — one checksum declared twice is refused and stores nothing, but not in legacy's
/// words: the signature reads the declaration before any decode does, and refuses the repeated name
/// as an unreadable declaration (`400 InvalidRequest`), where legacy RustFS answers `400
/// InvalidArgument` after its signature check. Both refuse; the code and the stage differ, a
/// difference this profile does not reach (rustfs/gateway#1349).
#[tokio::test]
async fn n_one_trailer_checksum_declared_twice_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let twice = "x-amz-checksum-crc32, x-amz-checksum-crc32";
    let refused = exchange(&service, trailed("/declared/trailed-twice", twice, &[])).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert_eq!(element(&body_of(&refused), "Code"), Some("InvalidRequest"), "{}", body_of(&refused));
    assert_eq!(get(&service, "/declared/trailed-twice").await.status(), 404);
}

/// Negative — beside an algorithm, legacy's decoder does not read the declaration; its storage
/// reader answers `500`, which the profile keeps as the gateway's own client error rather than
/// copy, and nothing is stored either way.
#[tokio::test]
async fn n_two_trailer_checksums_beside_an_algorithm_stay_a_client_error() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let refused = exchange(&service, trailed("/declared/beside", TWO_CHECKSUMS, &[(ALGORITHM, "CRC32")])).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert_eq!(element(&body_of(&refused), "Code"), Some("InvalidRequest"), "{}", body_of(&refused));
    assert_eq!(get(&service, "/declared/beside").await.status(), 404);
}

/// Positive — an upload declaring one trailer checksum is stored as sent.
#[tokio::test]
async fn one_declared_trailer_checksum_is_stored() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let stored = exchange(&service, trailed("/declared/one", "x-amz-checksum-crc32", &[])).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    assert_eq!(get(&service, "/declared/one").await.body().as_ref(), b"hello");
}

/// Positive — what legacy serves is served: a completion and a read carrying the same headers,
/// which legacy never reads on them, and an upload declaring one algorithm once.
#[tokio::test]
async fn requests_legacy_does_not_read_the_declaration_on_are_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;

    let read = send(
        &service,
        http::Method::GET,
        "/declared/kept",
        b"",
        &[(ALGORITHM, "CRC32"), (ALGORITHM, "CRC32")],
    )
    .await;
    assert_eq!((read.status().as_u16(), read.body().as_ref()), (200, &b"kept"[..]), "{}", body_of(&read));

    let once = send(&service, http::Method::PUT, "/declared/once", b"hello", &[(ALGORITHM, "CRC32")]).await;
    assert_eq!(once.status(), 200, "{}", body_of(&once));
    assert_eq!(get(&service, "/declared/once").await.body().as_ref(), b"hello");

    let upload = upload_id(&service, "completed").await;
    let part = send(
        &service,
        http::Method::PUT,
        &format!("/declared/completed?partNumber=1&uploadId={upload}"),
        b"part",
        &[],
    )
    .await;
    assert_eq!(part.status(), 200, "{}", body_of(&part));
    let etag = part
        .headers()
        .iter()
        .find_map(|(name, value)| (name.as_str() == "etag").then(|| value.to_str().ok()).flatten())
        .expect("a part ETag")
        .to_owned();
    let completion =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    let completed = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::POST,
            &format!("/declared/completed?uploadId={upload}"),
            Bytes::from(completion),
            &[(ALGORITHM, "CRC32"), (ALGORITHM, "CRC32")],
        ),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", body_of(&completed));
    assert_eq!(get(&service, "/declared/completed").await.body().as_ref(), b"part");
}
