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

//! MinIO's bare body literal, seen through the two generated decoders whose IR says
//! `xml.body_literal` (rustfs/backlog#1677, R6).
//!
//! Responsible for: `Enabled`, ASCII-trimmed, decoding on a marked view to exactly the input the
//! document it stands for decodes to — every member, not only the one it sets — and everything
//! else decoding as before: the literal on an unmarked view, every near miss on a marked one, the
//! literal on an operation whose IR does not accept one, and a `Content-MD5` still checked over the
//! bytes that arrived.
//! NOT responsible for: which operations an assembly marks (`rustfs-gateway`'s builder) or the
//! stored configuration (the seam diff and `compat-sut`).
//! Upstream: `crate::codec::value::body_literal`. Downstream: nothing.

use super::*;
use crate::codec::value::BODY_LITERALS;

const VERSIONING_DOCUMENT: &str = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
const LOCK_DOCUMENT: &str = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";

/// The base64 MD5 of `body`, as `Content-MD5` spells it.
fn md5_of(body: &[u8]) -> String {
    let algorithm = rustfs_gateway_types::ChecksumAlgorithm::Md5;
    let mut digest = algorithm.checksummer();
    digest.update(body);
    rustfs_gateway_types::ChecksumSpec::from_digest(algorithm, &digest.finalize())
        .expect("an MD5 digest is sixteen bytes")
        .render_base64()
        .to_owned()
}

/// Decodes `body` as a PutBucketVersioning, with its own `Content-MD5` unless `md5` overrides it.
fn versioning(body: &[u8], marked: bool, md5: Option<&str>) -> Result<dto::PutBucketVersioningInput, String> {
    decode::<dto::PutBucketVersioning>("/photos?versioning", body, marked, md5)
}

fn lock(body: &[u8], marked: bool) -> Result<dto::PutObjectLockConfigurationInput, String> {
    decode::<dto::PutObjectLockConfiguration>("/photos?object-lock", body, marked, None)
}

fn decode<O: OperationCodec>(target: &str, body: &[u8], marked: bool, md5: Option<&str>) -> Result<O::Input, String> {
    let digest = md5.map_or_else(|| md5_of(body), str::to_owned);
    let request = accepted("PUT", target, &[("content-md5", &digest)]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let view = if marked { view.with_body_literals() } else { view };
    O::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(body))).map_err(|error| error.code().as_str().to_owned())
}

/// The input a body decodes to, with the one member that carries the request's own `Content-MD5`
/// cleared, so two different bodies can be compared member for member.
fn versioning_without_digest(input: dto::PutBucketVersioningInput) -> dto::PutBucketVersioningInput {
    dto::PutBucketVersioningInput {
        content_md5: None,
        ..input
    }
}

fn lock_without_digest(input: dto::PutObjectLockConfigurationInput) -> dto::PutObjectLockConfigurationInput {
    dto::PutObjectLockConfigurationInput {
        content_md5: None,
        ..input
    }
}

/// Every member of an input, as its `Debug` form renders it: the inputs carry no `PartialEq`, and
/// the rendering names every member with its value.
fn members<T: core::fmt::Debug>(input: &T) -> String {
    format!("{input:?}")
}

#[test]
fn the_literal_decodes_to_exactly_what_its_document_decodes_to() {
    let document = versioning_without_digest(versioning(VERSIONING_DOCUMENT.as_bytes(), false, None).expect("the document"));
    assert!(members(&document).contains("Enabled"), "{document:?}");
    for literal in [b"Enabled".as_slice(), b" Enabled\r\n", b"\tEnabled ", b"\x0cEnabled\x0c"] {
        let read = versioning_without_digest(versioning(literal, true, None).expect("the literal on a marked view"));
        assert_eq!(members(&read), members(&document), "{literal:?}");
    }
    let document = lock_without_digest(lock(LOCK_DOCUMENT.as_bytes(), false).expect("the document"));
    let read = lock_without_digest(lock(b"Enabled\n", true).expect("the literal on a marked view"));
    assert_eq!(members(&read), members(&document));
    assert!(read.object_lock_configuration.rule.is_none(), "the literal sets no rule");
}

#[test]
fn n_the_literal_is_malformed_on_an_unmarked_view() {
    assert_eq!(versioning(b"Enabled", false, None).map(|_| ()), Err("MalformedXML".to_owned()));
    assert_eq!(lock(b"Enabled", false).map(|_| ()), Err("MalformedXML".to_owned()));
}

#[test]
fn n_every_near_miss_is_still_malformed_on_a_marked_view() {
    for body in [
        b"enabled".as_slice(),
        b"ENABLED",
        b"Suspended",
        b"Enabled\0",
        b"EnabledX",
        b"En abled",
        b"\"Enabled\"",
        b"\xc2\xa0Enabled",
    ] {
        assert_eq!(versioning(body, true, None).map(|_| ()), Err("MalformedXML".to_owned()), "{body:?}");
        assert_eq!(lock(body, true).map(|_| ()), Err("MalformedXML".to_owned()), "{body:?}");
    }
}

#[test]
fn n_the_digest_is_checked_over_the_bytes_that_arrived() {
    // A Content-MD5 of the document, not of the literal that was sent: refused.
    let document_digest = md5_of(VERSIONING_DOCUMENT.as_bytes());
    assert_eq!(
        versioning(b"Enabled", true, Some(&document_digest)).map(|_| ()),
        Err("BadDigest".to_owned())
    );
    // The literal's own Content-MD5: accepted.
    assert!(versioning(b"Enabled", true, Some(&md5_of(b"Enabled"))).is_ok());
}

#[test]
fn n_an_operation_whose_ir_takes_no_literal_ignores_the_mark() {
    let request = accepted("PUT", "/photos?accelerate", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view").with_body_literals();
    let answer = dto::PutBucketAccelerateConfiguration::decode(&view, RequestBody::Buffered(Bytes::from_static(b"Enabled")));
    assert_eq!(
        answer.map(|_| ()).map_err(|error| error.code().as_str().to_owned()),
        Err("MalformedXML".to_owned())
    );
}

#[test]
fn n_the_expansion_reads_only_its_own_root() {
    let request = accepted("PUT", "/photos?versioning", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view").with_body_literals();
    let body = Bytes::from_static(b"Enabled");
    assert_eq!(
        crate::codec::value::body_literal(&view, "AccelerateConfiguration", body.clone()),
        body,
        "a root with no literal is handed on unchanged"
    );
    for (root, literal, document) in BODY_LITERALS {
        assert_eq!(
            crate::codec::value::body_literal(&view, root, Bytes::from_static(literal.as_bytes())),
            Bytes::from_static(document.as_bytes()),
            "{root}"
        );
    }
}
