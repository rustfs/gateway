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

//! MinIO's bare body literals, as the RustFS profile reads them (rustfs/backlog#1677, R6).
//!
//! Responsible for: [`BODY_LITERALS`], the documents the literals stand for, and [`body_literal`],
//! the replacement a generated decoder applies to a buffered body on a view marked
//! [`MetaView::with_body_literals`].
//! NOT responsible for: which operations take a literal (their IR's `xml.body_literal`, emitted by
//! codegen), which assemblies mark the view (the assembly's RustFS profile), or the digest check,
//! which runs before it over the bytes that arrived (`super::value::verify_body_digest`).
//! Upstream: the view (`super::view::MetaView::with_body_literals`). Downstream: the generated
//! decoders of PutBucketVersioning and PutObjectLockConfiguration, through `super::value`.

use bytes::Bytes;

use crate::codec::view::MetaView;

/// The documents MinIO's bare body literals stand for, by the request root of the operation that
/// accepts one: `(root, literal, document)`.
///
/// Legacy RustFS, built with MinIO support, reads a PutBucketVersioning or PutObjectLockConfiguration
/// body whose ASCII-trimmed bytes are exactly `Enabled` as the configuration with that one member
/// set and nothing else, and every other body as XML (rustfs/backlog#1677, R6). Each document here
/// decodes to exactly that input: one member, `Enabled`, every other member absent.
pub const BODY_LITERALS: [(&str, &str, &str); 2] = [
    (
        "ObjectLockConfiguration",
        "Enabled",
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>",
    ),
    (
        "VersioningConfiguration",
        "Enabled",
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    ),
];

/// A buffered XML body, or the document it stands for when it is a bare body literal a deployment
/// accepts.
///
/// Generated into the decoder of every operation whose IR says `xml.body_literal`, right after
/// [`super::value::verify_body_digest`] and before the parse: the digest is always checked over the bytes that
/// arrived, and only the parse sees the document. On a view the deployment did not mark with
/// [`MetaView::with_body_literals`] — every assembly but the RustFS profile — `body` is returned
/// unchanged, so the literal is `MalformedXML` there as before. On a marked view, a body whose
/// ASCII-trimmed bytes equal the literal for `root` in [`BODY_LITERALS`] is replaced by its
/// document; anything else, `enabled` and a bare `Suspended` included, is returned unchanged.
#[must_use]
pub fn body_literal(request: &MetaView<'_>, root: &str, body: Bytes) -> Bytes {
    if !request.body_literals_accepted() {
        return body;
    }
    match BODY_LITERALS.iter().find(|(owner, _, _)| *owner == root) {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads MinIO's bare `Enabled` as a
        // versioning or object-lock document, which no S3 client sends and the S3 model does not
        // define, so any stray body that trims to the word switches versioning or object lock on.
        // Kept so a client of RustFS's MinIO dialect keeps working; the intended future behaviour is
        // the core default, `400 MalformedXML` for a body that is not the document
        // (c-bucketconfig-0060).
        Some((_, literal, document)) if body.trim_ascii() == literal.as_bytes() => Bytes::from_static(document.as_bytes()),
        _ => body,
    }
}
