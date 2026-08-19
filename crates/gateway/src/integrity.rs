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

//! What this assembly knows about request-body integrity that the wire layer cannot.
//!
//! Responsible for: [`checksum_subject`], the per-operation fact of what an `x-amz-checksum-*`
//! header is the digest *of*, and [`checksum_refusal`], the response an integrity verdict renders
//! as.
//! NOT responsible for: reading the headers, opening the digests, or comparing them —
//! `rustfs_gateway_http::BodyIntegrity` owns all three, and owns them alone.
//! Upstream: `crate::gate`, the only caller. Downstream: `rustfs-gateway-http`.
//!
//! # Why the subject is decided here and not there
//!
//! `rustfs-gateway-http` knows headers; it does not know operations, and giving it an operation
//! name would be the first thread of a route table in the wire layer. This assembly knows both, so
//! the two facts that depend on the operation live here and travel down as one enumerated value.

use http::Method;
use rustfs_gateway_core::HandlerError;
use rustfs_gateway_http::{BodyIntegrity, ChecksumReject, ChecksumSubject, HeaderView};

use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_transport_limit};

/// What this request's `x-amz-checksum-*` header is the digest of.
///
/// Two rules, both stated here rather than inferred, so that `grep CompleteMultipartUpload` finds
/// the exception:
///
/// * A method that carries no request body carries no claim about one. S3 ignores a `Content-MD5`
///   on a read rather than refusing it, and a digest of bytes that were never sent describes
///   nothing this service received.
/// * `CompleteMultipartUpload`'s checksum header is the digest of the **assembled object**,
///   commonly in the composite `<base64>-N` form, while its body is the completion XML. Comparing
///   them is a check that can only fail — it would answer `400` to every SDK multipart completion
///   that carries a checksum. `Content-MD5` on that operation is still the message body's digest
///   and is still compared.
pub(crate) fn checksum_subject(method: &Method, operation: &str) -> ChecksumSubject {
    if !matches!(*method, Method::PUT | Method::POST) {
        return ChecksumSubject::None;
    }
    if operation == "CompleteMultipartUpload" {
        return ChecksumSubject::NamedResource;
    }
    ChecksumSubject::RequestBody
}

/// Renders an integrity refusal.
///
/// The connection is kept, and for two different reasons depending on where the refusal came from.
/// An arbitration refusal fires before a body byte is polled, which is the same pre-commit position
/// every other head-level refusal answers from with `MayKeepAlive`. A comparison refusal fires
/// after the body has been read to its end — that is how the digest was computed at all — so
/// RFC 9112 §9.3 leaves nothing to drain. Either way the peer is a client with a bad request rather
/// than one this service has reason to disconnect.
pub(crate) fn checksum_refusal(reject: ChecksumReject) -> S3Error {
    from_transport_limit(
        HandlerError::new(reject.error_code(), reject.message()),
        reject.to_status(),
        ConnectionIntent::MayKeepAlive,
    )
}

/// Settles what one request body owes, from the head and above the body read.
///
/// Called before `SealedBody::read` and never after: two integrity claims cannot be reconciled by
/// any number of body bytes, so a request carrying a contradiction is malformed however it ends,
/// and refusing it after the transfer would pay for the transfer first.
///
/// `headers` must be the **accepted** head — the map the codec binds the operation input from —
/// and not the copy taken before the stage filters run. The two differ exactly when a filter writes
/// a checksum header, and binding a claim into an input that nothing compared against the body is
/// the shape this whole seam exists to remove.
///
/// # Errors
///
/// The rendered [`ChecksumReject`] for any ambiguity in the head.
pub(crate) fn resolve(headers: &HeaderView<'_>, method: &Method, operation: &str) -> Result<BodyIntegrity, S3Error> {
    BodyIntegrity::resolve(headers, checksum_subject(method, operation)).map_err(checksum_refusal)
}
