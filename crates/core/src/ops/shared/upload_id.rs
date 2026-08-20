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

//! An upload id is a capability, and this is the exchange that turns one into the right to act.
//!
//! No `//! Members:` line, and that is the honest state rather than an omission — the same state
//! [`super::part_table`] is in. An `impl Operation` is settled before a request is read, and
//! whether an upload id names an upload *this caller's bucket and key own* is a fact only storage
//! can answer, so no operation module can call this. The caller is the backend, reaching it
//! through the facade re-export, and the conformance fixture is the first one.
//!
//! Responsible for: the single exchange every multipart operation performs on the id it was given
//! — the shapes an id can never have, the resolution against the bucket *and* the key of the
//! request that spent it, and the one refusal all of that renders as. It owns
//! [`ResolvedUploadId`], whose only producer is [`resolve_upload`].
//! NOT responsible for: minting an id, storing or finding an upload (the lookup is the backend's,
//! passed in as a closure), what an upload contains, the part-number and part-size rules
//! (`q-mpu-limits-0038`), or the status the error code renders as —
//! `model/overlays/error-status.toml` owns that.
//! Upstream: `rustfs-gateway-types`' `BucketName`, `ObjectKey` and `ErrorCode`. Downstream: the
//! facade re-export, and through it every backend that answers a multipart request.
//!
//! # Why an id is not enough on its own
//!
//! Knowing an upload id is not evidence of anything: ids travel through logs, referrers and shared
//! traces. s3s#51 is what it costs to treat one as sufficient — a part could be pushed into any
//! upload whose id you had learned, and the owner completed it without ever discovering that a
//! stranger had contributed bytes. Both halves of the resolution are load-bearing: `c-mpu-0029`
//! carries a genuine id from another bucket, and `c-mpu-0030` carries a genuine id from another
//! key in the *same* bucket, so a check scoped by bucket alone still passes the first and fails
//! the second.
//!
//! The rejected alternative was a `check_upload_ownership()` call each handler makes for itself.
//! It has no type relationship to anything, so omitting it compiles — and the omission is exactly
//! the advisory. Here the id arrives as an [`UploadIdClaim`], which has no accessor, and the only
//! value carrying an id a backend can act on is [`ResolvedUploadId`], which only [`resolve_upload`]
//! produces. This is the construction [`super::copy_source::CopySource`] already uses for the
//! second resource a copy names.
//!
//! # Why every refusal is the same refusal
//!
//! A caller who can tell "that id belongs to another bucket" from "no such id" apart — by the
//! code, by the message, by anything in the document — has been told that the id it guessed is
//! genuine, which is the whole of what the id was protecting. So there is exactly one rejection
//! value in this module and every path returns it.

use rustfs_gateway_types::{BucketName, ErrorCode, ObjectKey};

/// AWS's own wording for an id that names nothing this caller may act on.
///
/// One constant rather than one per refusal: see the module note on why the refusals may not be
/// told apart.
const NO_SUCH_UPLOAD: &str =
    "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.";

/// What a backend recorded about an upload when it created it.
///
/// Two accessors and no more. The resolution needs the pair the id was minted for and nothing
/// else, so a backend implements this on whatever it already stores instead of copying its upload
/// record into a shape this crate defined.
pub trait RecordedUpload {
    /// The bucket the upload was created in.
    fn bucket(&self) -> &str;

    /// The key the upload was created for.
    fn key(&self) -> &str;
}

impl<T: RecordedUpload + ?Sized> RecordedUpload for &T {
    fn bucket(&self) -> &str {
        (**self).bucket()
    }

    fn key(&self) -> &str {
        (**self).key()
    }
}

/// The one refusal the upload-id exchange can produce.
///
/// It carries a code and a constant explanation for the same reason
/// [`super::copy_source::CopySourceRejection`] does: a message assembled from the rejected value
/// would echo caller-controlled bytes into an error document. Here it would also echo the id,
/// which is the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl UploadRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// The only rejection. Private, so "there is exactly one" is a fact you can read off this file.
    fn no_such_upload() -> Self {
        Self {
            code: ErrorCode::NO_SUCH_UPLOAD,
            reason: NO_SUCH_UPLOAD,
        }
    }
}

/// An upload id as it arrived: read off the wire, resolved against nothing.
///
/// There is no accessor. A claim can be handed to [`resolve_upload`] and that is all it is for —
/// which is what makes "the id was resolved before it was used" structural rather than a habit.
///
/// No `Debug`, for the same reason [`super::copy_source::CopySource`] has none and with a sharper
/// edge: an upload id **is** the bearer credential, and the failure this whole module exists to
/// answer begins with ids reaching logs, referrers and shared traces. A derived `Debug` makes one
/// `tracing::debug!("{claim:?}")` away from writing a credential into a log line, and
/// `tests/compile_fail/upload_debug.rs` is the proof that it does not compile. No `PartialEq`
/// either: a bearer value invites an `==` that decides something, and nothing here compares one.
#[derive(Clone, Copy)]
pub struct UploadIdClaim<'a> {
    raw: &'a str,
}

impl<'a> UploadIdClaim<'a> {
    /// Wraps the decoded `uploadId` value. The decoder is upstream of this and has already
    /// percent-decoded it exactly once.
    #[must_use]
    pub const fn from_wire(raw: &'a str) -> Self {
        Self { raw }
    }
}

/// An upload id shown to name an upload owned by the bucket and key of the request that spent it.
///
/// No public constructor, no `Default`, and the field is private: `tests/compile_fail` holds the
/// proof that neither spelling of a forged one compiles. A backend reaches storage with
/// [`ResolvedUploadId::id`], so a handler that never performed the exchange has no id to reach it
/// with.
///
/// It carries no `Debug` and no `PartialEq`, for the reason recorded on [`UploadIdClaim`]: the id
/// stays a credential after it has been resolved, and resolving it does not make it printable.
///
/// rustfs/gateway#7 sketches this type as `UploadHandle`. It is not called that, and the reason is
/// mechanical rather than taste: `nothing_on_the_routing_path_holds_a_store` refuses the identifier
/// segment `Handle` anywhere under `crates/core/src`, because that is the vocabulary of the store
/// this crate must never hold. `ResolvedUploadId` also matches the sibling this is modelled on,
/// [`super::copy_source::ResolvedCopySource`]. Do not rename it back.
#[derive(Clone, Copy)]
pub struct ResolvedUploadId<'a> {
    id: &'a str,
}

impl<'a> ResolvedUploadId<'a> {
    /// The resolved id, byte for byte as it arrived.
    #[must_use]
    pub const fn id(&self) -> &'a str {
        self.id
    }
}

/// Whether these bytes could be an id this service minted.
///
/// Four shapes are refused, and the reason is a backend that lays an upload out *under* its id —
/// which is what a filesystem backend does:
///
/// * empty, which names no upload and, joined onto a path, names the directory holding all of them;
/// * an ASCII control byte, which no URL carries and which splits a log line or a path in ways the
///   code reading it back does not expect;
/// * a leading `/`, because `Path::join` discards the base entirely when the argument is absolute;
/// * a `/`-delimited segment that is exactly `..`, which walks out of wherever the upload lives.
///
/// It is deliberately not an alphabet. This gateway does not mint upload ids — a backend does, and
/// AWS's own are opaque base64-ish text carrying `+`, `/` and `=` — so a whitelist here would
/// refuse ids that are perfectly legitimate. `..` *inside* a run of characters is likewise
/// ordinary: only a whole path segment of it is an escape.
fn could_have_been_minted(raw: &str) -> bool {
    if raw.is_empty() || raw.starts_with('/') {
        return false;
    }
    if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    !raw.split('/').any(|segment| segment == "..")
}

/// Exchanges an upload id for the right to act on the upload it names.
///
/// The order is the point of the function and cannot be rearranged by a caller: the shape is
/// judged first, so an id that could never have been minted never reaches `lookup`; then the
/// record is read exactly once; then the bucket and the key it was recorded against are compared
/// with the ones the request named. Only all three together produce a [`ResolvedUploadId`].
///
/// `lookup` is the backend's, because finding an upload is the one part of this that this crate
/// cannot do. It is called at most once, and never at all for a refused shape.
///
/// # Errors
///
/// [`UploadRejection`] — always the same one, carrying [`ErrorCode::NO_SUCH_UPLOAD`] — for a shape
/// no minted id can have, for an id no record names, and for an id recorded against a different
/// bucket or a different key. Telling those apart is the disclosure this module exists to prevent,
/// so they are one value and not three.
pub fn resolve_upload<'a, R, L>(
    claim: &UploadIdClaim<'a>,
    bucket: &BucketName,
    key: &ObjectKey,
    lookup: L,
) -> Result<(ResolvedUploadId<'a>, R), UploadRejection>
where
    R: RecordedUpload,
    L: FnOnce(&str) -> Option<R>,
{
    let id = claim.raw;
    if !could_have_been_minted(id) {
        return Err(UploadRejection::no_such_upload());
    }
    let Some(record) = lookup(id) else {
        return Err(UploadRejection::no_such_upload());
    };
    if record.bucket() != bucket.as_str() || record.key() != key.as_str() {
        return Err(UploadRejection::no_such_upload());
    }
    Ok((ResolvedUploadId { id }, record))
}
