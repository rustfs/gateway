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

//! Filesystem-backed browser `POST` Object uploads.
//!
//! Responsible for: storing the file part of an accepted browser form, with its media type,
//! `x-amz-meta-*` fields and the other `PutObject` members the form set, through the same
//! publication `PutObject` uses, as RustFS stores a form upload — or refusing a member this backend
//! cannot store as RustFS does — and reporting the stored entity tag and version for the
//! framework's success action.
//! NOT responsible for: the multipart form grammar, POST-policy signature and condition checks,
//! the `success_action_*` response, or the policy's content-length range — all of those are the
//! gateway's form pipeline, which hands this handler a live, policy-bounded stream.
//! Upstream: the authenticated gateway form pipeline. Downstream: the CRUD registry.

use std::collections::BTreeMap;

use rustfs_gateway::dto::{PostObject, PostObjectFields, PostObjectOutput, StorageClass};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp};

use super::content_headers::{ContentHeaders, normalized_content_encoding};
use super::records::ObjectAttributes;
use super::tagging::tags_from_header;
use super::transitions::{invalid_storage_class, requested_storage_class};
use super::{FsBackend, drain, etag};

/// RustFS's answer to a form upload that asks for SSE-KMS (`rustfs/src/app/object/put.rs:1198-1201`
/// at rustfs/rustfs `e870a6d25b`).
const POST_SSE_KMS_REFUSED: &str = "SSE-KMS is not supported for POST object uploads";

/// Refuses a form member RustFS applies to the object it stores and this backend cannot store as
/// RustFS does. RustFS keeps `x-amz-website-redirect-location` with the object, re-renders a
/// readable `Expires` and refuses any other, and checks the file against `Content-MD5`
/// (`rustfs/src/app/object/shared.rs:706-771`, `put.rs:1724-1729`); this backend keeps no redirect,
/// and keeps `Expires` and the digest check to the `PutObject` header path.
fn refuse_unstored(fields: &PostObjectFields) -> Result<(), HandlerError> {
    for (member, present) in [
        ("x-amz-website-redirect-location", fields.website_redirect_location.is_some()),
        ("Expires", fields.expires.is_some()),
        ("Content-MD5", fields.content_md5.is_some()),
    ] {
        if present {
            return Err(HandlerError::not_implemented(format!(
                "the filesystem backend does not store a form's {member} field"
            )));
        }
    }
    Ok(())
}

/// Whether the upload asks for SSE-KMS as RustFS reads the question for a form upload: the form's
/// algorithm is `aws:kms` in any case, the form names a KMS key at all, or the request's own
/// managed-encryption header is `aws:kms` (`rustfs/src/app/object/put.rs:898-913`).
fn requests_sse_kms(fields: &PostObjectFields, header_algorithm: Option<&str>) -> bool {
    let kms = |algorithm: &str| algorithm.eq_ignore_ascii_case("aws:kms");
    fields
        .server_side_encryption
        .as_ref()
        .is_some_and(|algorithm| kms(algorithm.as_str()))
        || fields.ssekms_key_id.is_some()
        || header_algorithm.is_some_and(|algorithm| kms(algorithm.trim()))
}

/// The storage class RustFS accepts on a write: exactly `STANDARD` or `REDUCED_REDUNDANCY`, else
/// `InvalidStorageClass` (`rustfs/src/app/object/put.rs:1202-1206`,
/// `crates/ecstore/src/config/storageclass.rs:52-61`).
fn form_storage_class(requested: Option<&StorageClass>) -> Result<Option<StorageClass>, HandlerError> {
    if requested.is_some_and(|class| !matches!(class.as_str(), "STANDARD" | "REDUCED_REDUNDANCY")) {
        return Err(invalid_storage_class());
    }
    requested_storage_class(requested)
}

/// Collects the form's metadata fields, refusing a field the form repeats.
///
/// A repeated field is refused rather than resolved by first- or last-write-wins: the form carried
/// two values for one stored key, and choosing one of them is a decision the uploader did not make.
///
/// Today the gateway's form pipeline already refuses a repeated field before this handler runs,
/// so over the wire this refusal is defense in depth. It stays because the input type is a list,
/// not a map: nothing in the handler contract promises uniqueness, and a silent merge here would
/// be the first thing to break if the pipeline ever relaxed that rule.
fn form_metadata(fields: Vec<(String, String)>) -> Result<BTreeMap<String, String>, HandlerError> {
    let mut metadata = BTreeMap::new();
    for (key, value) in fields {
        if metadata.insert(key, value).is_some() {
            return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the form repeats an x-amz-meta-* field"));
        }
    }
    Ok(metadata)
}

impl Handler<PostObject> for FsBackend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let header_algorithm = request
            .sse()
            .managed_algorithm()
            .map(|algorithm| algorithm.as_str().to_owned());
        let input = request.into_input();
        // Drained first: a refusal returned with the file unread would be reported as an abandoned
        // body rather than as itself. Nothing is published until every refusal has had its turn.
        let bytes = drain(Some(input.body)).await?;
        let fields = input.fields;
        // This backend's own refusal is answered last, after every refusal RustFS itself answers.
        let unstored = refuse_unstored(&fields);
        // RustFS's own order: the SSE-KMS refusal, the storage class, then the algorithm — the
        // form's, else the request's own header (`rustfs/src/app/object/put.rs:1198-1206`, `:1265`).
        if requests_sse_kms(&fields, header_algorithm.as_deref()) {
            return Err(HandlerError::not_implemented(POST_SSE_KMS_REFUSED));
        }
        let storage_class = form_storage_class(fields.storage_class.as_ref())?;
        let algorithm = fields
            .server_side_encryption
            .as_ref()
            .map(|algorithm| algorithm.as_str().to_owned())
            .or(header_algorithm);
        let encryption = self
            .write_encryption(input.bucket.as_str(), algorithm.as_deref(), None)
            .await?;
        // The members RustFS reads and then never acts on — the ACL and grants, the expected owner,
        // the request payer, the bucket-key flag, the checksum fields, the KMS context, the write
        // offset and the two conditions — are ignored here too. (RustFS verifies and evaluates the
        // request's own checksum and condition headers instead; this backend does not read those
        // for a form upload, a gap older than these members.)
        let headers = ContentHeaders::from_request(
            fields.cache_control,
            fields.content_disposition,
            fields.content_encoding.as_deref().and_then(normalized_content_encoding),
            fields.content_language,
            input.content_type,
            None,
        );
        let attributes = ObjectAttributes {
            part_lengths: None,
            checksum: None,
            metadata: form_metadata(input.metadata)?,
            headers: headers.with_encryption(encryption),
            storage_class,
            tags: tags_from_header(fields.tagging.as_deref())?,
        };
        unstored?;
        let e_tag = etag(&bytes)?;
        let published = self
            .publish_object(input.bucket.as_str(), input.key.as_str(), &bytes, &e_tag, &attributes)
            .await?;
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(e_tag),
            version_id: published.version_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    /// Negative — a repeated field is refused rather than resolved by picking one value.
    #[test]
    fn a_repeated_form_field_is_refused() {
        let error =
            form_metadata(vec![field("origin", "first"), field("origin", "second")]).expect_err("a repeated field is refused");
        assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
        assert_eq!(error.message(), "the form repeats an x-amz-meta-* field");
    }

    /// Positive — distinct fields are all kept.
    #[test]
    fn distinct_form_fields_are_kept() {
        let metadata = form_metadata(vec![field("origin", "browser"), field("owner", "ops")]).expect("distinct fields");
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata.get("origin").map(String::as_str), Some("browser"));
    }

    /// Positive and negative — `Content-Encoding` is stored as RustFS stores it: codings trimmed,
    /// `aws-chunked` in any case and empty codings dropped, the rest joined by `", "`, nothing left
    /// stored as nothing.
    #[test]
    fn a_content_encoding_is_stored_as_rustfs_stores_it() {
        for (sent, stored) in [
            ("gzip", Some("gzip")),
            (" gzip ,br ", Some("gzip, br")),
            ("gzip,AWS-Chunked,,br", Some("gzip, br")),
            ("aws-chunked", None),
            (" , ", None),
            ("", None),
            ("x-gzip;q=1", Some("x-gzip;q=1")),
        ] {
            assert_eq!(normalized_content_encoding(sent).as_deref(), stored, "{sent:?}");
        }
    }

    /// Positive and negative — SSE-KMS is read as RustFS reads it for a form upload: the form's
    /// algorithm in any case, any key id, or the request's own header; `AES256` is not.
    #[test]
    fn sse_kms_is_recognised_as_rustfs_recognises_it() {
        let with = |algorithm: Option<&str>, key_id: Option<&str>| PostObjectFields {
            server_side_encryption: algorithm.map(|value| rustfs_gateway::dto::ServerSideEncryption::custom(value.to_owned())),
            ssekms_key_id: key_id.map(str::to_owned),
            ..PostObjectFields::default()
        };
        assert!(requests_sse_kms(&with(Some("aws:kms"), None), None));
        assert!(requests_sse_kms(&with(Some("AWS:KMS"), None), None));
        assert!(requests_sse_kms(&with(None, Some("")), None));
        assert!(requests_sse_kms(&with(Some("AES256"), None), Some("aws:kms")));
        assert!(!requests_sse_kms(&with(Some("AES256"), None), Some("AES256")));
        assert!(
            !requests_sse_kms(&with(Some(" aws:kms"), None), None),
            "the form's algorithm is not trimmed"
        );
        assert!(!requests_sse_kms(&PostObjectFields::default(), None));
    }

    /// Positive and negative — only `STANDARD` and `REDUCED_REDUNDANCY`, exactly, are accepted.
    #[test]
    fn only_the_classes_rustfs_writes_are_accepted() {
        for class in ["STANDARD", "REDUCED_REDUNDANCY"] {
            let accepted = form_storage_class(Some(&StorageClass::custom(class.to_owned()))).expect("a written class");
            assert_eq!(accepted.as_ref().map(StorageClass::as_str), Some(class));
        }
        for class in ["STANDARD_IA", "GLACIER", "standard", ""] {
            let error = form_storage_class(Some(&StorageClass::custom(class.to_owned()))).expect_err("not written");
            assert_eq!(error.code(), &ErrorCode::INVALID_STORAGE_CLASS, "{class:?}");
        }
        assert_eq!(form_storage_class(None).expect("no class"), None);
    }
}
