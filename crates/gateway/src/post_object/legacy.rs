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

//! What a POST Object form stores under the RustFS profile: exactly what legacy RustFS stores for
//! the same form, or nothing.
//!
//! Responsible for: the key, content type and user metadata legacy RustFS stores from a form's
//! fields, and refusing — before the file is read — a form carrying a field legacy RustFS acts on
//! (applying it to the stored object, deciding by it whether to store one, or answering by it) that
//! this bridge cannot honour. NOT responsible for: reading the form (`rustfs-gateway-http`), the policy
//! (`rustfs-gateway-sig`), or the gateway grammar's projection, which `super` keeps unchanged.
//! Upstream: `super::PostObjectPrelude::resolve` under `FormGrammar::LegacyRustfs`. Downstream:
//! the handler's `PostObjectInput`.
//!
//! # Why a refusal rather than a best effort
//!
//! Legacy RustFS builds a `PutObject` from the form and stores it through its `put_object` path
//! (rustfs/rustfs at `1e7065101d`: `rustfs/src/storage/ecfs.rs` implements no `post_object`, so the
//! S3 layer's default hands the upload to `put_object`; the access hook's `post_object`,
//! `rustfs/src/storage/access.rs:2962`, first refuses a bad `success_action_status` or redirect,
//! `access.rs:2024-2036`). It stores the `key`, the `Content-Type` field and every `x-amz-meta-*`
//! field, and acts on the fields [`UNCARRIED_FIELDS`] names. Dropping one of those would store a
//! different object than legacy RustFS stores from the same request, or store one it refuses, so
//! a form carrying one is refused until this bridge honours it.

use super::{ErrorCode, HandlerError, ResponseKind, S3Error};
use crate::close::ConnectionIntent;
use crate::render::from_handler;

/// Form fields legacy RustFS acts on that this bridge cannot honour: the object-level fields
/// `PostObjectInput` has no member for, and `redirect`, which legacy RustFS reads as the success
/// redirect when `success_action_redirect` is absent and refuses the upload by when it is not an
/// absolute URL.
pub(super) const UNCARRIED_FIELDS: [&str; 41] = [
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-md5",
    "expires",
    "if-match",
    "if-none-match",
    "redirect",
    "x-amz-acl",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-md5",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "x-amz-checksum-sha512",
    "x-amz-checksum-xxhash128",
    "x-amz-checksum-xxhash3",
    "x-amz-checksum-xxhash64",
    "x-amz-expected-bucket-owner",
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
    "x-amz-object-lock-legal-hold",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-request-payer",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-storage-class",
    "x-amz-tagging",
    "x-amz-website-redirect-location",
    "x-amz-write-offset-bytes",
];

/// Why a form cannot be stored as legacy RustFS stores it.
#[derive(Debug)]
pub(super) struct NotCarried(&'static str);

impl NotCarried {
    /// The refusal a client receives: `501 NotImplemented`, before any file byte is read.
    pub(super) fn into_error(self) -> S3Error {
        from_handler(
            HandlerError::new(ErrorCode::NOT_IMPLEMENTED, self.0),
            ResponseKind::Other,
            ConnectionIntent::MayKeepAlive,
        )
    }
}

/// Refuses a form that carries a field in [`UNCARRIED_FIELDS`]. The caller answers the refusal at
/// the hand-off, after authorization, so that every refusal legacy RustFS answers first still wins.
pub(super) fn refuse_uncarried(fields: &[(&str, &str)]) -> Result<(), NotCarried> {
    if fields.iter().any(|(name, _)| UNCARRIED_FIELDS.contains(name)) {
        return Err(NotCarried("a POST form field this profile cannot honour yet was sent"));
    }
    Ok(())
}

/// The key legacy RustFS stores: the `key` field, every `${filename}` in it replaced by the file's
/// name exactly as the form gave it.
pub(super) fn stored_key(key_field: &str, file_name: &str) -> String {
    key_field.replace("${filename}", file_name)
}

/// Refuses a form whose key, as this gateway resolved it, is not the key legacy RustFS stores.
///
/// A signed form's key is resolved by the policy, which cleans `${filename}` (it keeps the last
/// path segment and drops `..`), and a key is materialised under the deployment's name policy;
/// legacy RustFS substitutes the name verbatim. Where the two differ the object would be stored
/// under another key, so the form is refused instead.
pub(super) fn refuse_other_key(resolved: &str, legacy: &str) -> Result<(), NotCarried> {
    if resolved != legacy {
        return Err(NotCarried("this POST form's key resolves differently from the key RustFS stores"));
    }
    Ok(())
}

/// The content type legacy RustFS stores: the `Content-Type` field, as sent.
pub(super) fn content_type(fields: &[(&str, &str)]) -> Option<String> {
    fields
        .iter()
        .find_map(|(name, value)| (*name == "content-type").then(|| (*value).to_owned()))
}

/// The user metadata legacy RustFS stores: every `x-amz-meta-*` field, by the name after the
/// prefix.
///
/// Legacy-compat (rustfs/backlog#2684): a field named exactly `x-amz-meta-` is read, counted by
/// the policy's field check, and then silently not stored. The intended future behaviour is to
/// refuse a metadata field with no name, as a `PutObject` header of that shape is refused.
pub(super) fn metadata(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    fields
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("x-amz-meta-")
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| (suffix.to_owned(), (*value).to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::Full;
    use rustfs_gateway_http::{FormGrammar, FormLimits};
    use rustfs_gateway_sig::RequestNow;
    use rustfs_gateway_types::{BucketName, NamePolicy};

    use crate::gate::BodyTimeouts;
    use crate::post_object::PostObjectPrelude;

    const BOUNDARY: &str = "----RustFSLegacyStore";

    /// A SigV4 policy for `example-bucket`, `uploads/` keys, AKIDEXAMPLE on 2015-08-30 and up to
    /// 1024 bytes; its signature is not checked here, where only the key is resolved.
    const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9LFsiY29udGVudC1sZW5ndGgtcmFuZ2UiLDAsMTAyNF1dfQ==";

    /// A moment before the policy's expiration.
    const NOW: i64 = 1_440_938_160;

    fn signed_form(filename: &str) -> Bytes {
        let mut body = String::new();
        for (name, value) in [
            ("key", "uploads/${filename}"),
            ("bucket", "example-bucket"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-signature", "9eb4faefbe4e1bd23ee9f29b6a1a1cd07c2496e2e439394c7ff2823593e07e7e"),
            ("policy", POLICY),
        ] {
            body.push_str(&format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ));
        }
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\nc\r\n--{BOUNDARY}--\r\n"
        ));
        Bytes::from(body)
    }

    async fn resolve(filename: &str) -> Result<String, StatusCode> {
        let prelude = PostObjectPrelude::read_with_grammar(
            Some(Full::new(signed_form(filename))),
            &format!("multipart/form-data; boundary={BOUNDARY}"),
            FormLimits::default(),
            FormGrammar::LegacyRustfs { declared_length: true },
            BodyTimeouts::S3,
        )
        .await
        .map_err(|error| error.status())?;
        let bucket = BucketName::new("example-bucket").map_err(|_| StatusCode::IM_A_TEAPOT)?;
        prelude
            .resolve(bucket, &NamePolicy::default(), RequestNow::from_unix_seconds(NOW))
            .map(|resolved| resolved.key().as_str().to_owned())
            .map_err(|error| error.status())
    }

    /// Negative — a signed form whose policy resolves `${filename}` to another key than legacy
    /// RustFS stores (the policy keeps the last path segment; legacy RustFS substitutes the name
    /// as sent) is refused rather than stored under the other key. The control resolves.
    #[tokio::test]
    async fn a_signed_form_resolving_another_key_is_refused() {
        assert_eq!(resolve("report.txt").await, Ok("uploads/report.txt".to_owned()));
        assert_eq!(resolve("dir/report.txt").await, Err(StatusCode::NOT_IMPLEMENTED));
    }
}
