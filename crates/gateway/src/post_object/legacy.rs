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
//! Responsible for: the key, content type, user metadata and other `PutObject` members legacy
//! RustFS reads from a form's fields, read as it reads them, and refusing — before the file is read
//! — a form carrying a field legacy RustFS acts on (applying it to the stored object, deciding by it
//! whether to store one, or answering by it) that this bridge cannot honour. NOT responsible for:
//! reading the form (`rustfs-gateway-http`), the policy (`rustfs-gateway-sig`), applying a member
//! to the stored object (the handler), or the gateway grammar's projection, which `super` keeps
//! unchanged. Upstream: `super::PostObjectPrelude::resolve` under `FormGrammar::LegacyRustfs`.
//! Downstream: the handler's `PostObjectInput`.
//!
//! # Carried, or refused — never dropped
//!
//! Legacy RustFS builds a `PutObject` from the form and stores it through its `put_object` path
//! (rustfs/rustfs at `e870a6d25b`: `rustfs/src/storage/ecfs.rs` implements no `post_object`, so the
//! S3 layer's default hands the upload to `put_object`; the access hook's `post_object`,
//! `rustfs/src/storage/access.rs:2962`, first refuses a bad `success_action_status` or redirect,
//! `access.rs:2024-2036`). Every field it reads for that `PutObject` crosses to the handler in
//! `PostObjectInput` as the member it fills ([`object_fields`]), for the handler to apply exactly as
//! it applies that member of a `PutObject`, except the fields [`UNCARRIED_FIELDS`] names: dropping
//! one of those would store a different object than legacy RustFS stores from the same request, or
//! store one it refuses, so a form carrying one is refused until this bridge honours it.

use rustfs_gateway_types::OpaqueString;
use rustfs_gateway_types::dto::{
    Acl, ChecksumAlgorithm, ObjectLockLegalHoldStatus, ObjectLockMode, PostObjectFields, RequestPayer, ServerSideEncryption,
    StorageClass,
};

use super::{ErrorCode, HandlerError, ResponseKind, S3Error};
use crate::close::ConnectionIntent;
use crate::render::from_handler;

/// Form fields legacy RustFS acts on that this bridge cannot honour yet.
///
/// The SSE-C fields: legacy RustFS encrypts with the key the form carries
/// (`rustfs/src/app/object/put.rs:1259-1263`), which this gateway's customer-key rules, stated over
/// headers, have not been extended to. (`redirect` is carried: the response plan reads it as legacy
/// RustFS does, `super::response`. The Object Lock fields are carried, and the route stage asks the
/// actions they require, `ResolvedPostObject::object_lock_actions`.)
pub(super) const UNCARRIED_FIELDS: [&str; 3] = [
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
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

/// The actions a form's Object Lock fields require on top of the base one, asked in legacy RustFS's
/// order: `s3:PutObjectLegalHold` for a legal hold, then `s3:PutObjectRetention` for a mode or a
/// retain-until date. A field counts as soon as it is sent, empty included, as legacy RustFS's
/// `put_object` access hook reads the input its POST operation built from the form
/// (`rustfs/src/storage/access.rs` `legal_hold_write_requested`, `retention_write_requested`; the
/// hook at `:3220-3226` on rustfs/rustfs `95268a3b9`).
pub(super) fn object_lock_actions(fields: &PostObjectFields) -> &'static [&'static str] {
    const HOLD: &str = "s3:PutObjectLegalHold";
    const RETENTION: &str = "s3:PutObjectRetention";
    let hold = fields.object_lock_legal_hold_status.is_some();
    let retention = fields.object_lock_mode.is_some() || fields.object_lock_retain_until_date.is_some();
    match (hold, retention) {
        (true, true) => &[HOLD, RETENTION],
        (true, false) => &[HOLD],
        (false, true) => &[RETENTION],
        (false, false) => &[],
    }
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
    field(fields, "content-type").map(str::to_owned)
}

/// The other `PutObject` members legacy RustFS reads from a form, read as it reads them, or the
/// `400 InvalidArgument` it answers for a value it cannot read.
///
/// Legacy RustFS reads each field named like a `PutObject` header with that member's own text
/// parser: a text or enumeration member is the field as sent, empty included; a `bool` or `i64`
/// member is Rust's own parse of it; an entity-tag condition is read with its grammar
/// ([`is_entity_tag_condition`]); a date-time member is an RFC 3339 date-time. Only those five can
/// fail, and the first that does — the bucket-key flag, then `If-Match`, then `If-None-Match`, then
/// the Object Lock retain-until date, then the write offset — refuses the upload before
/// authorization, naming the field and the value as sent.
pub(super) fn object_fields(fields: &[(&str, &str)]) -> Result<PostObjectFields, S3Error> {
    let text = |name: &str| field(fields, name).map(str::to_owned);
    let condition = |value: &str| is_entity_tag_condition(value).then(|| value.to_owned());
    let bucket_key_enabled = read(fields, "x-amz-server-side-encryption-bucket-key-enabled", |value| {
        value.parse::<bool>().ok()
    })?;
    let if_match = read(fields, "if-match", condition)?;
    let if_none_match = read(fields, "if-none-match", condition)?;
    let object_lock_retain_until_date = read(fields, "x-amz-object-lock-retain-until-date", super::legacy_date::read)?;
    let write_offset_bytes = read(fields, "x-amz-write-offset-bytes", |value| value.parse::<i64>().ok())?;
    Ok(PostObjectFields {
        acl: text("x-amz-acl").map(Acl::custom),
        bucket_key_enabled,
        cache_control: text("cache-control"),
        checksum_algorithm: text("x-amz-sdk-checksum-algorithm").map(ChecksumAlgorithm::custom),
        checksum_crc32: text("x-amz-checksum-crc32"),
        checksum_crc32c: text("x-amz-checksum-crc32c"),
        checksum_crc64nvme: text("x-amz-checksum-crc64nvme"),
        checksum_md5: text("x-amz-checksum-md5"),
        checksum_sha1: text("x-amz-checksum-sha1"),
        checksum_sha256: text("x-amz-checksum-sha256"),
        checksum_sha512: text("x-amz-checksum-sha512"),
        checksum_xxhash128: text("x-amz-checksum-xxhash128"),
        checksum_xxhash3: text("x-amz-checksum-xxhash3"),
        checksum_xxhash64: text("x-amz-checksum-xxhash64"),
        content_disposition: text("content-disposition"),
        content_encoding: text("content-encoding"),
        content_language: text("content-language"),
        content_md5: text("content-md5"),
        expected_bucket_owner: text("x-amz-expected-bucket-owner"),
        expires: text("expires").map(OpaqueString::from),
        grant_full_control: text("x-amz-grant-full-control"),
        grant_read: text("x-amz-grant-read"),
        grant_read_acp: text("x-amz-grant-read-acp"),
        grant_write_acp: text("x-amz-grant-write-acp"),
        if_match,
        if_none_match,
        object_lock_legal_hold_status: text("x-amz-object-lock-legal-hold").map(ObjectLockLegalHoldStatus::custom),
        object_lock_mode: text("x-amz-object-lock-mode").map(ObjectLockMode::custom),
        object_lock_retain_until_date,
        request_payer: text("x-amz-request-payer").map(RequestPayer::custom),
        server_side_encryption: text("x-amz-server-side-encryption").map(ServerSideEncryption::custom),
        ssekms_encryption_context: text("x-amz-server-side-encryption-context"),
        ssekms_key_id: text("x-amz-server-side-encryption-aws-kms-key-id"),
        storage_class: text("x-amz-storage-class").map(StorageClass::custom),
        tagging: text("x-amz-tagging"),
        website_redirect_location: text("x-amz-website-redirect-location"),
        write_offset_bytes,
    })
}

/// The value of the field `name`, if the form carried it.
fn field<'a>(fields: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    fields.iter().find_map(|(field, value)| (*field == name).then_some(*value))
}

/// The field `name` as `parse` reads it, or legacy RustFS's refusal of a value it cannot read.
fn read<T>(fields: &[(&str, &str)], name: &'static str, parse: impl Fn(&str) -> Option<T>) -> Result<Option<T>, S3Error> {
    field(fields, name)
        .map(|value| parse(value).ok_or_else(|| unreadable(name, value)))
        .transpose()
}

/// Whether legacy RustFS reads `value` as an entity-tag condition: `*`; a tag in double quotes,
/// optionally after `W/`, of ASCII characters that are not controls (tab excepted); or a bare tag
/// of ASCII letters, digits and `-`.
///
/// Legacy-compat (rustfs/backlog#2684): a quoted tag runs from the first quote to the last, so a
/// list such as `"a", "b"` is read as the one tag `a", "b` rather than refused, and a quote inside a
/// tag is kept. The intended future behaviour is RFC 9110's `entity-tag` grammar, one tag per
/// condition, refusing a list or an inner quote.
fn is_entity_tag_condition(value: &str) -> bool {
    let quoted = |tag: &[u8]| tag.iter().all(|byte| *byte == b'\t' || (0x20..0x7f).contains(byte));
    match value.as_bytes() {
        b"*" => true,
        [b'"', tag @ .., b'"'] | [b'W', b'/', b'"', tag @ .., b'"'] => quoted(tag),
        bare => !bare.is_empty() && bare.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-'),
    }
}

/// Legacy RustFS's refusal of a field value it cannot read.
fn unreadable(name: &str, value: &str) -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::INVALID_ARGUMENT, format!("invalid field value: {name}: {value:?}")),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

/// Read the legacy signed 32-bit status before authorization; its supported set is checked later.
pub(super) fn success_status(raw: &str) -> Result<String, S3Error> {
    raw.parse::<i32>()
        .map(|status| status.to_string())
        .map_err(|_| unreadable("success_action_status", raw))
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
#[allow(clippy::expect_used)]
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

    /// [`POLICY`], plus a condition admitting any `x-amz-server-side-encryption-bucket-key-enabled`.
    const POLICY_WITH_FLAG: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9LFsiY29udGVudC1sZW5ndGgtcmFuZ2UiLDAsMTAyNF0sWyJzdGFydHMtd2l0aCIsIiR4LWFtei1zZXJ2ZXItc2lkZS1lbmNyeXB0aW9uLWJ1Y2tldC1rZXktZW5hYmxlZCIsIiJdXX0=";

    fn signed_form(filename: &str) -> Bytes {
        signed_form_with(filename, POLICY, &[])
    }

    fn signed_form_with(filename: &str, policy: &str, extra: &[(&str, &str)]) -> Bytes {
        let mut body = String::new();
        for (name, value) in [
            ("key", "uploads/${filename}"),
            ("bucket", "example-bucket"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-signature", "9eb4faefbe4e1bd23ee9f29b6a1a1cd07c2496e2e439394c7ff2823593e07e7e"),
            ("policy", policy),
        ]
        .iter()
        .chain(extra)
        {
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
        resolve_form(signed_form(filename)).await
    }

    async fn resolve_form(form: Bytes) -> Result<String, StatusCode> {
        let prelude = PostObjectPrelude::read_with_grammar(
            Some(Full::new(form)),
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

    /// Negative — a field legacy RustFS cannot read answers with its `400` before this bridge's
    /// own `501` for a key it would resolve differently: legacy RustFS decodes the form before it
    /// stores, and would never reach the key. The control resolves.
    #[tokio::test]
    async fn an_unreadable_field_answers_before_a_key_this_bridge_cannot_store() {
        let form = |filename: &str, flag: &str| {
            signed_form_with(filename, POLICY_WITH_FLAG, &[("x-amz-server-side-encryption-bucket-key-enabled", flag)])
        };
        assert_eq!(resolve_form(form("report.txt", "true")).await, Ok("uploads/report.txt".to_owned()));
        assert_eq!(resolve_form(form("dir/report.txt", "true")).await, Err(StatusCode::NOT_IMPLEMENTED));
        assert_eq!(resolve_form(form("dir/report.txt", "yes")).await, Err(StatusCode::BAD_REQUEST));
    }

    /// Positive — every text and enumeration member is the field as sent, an empty one included,
    /// and a member the form did not carry is absent.
    #[test]
    fn a_text_member_is_carried_as_sent() {
        let fields = super::object_fields(&[
            ("cache-control", " max-age=60 "),
            ("content-disposition", "attachment; filename=\"r\u{e9}sum\u{e9}.pdf\""),
            ("content-language", ""),
            ("x-amz-storage-class", "standard"),
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-tagging", "a=b&c=d"),
            ("expires", "not a date"),
        ])
        .expect("every text member is read");
        assert_eq!(fields.cache_control.as_deref(), Some(" max-age=60 "));
        assert_eq!(
            fields.content_disposition.as_deref(),
            Some("attachment; filename=\"r\u{e9}sum\u{e9}.pdf\"")
        );
        assert_eq!(fields.content_language.as_deref(), Some(""));
        assert_eq!(fields.storage_class.as_ref().map(|class| class.as_str()), Some("standard"));
        assert_eq!(fields.server_side_encryption.as_ref().map(|algorithm| algorithm.as_str()), Some("AES256"));
        assert_eq!(fields.tagging.as_deref(), Some("a=b&c=d"));
        assert_eq!(fields.expires.as_ref().map(|value| value.as_str()), Some("not a date"));
        assert_eq!(fields.content_encoding, None);
        assert_eq!(fields.website_redirect_location, None);
    }

    /// Positive and negative — the two numeric members are Rust's own parses of the field.
    #[test]
    fn a_numeric_member_is_read_as_rust_reads_it() {
        for (value, expected) in [("true", Some(true)), ("false", Some(false))] {
            let fields =
                super::object_fields(&[("x-amz-server-side-encryption-bucket-key-enabled", value)]).expect("a Rust boolean");
            assert_eq!(fields.bucket_key_enabled, expected, "{value}");
        }
        for (value, expected) in [("0", 0), ("+5", 5), ("-5", -5), ("9223372036854775807", i64::MAX)] {
            let fields = super::object_fields(&[("x-amz-write-offset-bytes", value)]).expect("a Rust i64");
            assert_eq!(fields.write_offset_bytes, Some(expected), "{value}");
        }
        for value in ["True", "1", " true", ""] {
            let error = super::object_fields(&[("x-amz-server-side-encryption-bucket-key-enabled", value)])
                .expect_err("not a Rust boolean");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{value}");
        }
        for value in ["", " 5", "5 ", "0x10", "9223372036854775808", "1e3"] {
            let error = super::object_fields(&[("x-amz-write-offset-bytes", value)]).expect_err("not a Rust i64");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{value}");
        }
    }

    /// Positive and negative — an entity-tag condition is read with legacy RustFS's grammar.
    #[test]
    fn an_entity_tag_condition_is_read_with_the_legacy_grammar() {
        for value in [
            "*",
            "\"abc\"",
            "W/\"abc\"",
            "\"\"",
            "W/\"\"",
            "\"a b\"",
            "\"a\tb\"",
            "\"a\"b\"",
            "\"W/\"x\"\"",
            "\"a\", \"b\"",
            "abc-123",
            "-",
            "d41d8cd98f00b204e9800998ecf8427e-2",
        ] {
            assert!(super::is_entity_tag_condition(value), "{value:?}");
            let fields = super::object_fields(&[("if-match", value), ("if-none-match", value)]).expect("a condition");
            assert_eq!(fields.if_match.as_deref(), Some(value));
            assert_eq!(fields.if_none_match.as_deref(), Some(value));
        }
        for value in [
            "",
            "\"",
            "W/\"",
            "W/abc",
            "abc def",
            " *",
            "*,*",
            "\"a\", b",
            "\"\u{e9}\"",
            "\u{e9}",
            "\"a\u{1}\"",
            "\"a\u{7f}\"",
            "w/\"abc\"",
            "abc_1",
        ] {
            assert!(!super::is_entity_tag_condition(value), "{value:?}");
            let error = super::object_fields(&[("if-none-match", value)]).expect_err("not a condition");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{value:?}");
        }
    }

    /// Negative — the first unreadable field in legacy RustFS's reading order answers, naming the
    /// field and the value as sent.
    #[test]
    fn the_first_unreadable_field_in_reading_order_answers() {
        let every = [
            ("x-amz-write-offset-bytes", "x"),
            ("if-none-match", "x y"),
            ("if-match", "x y"),
            ("x-amz-server-side-encryption-bucket-key-enabled", "yes"),
        ];
        for (skipped, expected) in [
            (0, "invalid field value: x-amz-server-side-encryption-bucket-key-enabled: \"yes\""),
            (1, "invalid field value: if-match: \"x y\""),
            (2, "invalid field value: if-none-match: \"x y\""),
            (3, "invalid field value: x-amz-write-offset-bytes: \"x\""),
        ] {
            let present: Vec<_> = every.iter().copied().take(every.len().saturating_sub(skipped)).collect();
            let error = super::object_fields(&present).expect_err("an unreadable field");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
            assert_eq!(error.code().map(|code| code.as_str()), Some("InvalidArgument"));
            assert_eq!(error.message(), Some(expected));
        }
    }
}
