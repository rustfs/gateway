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

//! The ten per-request SSE headers, read once into one value.
//!
//! Responsible for: the header names, [`SseHeaders::read`] (the single read of the family off a
//! request head), the two customer-key trios, and the value rules of the managed channel — the
//! algorithm's closed set, the KMS members' agreement with it, the strict boolean, and the
//! encryption context's encoding, ceiling and JSON string-pair structure.
//! NOT responsible for: the transport gate or the order the rules run in
//! ([`super::enforce`]), the key itself ([`super::key`]), the multipart binding
//! ([`super::consistency`]), or the bucket's stored default-encryption document
//! (`crate::ops::shared::encryption`, whose rule this module *calls* rather than restates).
//! Upstream: `crate::codec::MetaView`, [`super::base64`]. Downstream: [`super::enforce`].
//!
//! # Why the key text is a newtype with no `Display`
//!
//! Every other member here is a value this service is willing to echo. The two customer keys are
//! not, and the difference has to be in the type rather than in a reviewer's attention: a
//! `Cow<'a, str>` field named `key` is one `{}` away from an error message. [`KeyText`] has no
//! `Debug`, no `Display` and one accessor, and `scripts/check_sse_key_never_leaks.sh` counts the
//! call sites of that accessor.
//!
//! # Why the managed channel's rules are a call and not a copy
//!
//! `crate::ops::shared::encryption::validate_encryption` already holds the closed `SSEAlgorithm`
//! set and the "a KMS key id is allowed if and only if the algorithm is a KMS one" rule, for the
//! document a bucket stores. Those are the same two rules the request headers need. Writing them
//! again here is the s3s #499-versus-#632 shape — one rule, two homes, two divergent fixes — so
//! [`ManagedChannel::validate`] builds the one-rule document the validator is defined over and
//! calls it. What this module adds on top is only what a document cannot carry: a header spelling
//! that is not a legal enumeration value at all, the strict boolean, and the context encoding.

use std::borrow::Cow;

use rustfs_gateway_types::dto::{
    ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule, SseAlgorithm,
};

use crate::codec::MetaView;
use crate::ops::shared::encryption::validate_encryption;

use super::base64::decode_bounded;

/// `x-amz-server-side-encryption` — the managed channel's algorithm.
pub const SSE_ALGORITHM: &str = "x-amz-server-side-encryption";
/// `x-amz-server-side-encryption-aws-kms-key-id`.
pub const SSE_KMS_KEY_ID: &str = "x-amz-server-side-encryption-aws-kms-key-id";
/// `x-amz-server-side-encryption-context`.
pub const SSE_CONTEXT: &str = "x-amz-server-side-encryption-context";
/// `x-amz-server-side-encryption-bucket-key-enabled`.
pub const SSE_BUCKET_KEY_ENABLED: &str = "x-amz-server-side-encryption-bucket-key-enabled";
/// `x-amz-server-side-encryption-customer-algorithm`.
pub const SSEC_ALGORITHM: &str = "x-amz-server-side-encryption-customer-algorithm";
/// `x-amz-server-side-encryption-customer-key` — never echoed, never logged.
pub const SSEC_KEY: &str = "x-amz-server-side-encryption-customer-key";
/// `x-amz-server-side-encryption-customer-key-md5`.
pub const SSEC_KEY_MD5: &str = "x-amz-server-side-encryption-customer-key-md5";
/// `x-amz-copy-source-server-side-encryption-customer-algorithm`.
pub const COPY_SSEC_ALGORITHM: &str = "x-amz-copy-source-server-side-encryption-customer-algorithm";
/// `x-amz-copy-source-server-side-encryption-customer-key` — never echoed, never logged.
pub const COPY_SSEC_KEY: &str = "x-amz-copy-source-server-side-encryption-customer-key";
/// `x-amz-copy-source-server-side-encryption-customer-key-md5`.
pub const COPY_SSEC_KEY_MD5: &str = "x-amz-copy-source-server-side-encryption-customer-key-md5";

/// The two header names whose value must never appear in a response.
///
/// The list a response filter is written against, and the list
/// `scripts/check_sse_key_never_leaks.sh` checks the operation bindings in `spec/` against. Both
/// spellings are here because `CopyObject` carries two independent keys, and losing the
/// copy-source one is the mistake that echoes a key nobody was looking for.
pub const NEVER_IN_A_RESPONSE: &[&str] = &[SSEC_KEY, COPY_SSEC_KEY];

/// The only customer-provided algorithm S3 accepts.
pub const CUSTOMER_ALGORITHM: &str = "AES256";

/// The largest encryption context this service will decode, in bytes after base64.
///
/// A judgement, not a citation: nothing AWS publishes puts a number on the header, and the
/// alternative to a number is decoding whatever arrives. Two kibibytes is far above any key-policy
/// context observed in practice and far below anything that costs a request. The ceiling is
/// applied *during* the decode, so an oversized value is refused at the byte that crosses it.
pub const MAX_CONTEXT_BYTES: usize = 2048;

/// The text of a customer-provided key, carried without a way to render it.
///
/// No `Debug`, no `Display`, no `PartialEq`, no `Clone`. Its private `expose` method is the single
/// accessor and exists for [`super::key::fingerprint_of`]; a second call site is a finding for
/// `scripts/check_sse_key_never_leaks.sh` rather than a judgement call at review time.
pub struct KeyText<'a>(Cow<'a, str>);

impl<'a> KeyText<'a> {
    /// The base64 text, for the one caller that hashes it.
    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

/// One side's three customer-key headers, present or absent independently.
///
/// A request carries up to two of these: the target's, and — on a `CopyObject` or an
/// `UploadPartCopy` — the source's. They are validated separately and share no value.
pub struct CustomerTrio<'a> {
    /// `…-customer-algorithm`.
    pub algorithm: Option<Cow<'a, str>>,
    /// `…-customer-key`, unrenderable by construction.
    pub key: Option<KeyText<'a>>,
    /// `…-customer-key-MD5`.
    pub digest: Option<Cow<'a, str>>,
}

impl CustomerTrio<'_> {
    /// Whether any of the three arrived. The transport gate is stated over this and nothing else:
    /// one header out of three is still a request that put a key on the wire, or tried to.
    #[must_use]
    pub fn any_present(&self) -> bool {
        self.algorithm.is_some() || self.key.is_some() || self.digest.is_some()
    }

    /// Whether all three arrived.
    #[must_use]
    pub fn all_present(&self) -> bool {
        self.algorithm.is_some() && self.key.is_some() && self.digest.is_some()
    }
}

/// The managed channel: `x-amz-server-side-encryption` and the three members that qualify it.
pub struct ManagedChannel<'a> {
    /// The algorithm as the caller spelled it.
    pub algorithm: Option<Cow<'a, str>>,
    /// `…-aws-kms-key-id`.
    pub kms_key_id: Option<Cow<'a, str>>,
    /// `…-context`.
    pub context: Option<Cow<'a, str>>,
    /// `…-bucket-key-enabled`.
    pub bucket_key_enabled: Option<Cow<'a, str>>,
}

impl ManagedChannel<'_> {
    /// Whether any of the four arrived.
    #[must_use]
    pub fn any_present(&self) -> bool {
        self.algorithm.is_some() || self.kms_key_id.is_some() || self.context.is_some() || self.bucket_key_enabled.is_some()
    }

    /// Checks the managed channel's values, first refusal wins.
    ///
    /// Rules, in the order they run:
    ///
    /// 1. a KMS member — key id, context or bucket-key switch — with no algorithm beside it names
    ///    an encryption scheme the request never asked for;
    /// 2. the algorithm is one of the documented enumeration values (the closed set held by
    ///    `crate::ops::shared::encryption`, reached through the document validator);
    /// 3. a KMS key id is allowed if and only if the algorithm is `aws:kms` or `aws:kms:dsse` —
    ///    the same validator's second rule;
    /// 4. the context and the bucket-key switch follow the key id: both describe a KMS
    ///    envelope, and neither means anything beside `AES256`;
    /// 5. the switch is `true` or `false` and nothing else;
    /// 6. the context is canonical base64 of at most [`MAX_CONTEXT_BYTES`] UTF-8 bytes,
    ///    containing one JSON object with unique string keys and string values (ADR-0019).
    ///
    /// # Errors
    ///
    /// [`ManagedRejection`] naming the first rule the request breaks.
    pub fn validate(&self) -> Result<Option<SseAlgorithm>, ManagedRejection> {
        let Some(spelling) = self.algorithm.as_deref() else {
            if self.kms_key_id.is_some() || self.context.is_some() || self.bucket_key_enabled.is_some() {
                return Err(ManagedRejection::QualifierWithoutAlgorithm);
            }
            return Ok(None);
        };
        let algorithm = SseAlgorithm::custom(spelling.to_owned());
        // One rule, one home: the closed value set and the key-id agreement are the bucket
        // document's, borrowed by building the one-rule document they are defined over.
        let document = ServerSideEncryptionConfiguration {
            rules: vec![ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
                    sse_algorithm: algorithm.clone(),
                    kms_master_key_id: self.kms_key_id.as_ref().map(|id| id.as_ref().to_owned()),
                }),
                ..ServerSideEncryptionRule::default()
            }],
        };
        validate_encryption(&document).map_err(ManagedRejection::Document)?;

        let kms_class = algorithm == SseAlgorithm::AWS_KMS || algorithm == SseAlgorithm::AWS_KMS_DSSE;
        if !kms_class && (self.context.is_some() || self.bucket_key_enabled.is_some()) {
            return Err(ManagedRejection::KmsQualifierWithoutKmsAlgorithm);
        }
        if let Some(switch) = self.bucket_key_enabled.as_deref()
            && switch != "true"
            && switch != "false"
        {
            return Err(ManagedRejection::BucketKeyNotABoolean);
        }
        if let Some(context) = self.context.as_deref() {
            let bytes = decode_bounded(context, MAX_CONTEXT_BYTES).map_err(|_| ManagedRejection::ContextNotBase64)?;
            core::str::from_utf8(&bytes).map_err(|_| ManagedRejection::ContextNotBase64)?;
            if !super::context::is_valid(&bytes) {
                return Err(ManagedRejection::ContextNotJson);
            }
        }
        Ok(Some(algorithm))
    }
}

/// Why the managed channel was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedRejection {
    /// A KMS member arrived with no `x-amz-server-side-encryption` beside it.
    QualifierWithoutAlgorithm,
    /// The shared document validator refused the algorithm, or the key id beside it.
    Document(crate::ops::shared::encryption::EncryptionRejection),
    /// The context or the bucket-key switch arrived beside a non-KMS algorithm.
    KmsQualifierWithoutKmsAlgorithm,
    /// `…-bucket-key-enabled` is neither `true` nor `false`.
    BucketKeyNotABoolean,
    /// `…-context` is not canonical base64 of at most [`MAX_CONTEXT_BYTES`] UTF-8 bytes.
    ContextNotBase64,
    /// The decoded context is not one JSON object with unique string keys and string values.
    ContextNotJson,
}

/// Every SSE header a request carries, read once.
pub struct SseHeaders<'a> {
    /// The managed channel: SSE-S3 and SSE-KMS.
    pub managed: ManagedChannel<'a>,
    /// The target object's customer-provided key.
    pub target: CustomerTrio<'a>,
    /// The copy source's customer-provided key, a second and independent key on one request.
    pub copy_source: CustomerTrio<'a>,
}

impl<'a> SseHeaders<'a> {
    /// Reads the family off a request head.
    ///
    /// Ten exact lookups, never a prefix scan: `…-customer-key` is a prefix of
    /// `…-customer-key-md5`, so a prefix match would read one header as the other. Repeated field
    /// lines arrive joined by `MetaView::header`, which is what makes a duplicated key header a
    /// value the strict decoders refuse rather than a value one of two spellings of.
    #[must_use]
    pub fn read(request: &MetaView<'a>) -> Self {
        Self {
            managed: ManagedChannel {
                algorithm: request.header(SSE_ALGORITHM),
                kms_key_id: request.header(SSE_KMS_KEY_ID),
                context: request.header(SSE_CONTEXT),
                bucket_key_enabled: request.header(SSE_BUCKET_KEY_ENABLED),
            },
            target: CustomerTrio {
                algorithm: request.header(SSEC_ALGORITHM),
                key: request.header(SSEC_KEY).map(KeyText),
                digest: request.header(SSEC_KEY_MD5),
            },
            copy_source: CustomerTrio {
                algorithm: request.header(COPY_SSEC_ALGORITHM),
                key: request.header(COPY_SSEC_KEY).map(KeyText),
                digest: request.header(COPY_SSEC_KEY_MD5),
            },
        }
    }

    /// Whether either side put a customer key, or a fragment of one, on the wire.
    #[must_use]
    pub fn any_customer_key_header(&self) -> bool {
        self.target.any_present() || self.copy_source.any_present()
    }
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `ops/shared/encryption.rs`.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ops::shared::encryption::EncryptionRejection;

    fn managed<'a>(
        algorithm: Option<&'a str>,
        kms: Option<&'a str>,
        context: Option<&'a str>,
        switch: Option<&'a str>,
    ) -> ManagedChannel<'a> {
        ManagedChannel {
            algorithm: algorithm.map(Cow::Borrowed),
            kms_key_id: kms.map(Cow::Borrowed),
            context: context.map(Cow::Borrowed),
            bucket_key_enabled: switch.map(Cow::Borrowed),
        }
    }

    const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    /// base64 of `{"a":"b"}`.
    const CONTEXT: &str = "eyJhIjoiYiJ9";

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_bare_aes256_request_is_accepted() {
        assert_eq!(managed(Some("AES256"), None, None, None).validate(), Ok(Some(SseAlgorithm::AES256)));
    }

    #[test]
    fn a_kms_request_with_every_qualifier_is_accepted() {
        let channel = managed(Some("aws:kms"), Some(KEY_ARN), Some(CONTEXT), Some("true"));
        assert_eq!(channel.validate(), Ok(Some(SseAlgorithm::AWS_KMS)));
    }

    #[test]
    fn the_double_layer_kms_spelling_is_accepted_with_the_same_qualifiers() {
        let channel = managed(Some("aws:kms:dsse"), Some(KEY_ARN), Some(CONTEXT), Some("false"));
        assert_eq!(channel.validate(), Ok(Some(SseAlgorithm::AWS_KMS_DSSE)));
    }

    #[test]
    fn a_request_naming_no_managed_algorithm_at_all_is_accepted() {
        assert_eq!(managed(None, None, None, None).validate(), Ok(None));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_an_unknown_algorithm_spelling_is_refused() {
        for spelling in ["aes256", "kms", "", "AES128", "aws:kms:", "AES256 "] {
            assert_eq!(
                managed(Some(spelling), None, None, None).validate(),
                Err(ManagedRejection::Document(EncryptionRejection::AlgorithmUnknown)),
                "accepted {spelling:?}"
            );
        }
    }

    #[test]
    fn n_a_kms_key_id_beside_aes256_is_refused() {
        assert_eq!(
            managed(Some("AES256"), Some(KEY_ARN), None, None).validate(),
            Err(ManagedRejection::Document(EncryptionRejection::KmsKeyWithoutKmsAlgorithm))
        );
    }

    #[test]
    fn n_a_context_or_a_bucket_key_switch_beside_aes256_is_refused() {
        assert_eq!(
            managed(Some("AES256"), None, Some(CONTEXT), None).validate(),
            Err(ManagedRejection::KmsQualifierWithoutKmsAlgorithm)
        );
        assert_eq!(
            managed(Some("AES256"), None, None, Some("true")).validate(),
            Err(ManagedRejection::KmsQualifierWithoutKmsAlgorithm)
        );
    }

    #[test]
    fn n_a_qualifier_with_no_algorithm_beside_it_is_refused() {
        for channel in [
            managed(None, Some(KEY_ARN), None, None),
            managed(None, None, Some(CONTEXT), None),
            managed(None, None, None, Some("true")),
        ] {
            assert_eq!(channel.validate(), Err(ManagedRejection::QualifierWithoutAlgorithm));
        }
    }

    #[test]
    fn n_the_bucket_key_switch_is_a_strict_boolean() {
        for spelling in ["TRUE", "True", "1", "0", "yes", "", " true"] {
            assert_eq!(
                managed(Some("aws:kms"), None, None, Some(spelling)).validate(),
                Err(ManagedRejection::BucketKeyNotABoolean),
                "accepted {spelling:?}"
            );
        }
    }

    fn context_json_is_accepted(json: &str) -> bool {
        let encoded = crate::sse::tests_support::base64_of(json.as_bytes());
        managed(Some("aws:kms"), None, Some(&encoded), None).validate().is_ok()
    }

    #[test]
    fn context_json_accepts_string_pairs_unicode_escapes_and_whitespace() {
        for json in [
            r#"{"key":"value","empty":""}"#,
            r#"{"emoji":"\ud83d\udd11","\u0061":"雪"}"#,
            " \r\n\t{} ",
        ] {
            assert!(context_json_is_accepted(json), "valid context refused");
        }
    }

    #[test]
    fn context_json_rejects_scalar_and_array_roots() {
        for json in ["null", "true", "1", r#""string""#, "[]", r#"["x"]"#] {
            assert!(!context_json_is_accepted(json), "non-object context accepted");
        }
    }

    #[test]
    fn context_json_rejects_non_string_values() {
        for json in [
            r#"{"key":null}"#,
            r#"{"key":false}"#,
            r#"{"key":42}"#,
            r#"{"key":[]}"#,
            r#"{"key":{}}"#,
        ] {
            assert!(!context_json_is_accepted(json), "non-string context value accepted");
        }
    }

    #[test]
    fn context_json_rejects_plain_and_escape_equivalent_duplicate_keys() {
        for json in [
            r#"{"key":"a","key":"b"}"#,
            r#"{"key":"a","\u006bey":"b"}"#,
            r#"{"":"a","":"b"}"#,
        ] {
            assert!(!context_json_is_accepted(json), "duplicate context key accepted");
        }
    }

    #[test]
    fn context_json_rejects_truncated_and_malformed_input() {
        for json in [
            "",
            "text",
            "{",
            r#"{"key":"value""#,
            r#"{"key":"value",}"#,
            r#"{"key" "value"}"#,
        ] {
            assert!(!context_json_is_accepted(json), "malformed context accepted");
        }
    }

    #[test]
    fn context_json_rejects_bad_escapes_and_unpaired_surrogates() {
        for json in [
            r#"{"key":"\q"}"#,
            r#"{"key":"\uD800"}"#,
            r#"{"key":"\uDC00"}"#,
            "{\"key\":\"line\nbreak\"}",
        ] {
            assert!(!context_json_is_accepted(json), "invalid JSON string accepted");
        }
    }

    #[test]
    fn context_json_rejects_a_second_value_or_trailing_garbage() {
        for json in ["{}{}", "{} null", "{} trailing", "{}\0", "{}\u{00a0}"] {
            assert!(!context_json_is_accepted(json), "trailing data accepted");
        }
    }

    #[test]
    fn context_json_rejects_deeply_nested_values_below_the_byte_limit() {
        let json = format!("{{\"key\":{}0{}}}", "[".repeat(500), "]".repeat(500));
        assert!(!context_json_is_accepted(&json), "nested value accepted");
    }

    #[test]
    fn n_a_context_that_is_not_canonical_base64_is_refused() {
        for spelling in ["not base64!", "eyJhIjoiYiJ9=", "eyJhIjoiYiJ", "  eyJhIjoiYiJ9"] {
            assert_eq!(
                managed(Some("aws:kms"), None, Some(spelling), None).validate(),
                Err(ManagedRejection::ContextNotBase64),
                "accepted {spelling:?}"
            );
        }
    }

    #[test]
    fn n_a_context_over_the_ceiling_is_refused_rather_than_decoded() {
        // 2052 bytes of `A`, encoded: over the 2048-byte ceiling by four bytes.
        let oversized = crate::sse::tests_support::base64_of(&vec![b'A'; MAX_CONTEXT_BYTES + 4]);
        assert_eq!(
            managed(Some("aws:kms"), None, Some(&oversized), None).validate(),
            Err(ManagedRejection::ContextNotBase64)
        );
        // The direction that proves the ceiling is a ceiling and not a blanket refusal.
        let json = format!("{{\"k\":\"{}\"}}", "A".repeat(MAX_CONTEXT_BYTES - 8));
        let at_the_limit = crate::sse::tests_support::base64_of(json.as_bytes());
        assert!(managed(Some("aws:kms"), None, Some(&at_the_limit), None).validate().is_ok());
    }

    #[test]
    fn n_a_context_whose_bytes_are_not_utf8_is_refused() {
        let not_utf8 = crate::sse::tests_support::base64_of(&[0xff, 0xfe, 0xfd]);
        assert_eq!(
            managed(Some("aws:kms"), None, Some(&not_utf8), None).validate(),
            Err(ManagedRejection::ContextNotBase64)
        );
    }

    /// Negative — the header rule and the document rule are the same rule.
    ///
    /// If a future edit gives this module its own algorithm set, the two stop agreeing and this
    /// case says so. Both directions are covered: an algorithm the document accepts must be
    /// accepted here, and one it refuses must be refused here.
    #[test]
    fn n_the_header_channel_and_the_stored_document_agree_on_every_spelling() {
        for spelling in ["AES256", "aws:kms", "aws:kms:dsse", "aws:fsx", "aes256", "AES128", "", "kms"] {
            let via_header = managed(Some(spelling), None, None, None).validate().is_ok();
            let document = ServerSideEncryptionConfiguration {
                rules: vec![ServerSideEncryptionRule {
                    apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
                        sse_algorithm: SseAlgorithm::custom(spelling.to_owned()),
                        kms_master_key_id: None,
                    }),
                    ..ServerSideEncryptionRule::default()
                }],
            };
            let via_document = validate_encryption(&document).is_ok();
            assert_eq!(via_header, via_document, "the two disagree about {spelling:?}");
        }
    }

    #[test]
    fn n_a_trio_reports_partial_presence_as_present_but_not_complete() {
        let partial = CustomerTrio {
            algorithm: Some(Cow::Borrowed(CUSTOMER_ALGORITHM)),
            key: None,
            digest: None,
        };
        assert!(partial.any_present());
        assert!(!partial.all_present());
        let empty = CustomerTrio {
            algorithm: None,
            key: None,
            digest: None,
        };
        assert!(!empty.any_present());
        assert!(!empty.all_present());
    }
}
