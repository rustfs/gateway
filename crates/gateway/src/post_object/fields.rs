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

//! The Object Lock and customer-key fields of a POST Object form, read under either grammar
//! (rustfs/gateway#1167).
//!
//! Responsible for: reading `x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`,
//! `x-amz-object-lock-legal-hold` and the three `x-amz-server-side-encryption-customer-*` fields
//! into the `PutObject` members of the same name ([`LockAndCustomerKey`]); the lookups the
//! pipeline runs over a form in place of request headers — the customer-key gate's
//! ([`sse_lookup`]) and the extra-permission triggers' ([`permission_fields`],
//! [`permission_applies`]: a field sent is set, an empty one included).
//! NOT responsible for: the retain-until date's RustFS-profile grammar (`super::legacy_date`),
//! judging the key (`rustfs_gateway_core::sse::enforce_with`, called by
//! `super::ResolvedPostObject`), asking the authorizer (`crate::service`'s route stage), the
//! closed value sets of the mode and hold (the handler's rule, as for the header), or any other
//! member (`super::legacy`).
//! Upstream: `super::PostObjectPrelude::resolve` and `super::legacy::object_fields`.
//! Downstream: `PostObjectInput::fields`, the route stage, the customer-key gate.
//!
//! # Why both grammars read these six
//!
//! A browser form may carry them on any profile, and each is a field the pipeline must act on
//! rather than drop: a lock a form asked for and did not get is a protection the client believes
//! it has, and a customer key the gate never saw is a key that went on the wire unjudged. Legacy
//! RustFS reads all six from the form for its `put_object` path and asks its access hook the lock
//! actions for them (`rustfs/src/storage/access.rs:3214-3220` at rustfs/rustfs `19978b2cb6`).

use std::borrow::Cow;

use http::HeaderMap;
use rustfs_gateway_core::sse::headers::{SSE_ALGORITHM, SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5};
use rustfs_gateway_core::{ExtraPermission, HeaderTrigger, Operation};
use rustfs_gateway_types::dto::{ObjectLockLegalHoldStatus, ObjectLockMode, PostObject, PostObjectFields};
use rustfs_gateway_types::{SseCustomerKey, Timestamp, TimestampFormat};

use super::S3Error;
use super::legacy::unreadable;

const LOCK_MODE: &str = "x-amz-object-lock-mode";
const LOCK_RETAIN_UNTIL: &str = "x-amz-object-lock-retain-until-date";
const LOCK_LEGAL_HOLD: &str = "x-amz-object-lock-legal-hold";

/// The grammar a form's `x-amz-object-lock-retain-until-date` is read with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DateGrammar {
    /// The gateway's own form grammar: the ISO 8601 instant the `PutObject` header is
    /// (`q-timestamp-0011`). No legacy stack answers that profile, and every field it reads is read
    /// as the header of the same name is.
    Iso8601Header,
    /// The RustFS profile: the RFC 3339 date-time legacy RustFS's form decoder reads
    /// (`super::legacy_date`), which differs from the header's grammar on a lowercase `t` or `z`, a
    /// separator other than `T`, a leap second, an empty fraction and a colon-less offset.
    LegacyRustfs,
}

/// The six members, read from a form.
pub(super) struct LockAndCustomerKey {
    object_lock_legal_hold_status: Option<ObjectLockLegalHoldStatus>,
    object_lock_mode: Option<ObjectLockMode>,
    object_lock_retain_until_date: Option<Timestamp>,
    sse_customer_algorithm: Option<String>,
    sse_customer_key: Option<SseCustomerKey>,
    sse_customer_key_md5: Option<String>,
}

impl LockAndCustomerKey {
    /// Reads the six fields. The mode, the hold and the three customer-key fields are the value as
    /// sent, an empty one included; the retain-until date is parsed with `grammar`, and one that
    /// does not read is the `400 InvalidArgument` legacy RustFS's decoder answers before
    /// authorization.
    ///
    /// # Errors
    ///
    /// The refusal of an unreadable retain-until date.
    pub(super) fn read(fields: &[(&str, &str)], grammar: DateGrammar) -> Result<Self, S3Error> {
        let field = |name: &str| fields.iter().find_map(|(field, value)| (*field == name).then_some(*value));
        let instant = |value: &str| match grammar {
            DateGrammar::Iso8601Header => Timestamp::parse(value, TimestampFormat::Iso8601).ok(),
            DateGrammar::LegacyRustfs => super::legacy_date::read(value),
        };
        let object_lock_retain_until_date = field(LOCK_RETAIN_UNTIL)
            .map(|value| instant(value).ok_or_else(|| unreadable(LOCK_RETAIN_UNTIL, value)))
            .transpose()?;
        Ok(Self {
            object_lock_legal_hold_status: field(LOCK_LEGAL_HOLD)
                .map(|value| ObjectLockLegalHoldStatus::custom(value.to_owned())),
            object_lock_mode: field(LOCK_MODE).map(|value| ObjectLockMode::custom(value.to_owned())),
            object_lock_retain_until_date,
            sse_customer_algorithm: field(SSEC_ALGORITHM).map(str::to_owned),
            sse_customer_key: field(SSEC_KEY).map(SseCustomerKey::from_wire),
            sse_customer_key_md5: field(SSEC_KEY_MD5).map(str::to_owned),
        })
    }

    /// `base`, with the six members set from this reading.
    pub(super) fn into_fields(self, base: PostObjectFields) -> PostObjectFields {
        PostObjectFields {
            object_lock_legal_hold_status: self.object_lock_legal_hold_status,
            object_lock_mode: self.object_lock_mode,
            object_lock_retain_until_date: self.object_lock_retain_until_date,
            sse_customer_algorithm: self.sse_customer_algorithm,
            sse_customer_key: self.sse_customer_key,
            sse_customer_key_md5: self.sse_customer_key_md5,
            ..base
        }
    }
}

/// Whether the form carried any of the three customer-key fields: the gate runs over the form
/// exactly when it would have run over the headers for the same trio, a lone fragment included.
pub(super) fn carries_customer_key(fields: &PostObjectFields) -> bool {
    fields.sse_customer_algorithm.is_some() || fields.sse_customer_key.is_some() || fields.sse_customer_key_md5.is_some()
}

/// The customer-key gate's reading of a form: the target trio and the managed algorithm by the
/// header names the gate asks for, nothing else. The copy-source names answer nothing, as a form
/// has no copy source; the KMS qualifiers answer nothing, since the gate is run only for a form
/// carrying a customer key, beside which any managed algorithm is already the contradiction. The
/// managed algorithm is the `x-amz-server-side-encryption` member, which only the RustFS profile
/// reads from a form: under the gateway grammar the field is not read, so there is nothing for
/// the key to contradict there.
pub(super) fn sse_lookup<'a>(fields: &'a PostObjectFields) -> impl Fn(&str) -> Option<Cow<'a, str>> + 'a {
    move |name: &str| {
        let value = match name {
            SSEC_ALGORITHM => fields.sse_customer_algorithm.as_deref(),
            // The one place the key is read as text, to be hashed by the gate and nothing else.
            SSEC_KEY => fields.sse_customer_key.as_ref().map(SseCustomerKey::expose_secret),
            SSEC_KEY_MD5 => fields.sse_customer_key_md5.as_deref(),
            SSE_ALGORITHM => fields.server_side_encryption.as_ref().map(|algorithm| algorithm.as_str()),
            _ => None,
        };
        value.map(Cow::Borrowed)
    }
}

/// The fields that can trigger one of `PostObject`'s extra permissions, as sent, for the route
/// stage to read where it reads a header for any other write.
pub(super) fn permission_fields(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    let triggers = PostObject::spec().extra_permission_set();
    fields
        .iter()
        .filter(|(name, _)| {
            triggers
                .iter()
                .flat_map(|extra| extra.triggers())
                .any(|trigger| trigger.header() == *name)
        })
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// Whether `extra` applies to a request: by its form's fields for a form upload, which reads none
/// of its request's headers, and by the request header for every other operation.
///
/// A form field that was sent is set, an empty one included: legacy RustFS's form decoder reads an
/// empty field as `Some("")`, never as absent, and its `put_object` access hook asks the lock
/// action for any field that is `Some` (rustfs/gateway#1167); the handler is handed the empty
/// member too, so the action is asked exactly when the member reaches the handler. A header keeps
/// the trigger's own rule, under which an empty value is unset, as the header codec reads it.
pub(crate) fn permission_applies(form: Option<&[(String, String)]>, headers: &HeaderMap, extra: &ExtraPermission) -> bool {
    let Some(fields) = form else {
        return extra.applies(|name| headers.get(name).and_then(|value| value.to_str().ok()));
    };
    extra.triggers().iter().any(|trigger| {
        let value = fields
            .iter()
            .find(|(field, _)| field == trigger.header())
            .map(|(_, value)| value.as_str());
        match trigger {
            HeaderTrigger::Present(_) => value.is_some(),
            HeaderTrigger::True(_) => trigger.fires(value),
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use http::StatusCode;

    use super::*;

    /// Positive — each of the six is read into its member; the date is an instant, the rest the
    /// value as sent.
    #[test]
    fn the_six_fields_are_read_into_their_members() {
        let read = LockAndCustomerKey::read(
            &[
                (LOCK_MODE, "GOVERNANCE"),
                (LOCK_RETAIN_UNTIL, "2030-01-01T00:00:00.000Z"),
                (LOCK_LEGAL_HOLD, "ON"),
                (SSEC_ALGORITHM, "AES256"),
                (SSEC_KEY, "key-text"),
                (SSEC_KEY_MD5, "digest-text"),
            ],
            DateGrammar::Iso8601Header,
        )
        .expect("every field reads");
        let fields = read.into_fields(PostObjectFields::default());
        assert_eq!(fields.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some("GOVERNANCE"));
        assert_eq!(fields.object_lock_retain_until_date.map(|instant| instant.secs()), Some(1_893_456_000));
        assert_eq!(fields.object_lock_legal_hold_status.as_ref().map(|status| status.as_str()), Some("ON"));
        assert_eq!(fields.sse_customer_algorithm.as_deref(), Some("AES256"));
        assert_eq!(fields.sse_customer_key.as_ref().map(SseCustomerKey::expose_secret), Some("key-text"));
        assert_eq!(fields.sse_customer_key_md5.as_deref(), Some("digest-text"));
        assert!(carries_customer_key(&fields));
    }

    /// Negative — a form without the six sets none of them and carries no key; a field whose name
    /// merely starts with one of theirs is not read.
    #[test]
    fn n_absent_fields_and_near_misses_set_nothing() {
        let read = LockAndCustomerKey::read(
            &[
                ("x-amz-object-lock-mode-extra", "GOVERNANCE"),
                ("x-amz-server-side-encryption-customer-key-extra", "k"),
            ],
            DateGrammar::LegacyRustfs,
        )
        .expect("nothing to read");
        let fields = read.into_fields(PostObjectFields::default());
        assert!(fields.is_empty(), "{fields:?}");
        assert!(!carries_customer_key(&fields));
    }

    /// Negative — a retain-until date its grammar does not read is `400 InvalidArgument`, naming
    /// the field: the spellings neither grammar reads under both, and each grammar's own refusals
    /// under it alone; the mode, the hold and the key fields are never refused here.
    #[test]
    fn n_an_unreadable_date_is_refused_and_nothing_else_is() {
        let both = [DateGrammar::Iso8601Header, DateGrammar::LegacyRustfs];
        for (value, grammars) in [
            ("Tue, 01 Jan 2030 00:00:00 GMT", &both[..]),
            ("2030-01-01", &both[..]),
            ("", &both[..]),
            (" 2030-01-01T00:00:00Z", &both[..]),
            ("20300101T000000Z", &both[..]),
            ("2030-01-01t00:00:00z", &both[..1]),
            ("2030-01-01T00:00:00+0800", &both[1..]),
        ] {
            for grammar in grammars.iter().copied() {
                let error = LockAndCustomerKey::read(&[(LOCK_RETAIN_UNTIL, value)], grammar)
                    .err()
                    .expect("not an instant");
                assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{grammar:?} {value:?}");
                assert_eq!(error.code().map(|code| code.as_str()), Some("InvalidArgument"), "{grammar:?} {value:?}");
                let names_the_field = error.message().is_some_and(|message| message.contains(LOCK_RETAIN_UNTIL));
                assert!(names_the_field, "{grammar:?} {value:?}");
            }
        }
        let read = LockAndCustomerKey::read(
            &[
                (LOCK_MODE, "ARCHIVE"),
                (LOCK_LEGAL_HOLD, "on"),
                (SSEC_ALGORITHM, ""),
                (SSEC_KEY, ""),
                (SSEC_KEY_MD5, "not base64"),
            ],
            DateGrammar::LegacyRustfs,
        )
        .expect("read as sent");
        let fields = read.into_fields(PostObjectFields::default());
        assert_eq!(fields.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some("ARCHIVE"));
        assert_eq!(fields.sse_customer_algorithm.as_deref(), Some(""));
        assert!(carries_customer_key(&fields));
    }

    /// Negative — the gate's lookup answers the four names it reads and nothing for any other,
    /// the copy-source and KMS names included.
    #[test]
    fn n_the_gate_lookup_answers_only_the_names_it_reads() {
        let fields = LockAndCustomerKey::read(
            &[
                (SSEC_ALGORITHM, "AES256"),
                (SSEC_KEY, "key-text"),
                (SSEC_KEY_MD5, "digest-text"),
            ],
            DateGrammar::Iso8601Header,
        )
        .expect("read")
        .into_fields(PostObjectFields {
            server_side_encryption: Some(rustfs_gateway_types::dto::ServerSideEncryption::custom("aws:kms".to_owned())),
            ssekms_key_id: Some("key-id".to_owned()),
            ..PostObjectFields::default()
        });
        let lookup = sse_lookup(&fields);
        assert_eq!(lookup(SSEC_ALGORITHM).as_deref(), Some("AES256"));
        assert_eq!(lookup(SSEC_KEY).as_deref(), Some("key-text"));
        assert_eq!(lookup(SSEC_KEY_MD5).as_deref(), Some("digest-text"));
        assert_eq!(lookup(SSE_ALGORITHM).as_deref(), Some("aws:kms"));
        for name in [
            rustfs_gateway_core::sse::headers::COPY_SSEC_KEY,
            rustfs_gateway_core::sse::headers::COPY_SSEC_ALGORITHM,
            rustfs_gateway_core::sse::headers::SSE_KMS_KEY_ID,
            "x-amz-server-side-encryption-customer-key-extra",
        ] {
            assert_eq!(lookup(name), None, "{name}");
        }
    }

    /// Positive and negative — the permission fields are exactly those a trigger names, as sent;
    /// a form applies an extra for a field it sent, an empty one included, and never for a
    /// request header; any other request applies it by the header's non-empty rule.
    #[test]
    fn the_permission_fields_are_the_trigger_names_and_a_sent_field_applies_its_extra() {
        let kept = permission_fields(&[
            (LOCK_MODE, "GOVERNANCE"),
            ("x-amz-tagging", "a=b"),
            ("x-amz-acl", ""),
            ("x-amz-meta-note", "n"),
            ("key", "k"),
            (SSEC_KEY, "key-text"),
        ]);
        assert_eq!(
            kept,
            vec![
                (LOCK_MODE.to_owned(), "GOVERNANCE".to_owned()),
                ("x-amz-tagging".to_owned(), "a=b".to_owned()),
                ("x-amz-acl".to_owned(), String::new()),
            ]
        );
        let extra = |action: &str| {
            PostObject::spec()
                .extra_permission_set()
                .iter()
                .find(|extra| extra.action() == action)
                .expect("PostObject declares the action")
        };
        let (retention, hold, tagging) = (
            extra("s3:PutObjectRetention"),
            extra("s3:PutObjectLegalHold"),
            extra("s3:PutObjectTagging"),
        );
        let headers = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(LOCK_MODE, http::HeaderValue::from_static(value));
            headers
        };
        let sent = |name: &str, value: &str| vec![(name.to_owned(), value.to_owned())];
        // A form: a field it sent, an empty one included; never the request's headers.
        assert!(permission_applies(Some(&kept), &HeaderMap::new(), retention));
        assert!(permission_applies(Some(&kept), &HeaderMap::new(), tagging));
        assert!(permission_applies(Some(&sent(LOCK_MODE, "")), &HeaderMap::new(), retention));
        assert!(permission_applies(Some(&sent(LOCK_LEGAL_HOLD, "")), &HeaderMap::new(), hold));
        assert!(!permission_applies(Some(&kept), &HeaderMap::new(), hold), "no hold field");
        assert!(
            !permission_applies(Some(&[]), &headers("COMPLIANCE"), retention),
            "a form never reads a header"
        );
        // Any other request: the header, by the trigger's own rule.
        assert!(permission_applies(None, &headers("COMPLIANCE"), retention));
        assert!(!permission_applies(None, &headers(""), retention), "an empty header is unset");
        assert!(!permission_applies(None, &headers("COMPLIANCE"), hold));
    }
}
