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

//! A form policy no signature covers, enforced as legacy RustFS enforces one, and its answers.
//!
//! Responsible for: which forms carry such a policy, and answering each refusal of it in legacy
//! RustFS's code and sentence (`ServiceBuilder::enforce_unsigned_post_policies_as_legacy_rustfs`).
//! NOT responsible for: the policy reading itself (`rustfs_gateway_sig::UnsignedPostPolicy`), who
//! sent the form (the request stays anonymous; this module never touches an identity), or the
//! file stream (`super::PostFileBody`).
//! Upstream: `super::PostObjectPrelude::resolve`. Downstream: `super::refusals`'s renderer.
//!
//! Evidence: the pinned s3s (`ops/mod.rs` `parse_post_policy`, `post_policy.rs`
//! `validate_conditions_only`) parses and enforces a form's policy whether or not the form is
//! signed, and answers each failure with the codes below; RustFS's suite
//! (`crates/e2e_test/src/multipart_auth_test.rs`, `test_anonymous_post_object_*`) reads the field
//! names, the `starts-with` operator, the form's conflicting bucket and the size sentences.
//!
//! Legacy-compat (rustfs/backlog#2734): those sentences name what the same form sent — a field
//! name, its `bucket` value — where rustfs/gateway#1444 echoes nothing. A policy value, a
//! credential and a signature are never echoed, and nor is a name only the policy holds.

use std::borrow::Cow;

use rustfs_gateway_sig::{PostPolicyError, PostPolicyLimits, PostPolicyRefusal, RequestNow, UnsignedPostPolicy};

use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_handler};
use crate::{ErrorCode, HandlerError, ResponseKind};

/// The longest form name or value a message repeats; a longer one is left out of the message.
const MAX_ECHO_BYTES: usize = 1024;

/// Whether the form carries a policy and no signature, so nothing binds the policy to anyone.
pub(super) fn applies(fields: &[(&str, &str)]) -> bool {
    let has = |wanted: &str| fields.iter().any(|(name, _)| *name == wanted);
    has("policy") && !has("x-amz-signature") && !has("signature")
}

/// An unsigned policy, with what its refusals may name from the same form.
pub(super) struct UnsignedForm {
    policy: UnsignedPostPolicy,
    /// The form's own `bucket` field, as sent.
    form_bucket: Option<String>,
    routed_bucket: String,
}

impl UnsignedForm {
    /// Parses the policy and enforces its pre-file conditions.
    pub(super) fn parse(
        fields: &[(&str, &str)],
        filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
        routed_bucket: &str,
    ) -> Result<Self, S3Error> {
        let form_bucket = fields
            .iter()
            .find_map(|(name, value)| (*name == "bucket").then(|| (*value).to_owned()));
        match UnsignedPostPolicy::parse_as_legacy_rustfs(fields, filename, limits, now) {
            Ok(policy) => Ok(Self {
                policy,
                form_bucket,
                routed_bucket: routed_bucket.to_owned(),
            }),
            Err(refusal) => Err(Self::form_refusal(&refusal, fields, form_bucket.as_deref(), routed_bucket)),
        }
    }

    pub(super) const fn policy(&self) -> &UnsignedPostPolicy {
        &self.policy
    }

    /// The answer to a file the policy refuses: its size, the routed bucket, or an unnamed field.
    pub(super) fn file_refusal(&self, error: PostPolicyError) -> S3Error {
        match error {
            PostPolicyError::EntityTooLarge => answer(
                ErrorCode::ENTITY_TOO_LARGE,
                "Your proposed upload exceeds the maximum allowed object size.".into(),
            ),
            PostPolicyError::EntityTooSmall => answer(
                ErrorCode::ENTITY_TOO_SMALL,
                "Your proposed upload is smaller than the minimum allowed object size.".into(),
            ),
            PostPolicyError::FieldNotInPolicy => {
                let named = self
                    .policy
                    .unlisted_field()
                    .and_then(echo)
                    .map_or_else(String::new, |name| format!(" \"{name}\" not specified in the policy."));
                answer(
                    ErrorCode::ACCESS_DENIED,
                    format!("Each form field that you specify in a form must appear in the list of policy conditions.{named}")
                        .into(),
                )
            }
            PostPolicyError::ConditionFailed => {
                bucket_mismatch(self.form_bucket.as_deref(), &self.routed_bucket).unwrap_or_else(|| {
                    answer(ErrorCode::INVALID_POLICY_DOCUMENT, "Policy condition for field 'bucket' failed".into())
                })
            }
            _ => answer(ErrorCode::ACCESS_DENIED, "the POST file did not satisfy its policy".into()),
        }
    }

    fn form_refusal(refusal: &PostPolicyRefusal, fields: &[(&str, &str)], form_bucket: Option<&str>, routed: &str) -> S3Error {
        match refusal.error() {
            PostPolicyError::Expired => answer(ErrorCode::ACCESS_DENIED, "Request has expired".into()),
            PostPolicyError::ConditionFailed => {
                let Some((operator, field)) = refusal.failed_condition() else {
                    return answer(ErrorCode::INVALID_POLICY_DOCUMENT, "Policy condition failed".into());
                };
                if field == "bucket"
                    && let Some(mismatch) = bucket_mismatch(form_bucket, routed)
                {
                    return mismatch;
                }
                let sent = fields.iter().any(|(name, _)| name.eq_ignore_ascii_case(field));
                let message = match echo(field).filter(|_| sent) {
                    Some(field) => format!("Policy condition '{operator}' for field '{field}' failed"),
                    None => format!("Policy condition '{operator}' failed"),
                };
                answer(ErrorCode::INVALID_POLICY_DOCUMENT, message.into())
            }
            _ => answer(ErrorCode::INVALID_POLICY_DOCUMENT, "failed to parse POST policy".into()),
        }
    }
}

/// A form `bucket` other than the routed one, named as the form sent it.
fn bucket_mismatch(form_bucket: Option<&str>, routed: &str) -> Option<S3Error> {
    let sent = form_bucket.filter(|sent| *sent != routed)?;
    let message = match echo(sent) {
        Some(sent) => format!("Bucket in form field '{sent}' does not match bucket in URL '{routed}'"),
        None => format!("Bucket in form field does not match bucket in URL '{routed}'"),
    };
    Some(answer(ErrorCode::INVALID_POLICY_DOCUMENT, message.into()))
}

fn echo(text: &str) -> Option<&str> {
    (text.len() <= MAX_ECHO_BYTES).then_some(text)
}

/// A refusal in legacy RustFS's own sentence, which the profile's body rewording leaves alone: that
/// rewording is for a declared length above RustFS's request ceiling, not for a policy's range.
fn answer(code: ErrorCode, message: Cow<'static, str>) -> S3Error {
    let mut refusal = from_handler(HandlerError::new(code, message), ResponseKind::Other, ConnectionIntent::MayKeepAlive);
    refusal.keeps_its_sentence = true;
    refusal
}
