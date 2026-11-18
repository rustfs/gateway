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

//! A browser form's POST policy that no signature covers, read as legacy RustFS reads it.
//!
//! Responsible for: [`UnsignedPostPolicy`], the legacy SigV2-form reading of a policy without its
//! two signature fields, and [`PostPolicyRefusal`], which names the condition a form failed.
//! NOT responsible for: who sent the form (an unsigned policy authenticates nobody: the request
//! stays anonymous), multipart framing, or HTTP answers.
//! Upstream: the bounded form prelude. Downstream: the gateway's POST Object bridge.

use super::{
    BucketBinding, FieldSet, PolicyReading, PostPolicyEnforcement, PostPolicyError, PostPolicyLimits, enforce_final_values,
    enforce_policy_fields, parse_policy_document,
};
use crate::RequestNow;

/// A refusal of a POST policy, naming the `eq` or `starts-with` condition that failed where one
/// did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostPolicyRefusal {
    error: PostPolicyError,
    condition: Option<(&'static str, String)>,
}

impl PostPolicyRefusal {
    pub(super) const fn condition(operator: &'static str, field: String) -> Self {
        Self {
            error: PostPolicyError::ConditionFailed,
            condition: Some((operator, field)),
        }
    }

    /// What was refused.
    #[must_use]
    pub const fn error(&self) -> PostPolicyError {
        self.error
    }

    /// The failed condition's operator (`eq` or `starts-with`) and the field it names, lowercased.
    /// The field name comes from the policy: a caller echoing it must first check that the form
    /// itself carries that field.
    #[must_use]
    pub fn failed_condition(&self) -> Option<(&'static str, &str)> {
        self.condition.as_ref().map(|(operator, field)| (*operator, field.as_str()))
    }
}

impl From<PostPolicyError> for PostPolicyRefusal {
    fn from(error: PostPolicyError) -> Self {
        Self { error, condition: None }
    }
}

impl From<PostPolicyRefusal> for PostPolicyError {
    fn from(refusal: PostPolicyRefusal) -> Self {
        refusal.error
    }
}

/// A POST policy a form carries without a signature, parsed and enforced as legacy RustFS
/// enforces one (rustfs/backlog#2734): its operators, expiration spellings, exempt fields and
/// deferred coverage are [`super::SigV2PostPolicy::parse_as_legacy_rustfs`]'s, without that
/// reading's two signature fields.
///
/// It proves nothing about the sender and has no `verify`: the form stays anonymous, and access
/// is whatever the bucket grants the public.
pub struct UnsignedPostPolicy {
    bucket: BucketBinding,
    final_key: String,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
    unlisted_field: Option<String>,
}

impl core::fmt::Debug for UnsignedPostPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnsignedPostPolicy")
            .field("read_ceiling", &self.maximum_file_bytes)
            .finish_non_exhaustive()
    }
}

impl UnsignedPostPolicy {
    /// Parses the form's policy and enforces its pre-file conditions.
    ///
    /// # Errors
    ///
    /// A malformed or expired policy, or the first condition the form fails, named.
    pub fn parse_as_legacy_rustfs(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
    ) -> Result<Self, PostPolicyRefusal> {
        let reading = PolicyReading::LegacyRustfsSigV2Form;
        let fields = FieldSet::parse(fields)?;
        let (encoded, conditions) = parse_policy_document(&fields, limits, now, reading)?;
        let common = enforce_policy_fields(&fields, raw_filename, limits, encoded, &conditions, reading)?;
        Ok(Self {
            bucket: common.bucket,
            final_key: common.final_key,
            minimum_file_bytes: common.minimum_file_bytes,
            maximum_file_bytes: common.maximum_file_bytes,
            unlisted_field: common.unlisted_field,
        })
    }

    /// The final key after safe filename substitution.
    #[must_use]
    pub fn final_key(&self) -> &str {
        &self.final_key
    }

    /// Maximum bytes the multipart reader may accept before stopping.
    #[must_use]
    pub const fn read_ceiling(&self) -> u64 {
        self.maximum_file_bytes
    }

    /// The first form field, in name order, that no condition names: a field the form carries.
    #[must_use]
    pub fn unlisted_field(&self) -> Option<&str> {
        self.unlisted_field.as_deref()
    }

    /// Rechecks the routed bucket, the key and the file size, then whether every field was named.
    ///
    /// # Errors
    ///
    /// As [`super::SigV2PostPolicy::enforce_final`].
    pub fn enforce_final(&self, bucket: &str, key: &str, file_bytes: u64) -> Result<PostPolicyEnforcement, PostPolicyError> {
        enforce_final_values(
            &self.bucket,
            &self.final_key,
            (self.minimum_file_bytes, self.maximum_file_bytes),
            self.unlisted_field.is_some(),
            bucket,
            key,
            file_bytes,
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const POLICY: &[u8; 178] = br#"{"expiration":"2030-01-01T00:00:00.000Z","conditions":[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-meta-project":"alpha"},["content-length-range",2,8]]}"#;

    fn parse(extra: &[(&str, &str)], now: i64) -> Result<UnsignedPostPolicy, PostPolicyRefusal> {
        let encoded = crate::codec::encode_base64_exact(POLICY);
        let mut fields = vec![
            ("key", "uploads/report.txt"),
            ("policy", encoded.as_str()),
            ("x-amz-meta-project", "alpha"),
        ];
        fields.extend_from_slice(extra);
        UnsignedPostPolicy::parse_as_legacy_rustfs(&fields, "", PostPolicyLimits::default(), RequestNow::from_unix_seconds(now))
    }

    fn replaced(name: &str, value: &str) -> Result<UnsignedPostPolicy, PostPolicyRefusal> {
        let encoded = crate::codec::encode_base64_exact(POLICY);
        let mut fields = vec![
            ("key", "uploads/report.txt"),
            ("policy", encoded.as_str()),
            ("x-amz-meta-project", "alpha"),
        ];
        fields.retain(|(field, _)| *field != name);
        if !value.is_empty() {
            fields.push((name, value));
        }
        UnsignedPostPolicy::parse_as_legacy_rustfs(&fields, "", PostPolicyLimits::default(), RequestNow::from_unix_seconds(0))
    }

    /// Positive — a form with a policy and no signature field is read and enforced: the key, the
    /// routed bucket and a size inside the range are admitted.
    #[test]
    fn a_policy_without_a_signature_is_read_and_enforced() {
        let policy = parse(&[], 0).expect("an unsigned policy is read");
        assert_eq!(policy.final_key(), "uploads/report.txt");
        assert_eq!(policy.read_ceiling(), 8);
        assert_eq!(policy.unlisted_field(), None);
        assert!(policy.enforce_final("example-bucket", "uploads/report.txt", 4).is_ok());
    }

    /// Positive — legacy RustFS's exempt fields need no condition: an access key without its
    /// signature, `submit`, an encryption field and an `x-ignore-*` field.
    #[test]
    fn legacy_exempt_fields_need_no_condition() {
        for extra in [
            ("awsaccesskeyid", "AKIDEXAMPLE"),
            ("submit", "Upload"),
            ("x-amz-server-side-encryption", "AES256"),
            ("x-ignore-trace", "1"),
        ] {
            let policy = parse(&[extra], 0).expect("exempt");
            assert_eq!(policy.unlisted_field(), None, "{extra:?}");
            assert!(policy.enforce_final("example-bucket", "uploads/report.txt", 4).is_ok(), "{extra:?}");
        }
    }

    /// Negative — an exact condition the form's value fails names `eq` and the field.
    #[test]
    fn n_a_failed_exact_condition_is_named() {
        let refusal = replaced("x-amz-meta-project", "beta").expect_err("refused");
        assert_eq!(refusal.error(), PostPolicyError::ConditionFailed);
        assert_eq!(refusal.failed_condition(), Some(("eq", "x-amz-meta-project")));
    }

    /// Negative — an exact condition whose field the form lacks is named too.
    #[test]
    fn n_an_exact_condition_over_a_missing_field_is_named() {
        let refusal = replaced("x-amz-meta-project", "").expect_err("refused");
        assert_eq!(refusal.failed_condition(), Some(("eq", "x-amz-meta-project")));
    }

    /// Negative — a prefix condition the key fails names `starts-with` and the field.
    #[test]
    fn n_a_failed_prefix_condition_is_named() {
        let refusal = replaced("key", "other/report.txt").expect_err("refused");
        assert_eq!(refusal.error(), PostPolicyError::ConditionFailed);
        assert_eq!(refusal.failed_condition(), Some(("starts-with", "key")));
    }

    /// Negative — a form `bucket` other than the policy's fails the bucket's exact condition.
    #[test]
    fn n_a_form_bucket_the_policy_does_not_name_is_refused() {
        let refusal = parse(&[("bucket", "different-bucket")], 0).expect_err("refused");
        assert_eq!(refusal.failed_condition(), Some(("eq", "bucket")));
    }

    /// Negative — a policy for another bucket than the routed one is refused at the final check.
    #[test]
    fn n_another_routed_bucket_is_refused_at_the_end() {
        let policy = parse(&[], 0).expect("read");
        assert_eq!(
            policy.enforce_final("another-bucket", "uploads/report.txt", 4).err(),
            Some(PostPolicyError::ConditionFailed)
        );
    }

    /// Negative — an expired policy is refused whether or not anything signs it.
    #[test]
    fn n_an_expired_unsigned_policy_is_refused() {
        let refusal = parse(&[], 2_000_000_000).expect_err("refused");
        assert_eq!(refusal, PostPolicyRefusal::from(PostPolicyError::Expired));
    }

    /// Negative — a policy that is not base64, and a form without a policy, are malformed.
    #[test]
    fn n_an_unreadable_or_absent_policy_is_malformed() {
        for value in ["not base64!", ""] {
            let refusal = replaced("policy", value).expect_err("refused");
            assert_eq!(refusal, PostPolicyRefusal::from(PostPolicyError::Malformed), "{value:?}");
        }
    }

    /// Negative — a field no condition names, the SigV4 credential fields included (legacy RustFS
    /// does not exempt them), is refused last and named: the first in name order.
    #[test]
    fn n_an_unnamed_field_is_refused_last_and_named() {
        let policy = parse(&[("x-amz-meta-zone", "a"), ("x-amz-credential", "AKID/x")], 0).expect("deferred");
        assert_eq!(policy.unlisted_field(), Some("x-amz-credential"));
        assert_eq!(
            policy.enforce_final("example-bucket", "uploads/report.txt", 4).err(),
            Some(PostPolicyError::FieldNotInPolicy)
        );
        assert_eq!(
            policy.enforce_final("example-bucket", "uploads/report.txt", 9).err(),
            Some(PostPolicyError::EntityTooLarge),
            "the size is judged before coverage"
        );
    }

    /// Negative — a file outside the size range is too large or too small.
    #[test]
    fn n_a_file_outside_the_range_is_refused() {
        let policy = parse(&[], 0).expect("read");
        for (bytes, error) in [(9, PostPolicyError::EntityTooLarge), (1, PostPolicyError::EntityTooSmall)] {
            assert_eq!(policy.enforce_final("example-bucket", "uploads/report.txt", bytes).err(), Some(error));
        }
    }
}
