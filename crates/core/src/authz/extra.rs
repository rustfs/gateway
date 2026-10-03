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

//! The IAM actions an operation requires only when the request carries a particular header.
//!
//! Responsible for: [`ExtraPermission`] — one action a write requires on top of its base action
//! when a header is present — its trigger set ([`HeaderTrigger`]), and the profile that decides
//! whether the RustFS profile may waive it ([`ExtraProfile`]).
//! NOT responsible for: reading a header (the caller passes a lookup), asking the authorizer (the
//! facade's route stage), or the base action ([`crate::AuthRequirement`]).
//! Upstream: `crate::registry::OperationSpec`. Downstream: the facade route stage.
//!
//! # Why these are separate from the action rule
//!
//! S3 requires `s3:PutObjectRetention` on a `PutObject` **only when** the request sets an
//! object-lock retention header, `s3:PutObjectLegalHold` only with a legal-hold header,
//! `s3:BypassGovernanceRetention` only with `x-amz-bypass-governance-retention: true`, and
//! `s3:PutObjectTagging` / `s3:PutObjectAcl` only with a tagging / ACL header
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>).
//! The base action is always required; these are extra, header-gated, and each is an all-of
//! obligation — every triggered one must be allowed. Modelling them as `ActionRule::AllOf` would
//! require every action of every request, so they are their own list, evaluated against the
//! request's headers before the body is read.

/// When one header makes an [`ExtraPermission`] apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderTrigger {
    /// The header is present with a non-empty value (after trimming ASCII whitespace).
    ///
    /// This is how a DTO header binding reads as set: an object-lock mode, a retain-until date, a
    /// legal-hold status (`OFF` included, as legacy RustFS reads it), a tag set, or a canned ACL
    /// or grant header.
    Present(&'static str),
    /// The header is present and its trimmed value is `true`, case-insensitively.
    ///
    /// `x-amz-bypass-governance-retention` is a boolean flag; only a `true` bypasses governance,
    /// as legacy RustFS's `has_bypass_governance_header` reads it.
    True(&'static str),
}

impl HeaderTrigger {
    /// The header name this trigger inspects.
    #[must_use]
    pub const fn header(self) -> &'static str {
        match self {
            Self::Present(header) | Self::True(header) => header,
        }
    }

    /// Whether `value`, the header's raw value (or `None` when absent), fires this trigger.
    #[must_use]
    pub fn fires(self, value: Option<&str>) -> bool {
        match self {
            Self::Present(_) => value.is_some_and(|value| !value.trim_matches(is_ascii_whitespace).is_empty()),
            Self::True(_) => value.is_some_and(|value| value.trim_matches(is_ascii_whitespace).eq_ignore_ascii_case("true")),
        }
    }
}

fn is_ascii_whitespace(c: char) -> bool {
    c.is_ascii_whitespace()
}

/// Whether an [`ExtraPermission`] is one the RustFS profile may waive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtraProfile {
    /// AWS and legacy RustFS both require it: no deployment waives it.
    ///
    /// The object-lock retention and legal-hold actions on a write, and
    /// `s3:BypassGovernanceRetention` on a delete or retention change.
    Generic,
    /// AWS requires it, legacy RustFS does not: the generic profile requires it, and the RustFS
    /// profile waives it to match legacy.
    ///
    /// `s3:PutObjectTagging` for a tagging header and `s3:PutObjectAcl` for an ACL header, which
    /// legacy RustFS's access hook does not ask on a `PutObject`, `CopyObject`,
    /// `CreateMultipartUpload` or `PostObject` (`rustfs/src/storage/access.rs` on rustfs/rustfs
    /// `d60dfbb826` asks the base action alone for those; the tag header only adds
    /// `RequestObjectTag` condition keys to it).
    RustfsWaivable,
}

/// One IAM action a request requires on top of its base action when a header triggers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtraPermission {
    action: &'static str,
    triggers: &'static [HeaderTrigger],
    profile: ExtraProfile,
}

impl ExtraPermission {
    /// An extra permission required whenever any of `triggers` fires.
    #[must_use]
    pub const fn new(action: &'static str, triggers: &'static [HeaderTrigger], profile: ExtraProfile) -> Self {
        Self {
            action,
            triggers,
            profile,
        }
    }

    /// The IAM action, in its wire spelling.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }

    /// The headers that trigger it.
    #[must_use]
    pub const fn triggers(&self) -> &'static [HeaderTrigger] {
        self.triggers
    }

    /// Whether the RustFS profile may waive it.
    #[must_use]
    pub const fn profile(&self) -> ExtraProfile {
        self.profile
    }

    /// Whether this permission applies to a request whose headers `lookup` reads.
    ///
    /// `lookup` returns a header's raw value, or `None` when it is absent; the value may be
    /// borrowed or owned (`&str`, `String`, `Cow`), which is what lets the facade pass its
    /// per-request view without allocating. Any trigger that fires applies the permission.
    pub fn applies<S: AsRef<str>>(&self, lookup: impl Fn(&str) -> Option<S>) -> bool {
        self.triggers
            .iter()
            .any(|trigger| trigger.fires(lookup(trigger.header()).as_ref().map(AsRef::as_ref)))
    }

    /// The reason this permission cannot be registered, or `None`.
    ///
    /// An action is spelled `service:Action`, and a permission names at least one trigger.
    #[must_use]
    pub fn fault(&self) -> Option<&'static str> {
        if self.triggers.is_empty() {
            return Some("an extra permission names at least one header trigger");
        }
        if !crate::op::is_well_formed_action(self.action) {
            return Some("an extra permission's action is spelled `service:Action`");
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn present_fires_only_for_a_non_empty_value() {
        let trigger = HeaderTrigger::Present("x-amz-object-lock-mode");
        assert!(trigger.fires(Some("GOVERNANCE")));
        assert!(trigger.fires(Some("OFF")), "a legal-hold OFF still triggers, as legacy reads it");
        assert!(!trigger.fires(None));
        assert!(!trigger.fires(Some("")));
        assert!(!trigger.fires(Some("  ")), "an all-whitespace value is empty");
    }

    #[test]
    fn true_fires_only_for_true() {
        let trigger = HeaderTrigger::True("x-amz-bypass-governance-retention");
        assert!(trigger.fires(Some("true")));
        assert!(trigger.fires(Some("TRUE")));
        assert!(trigger.fires(Some(" true ")));
        assert!(!trigger.fires(Some("false")));
        assert!(!trigger.fires(Some("1")));
        assert!(!trigger.fires(None));
        assert!(!trigger.fires(Some("")));
    }

    #[test]
    fn applies_when_any_trigger_fires() {
        let retention = ExtraPermission::new(
            "s3:PutObjectRetention",
            &[
                HeaderTrigger::Present("x-amz-object-lock-mode"),
                HeaderTrigger::Present("x-amz-object-lock-retain-until-date"),
            ],
            ExtraProfile::Generic,
        );
        let has = |name: &str| -> Option<&str> {
            match name {
                "x-amz-object-lock-retain-until-date" => Some("2030-01-01T00:00:00Z"),
                _ => None,
            }
        };
        assert!(retention.applies(has));
        assert!(!retention.applies(|_: &str| Option::<&str>::None));
    }

    #[test]
    fn a_well_formed_permission_has_no_fault() {
        let permission = ExtraPermission::new(
            "s3:PutObjectLegalHold",
            &[HeaderTrigger::Present("x-amz-object-lock-legal-hold")],
            ExtraProfile::Generic,
        );
        assert_eq!(permission.fault(), None);
    }

    #[test]
    fn n_a_permission_without_a_trigger_or_a_malformed_action_is_refused() {
        assert!(
            ExtraPermission::new("s3:PutObjectRetention", &[], ExtraProfile::Generic)
                .fault()
                .expect("no trigger is a fault")
                .contains("at least one")
        );
        assert!(
            ExtraPermission::new("PutObjectRetention", &[HeaderTrigger::Present("h")], ExtraProfile::Generic)
                .fault()
                .expect("malformed action is a fault")
                .contains("service:Action")
        );
    }
}
