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

//! The header-conditional IAM actions the object-write operations share.
//!
//! Members: PutObject, CopyObject, CreateMultipartUpload, DeleteObject, PutObjectRetention
//!
//! Responsible for: [`OBJECT_WRITE`], the extra permissions a request that stores an object
//! requires when it sets an object-lock, tagging or ACL header, and [`GOVERNANCE_BYPASS`], the one
//! a delete or retention change requires when it bypasses governance retention. One list, so a
//! rule added to it reaches every member instead of three of four.
//! NOT responsible for: the base action ([`crate::AuthRequirement`] on each op), reading a header
//! (the facade), or asking the authorizer (the facade route stage).
//! Upstream: `crate::authz`. Downstream: the operation modules that list it. `PostObject` is
//! deliberately not a member: its object-lock, tagging and ACL values are form fields, not HTTP
//! headers, so these header triggers never fire for it; its form-field permissions are the
//! POST-form seam's (rustfs/gateway#1167).
//!
//! # Where the actions come from
//!
//! AWS's required-permission table
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>)
//! lists, for `PutObject`, `CopyObject` and `CreateMultipartUpload`, `s3:PutObjectRetention` and
//! `s3:PutObjectLegalHold` as conditionally required with the object-lock headers, and
//! `s3:PutObjectAcl` / `s3:PutObjectTagging` with an ACL / tagging header; for `DeleteObject` and
//! `PutObjectRetention`, `s3:BypassGovernanceRetention` with `x-amz-bypass-governance-retention`.
//!
//! Legacy RustFS asks the two object-lock actions and the bypass action the same way
//! (`rustfs/src/storage/access.rs` `legal_hold_write_requested` / `retention_write_requested` /
//! `has_bypass_governance_header` on rustfs/rustfs `d60dfbb826`: the `PutObject` hook at
//! `:3182-3188`, `CopyObject` at `:2227-2233`, `CreateMultipartUpload` at `:2251-2257`,
//! `DeleteObject` at `:2447-2449`, `PutObjectRetention` at `:3242-3245`), so those are
//! [`ExtraProfile::Generic`]. It does **not** ask `s3:PutObjectAcl` or `s3:PutObjectTagging` for
//! those headers — its access hook asks the base `s3:PutObject` alone and the tag header only adds
//! `RequestObjectTag` condition keys to it — so those two are [`ExtraProfile::RustfsWaivable`]:
//! the generic profile requires them as AWS does, and the RustFS profile waives them.

use crate::authz::{ExtraPermission, ExtraProfile, HeaderTrigger};

/// The extra permissions an object-store write requires, by the header that triggers each.
///
/// A member operation whose input carries none of these headers requires only its base action.
pub static OBJECT_WRITE: [ExtraPermission; 4] = [
    ExtraPermission::new(
        "s3:PutObjectRetention",
        &[
            HeaderTrigger::Present("x-amz-object-lock-mode"),
            HeaderTrigger::Present("x-amz-object-lock-retain-until-date"),
        ],
        ExtraProfile::Generic,
    ),
    ExtraPermission::new(
        "s3:PutObjectLegalHold",
        &[HeaderTrigger::Present("x-amz-object-lock-legal-hold")],
        ExtraProfile::Generic,
    ),
    ExtraPermission::new(
        "s3:PutObjectTagging",
        &[HeaderTrigger::Present("x-amz-tagging")],
        ExtraProfile::RustfsWaivable,
    ),
    ExtraPermission::new(
        "s3:PutObjectAcl",
        &[
            HeaderTrigger::Present("x-amz-acl"),
            HeaderTrigger::Present("x-amz-grant-full-control"),
            HeaderTrigger::Present("x-amz-grant-read"),
            HeaderTrigger::Present("x-amz-grant-read-acp"),
            HeaderTrigger::Present("x-amz-grant-write-acp"),
        ],
        ExtraProfile::RustfsWaivable,
    ),
];

/// The one extra permission a delete or a retention change requires when it bypasses governance
/// retention.
pub static GOVERNANCE_BYPASS: [ExtraPermission; 1] = [ExtraPermission::new(
    "s3:BypassGovernanceRetention",
    &[HeaderTrigger::True("x-amz-bypass-governance-retention")],
    ExtraProfile::Generic,
)];
