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

//! Which header-conditional extra permissions each object-write operation declares.
//!
//! Responsible for: the extra permissions and their profiles on PutObject, PostObject, CopyObject,
//! CreateMultipartUpload, DeleteObject and PutObjectRetention, and that a header-less request
//! triggers none of them. NOT responsible for: asking them (the gateway runtime suite) or the
//! registration rules (the registry unit suite).
//! Upstream: the op specs. Downstream: nothing.
//!
//! Evidence: AWS's required-permission table
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>)
//! lists these as conditionally required by the matching header.

use rustfs_gateway_core::op::Operation;
use rustfs_gateway_core::{ExtraPermission, ExtraProfile};
use rustfs_gateway_types::dto;

fn extras<O: Operation>() -> &'static [ExtraPermission] {
    O::spec().extra_permission_set()
}

/// One (action, profile) per declared extra permission, in declaration order.
fn shape(extras: &[ExtraPermission]) -> Vec<(&'static str, ExtraProfile)> {
    extras.iter().map(|extra| (extra.action(), extra.profile())).collect()
}

const OBJECT_WRITE: [(&str, ExtraProfile); 4] = [
    ("s3:PutObjectRetention", ExtraProfile::Generic),
    ("s3:PutObjectLegalHold", ExtraProfile::Generic),
    ("s3:PutObjectTagging", ExtraProfile::RustfsWaivable),
    ("s3:PutObjectAcl", ExtraProfile::RustfsWaivable),
];

/// The three header-driven object-store writes require the object-lock actions (generic) and the
/// tagging/ACL actions (RustFS-waivable) by their headers.
#[test]
fn the_object_writes_require_the_lock_tag_and_acl_actions_by_header() {
    assert_eq!(shape(extras::<dto::PutObject>()), OBJECT_WRITE);
    assert_eq!(shape(extras::<dto::CopyObject>()), OBJECT_WRITE);
    assert_eq!(shape(extras::<dto::CreateMultipartUpload>()), OBJECT_WRITE);
}

/// `PostObject` declares the same four: its object-lock, tagging and ACL values are form fields
/// rather than HTTP headers, and the facade's route stage reads the triggers off the form for it
/// (rustfs/gateway#1167), so legacy RustFS's `s3:PutObjectRetention` / `s3:PutObjectLegalHold`
/// question for a form naming a lock is asked here too.
#[test]
fn post_object_requires_the_same_actions_by_form_field() {
    assert_eq!(shape(extras::<dto::PostObject>()), OBJECT_WRITE);
}

/// A delete and a retention change require `s3:BypassGovernanceRetention` by the bypass header, and
/// nothing waives it.
#[test]
fn a_delete_and_a_retention_change_require_the_bypass_action() {
    let bypass = [("s3:BypassGovernanceRetention", ExtraProfile::Generic)];
    assert_eq!(shape(extras::<dto::DeleteObject>()), bypass);
    assert_eq!(shape(extras::<dto::PutObjectRetention>()), bypass);
}

/// Negative — an ordinary read or bucket operation declares no extra permission, so no header can
/// make it require a second action.
#[test]
fn n_a_read_or_bucket_operation_declares_no_extra_permission() {
    assert!(extras::<dto::GetObject>().is_empty());
    assert!(extras::<dto::HeadObject>().is_empty());
    assert!(extras::<dto::PutObjectTagging>().is_empty());
    assert!(extras::<dto::PutObjectAcl>().is_empty());
    assert!(extras::<dto::PutBucketPolicy>().is_empty());
    assert!(extras::<dto::UploadPart>().is_empty());
}

/// Negative — a `PutObject` that carries none of the trigger headers applies none of its extra
/// permissions, so it requires only its base action.
#[test]
fn n_a_header_less_write_applies_no_extra_permission() {
    let none = |_: &str| Option::<&str>::None;
    for extra in extras::<dto::PutObject>() {
        assert!(!extra.applies(none), "{}", extra.action());
    }
    // And each applies once its own header is present.
    for extra in extras::<dto::PutObject>() {
        let header = extra.triggers()[0].header();
        let present = |name: &str| (name == header).then_some("v");
        assert!(extra.applies(present), "{} did not fire on {header}", extra.action());
    }
}
