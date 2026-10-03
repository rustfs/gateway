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

//! Which operations ask a version action for a request that names one object version.
//!
//! Responsible for: every operation that binds the `versionId` query parameter, and the
//! requirement each asks for a request that names a version — the version action AWS documents
//! for the reads, deletes, tag and ACL operations, and the operation's own action for the rest.
//! NOT responsible for: asking the question (the facade's route stage, pinned in the gateway's
//! runtime suite) or the registration rules of a version requirement (the registry's unit suite).
//! Upstream: the op specs. Downstream: nothing.
//!
//! Evidence: AWS's permission table for S3 API operations
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>) names
//! the version action required, instead of the unversioned one, when `versionId` is specified for
//! GetObject, DeleteObject, the three object-tagging operations and the two object-ACL operations;
//! HeadObject needs "the relevant read object (or version) permission"
//! (<https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html>).

use rustfs_gateway_core::ResourceShape;
use rustfs_gateway_core::op::{AuthRequirement, Operation};
use rustfs_gateway_types::dto;

fn requirement<O: Operation>() -> AuthRequirement {
    O::spec().auth.unwrap_or_else(|| panic!("{} declares an action", O::NAME))
}

/// The operations whose request naming a version is asked the version action, with both actions.
fn versioned() -> [(&'static str, AuthRequirement, &'static str, &'static str); 8] {
    [
        ("GetObject", requirement::<dto::GetObject>(), "s3:GetObject", "s3:GetObjectVersion"),
        ("HeadObject", requirement::<dto::HeadObject>(), "s3:GetObject", "s3:GetObjectVersion"),
        (
            "GetObjectAttributes",
            requirement::<dto::GetObjectAttributes>(),
            "s3:GetObject",
            "s3:GetObjectVersion",
        ),
        (
            "DeleteObject",
            requirement::<dto::DeleteObject>(),
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
        ),
        (
            "GetObjectTagging",
            requirement::<dto::GetObjectTagging>(),
            "s3:GetObjectTagging",
            "s3:GetObjectVersionTagging",
        ),
        (
            "PutObjectTagging",
            requirement::<dto::PutObjectTagging>(),
            "s3:PutObjectTagging",
            "s3:PutObjectVersionTagging",
        ),
        (
            "DeleteObjectTagging",
            requirement::<dto::DeleteObjectTagging>(),
            "s3:DeleteObjectTagging",
            "s3:DeleteObjectVersionTagging",
        ),
        (
            "GetObjectAcl",
            requirement::<dto::GetObjectAcl>(),
            "s3:GetObjectAcl",
            "s3:GetObjectVersionAcl",
        ),
    ]
}

/// A request naming a version is asked the version action, about the same object, and only it.
#[test]
fn a_version_read_delete_tag_or_acl_request_is_asked_the_version_action() {
    for (name, requirement, action, version_action) in versioned() {
        assert_eq!(requirement.for_version(false).action, action, "{name}");
        let versioned = requirement.for_version(true);
        assert_eq!(versioned.action, version_action, "{name}");
        assert_eq!(versioned.actions(), [version_action], "{name}: the version action alone");
        assert_eq!(versioned.resource, ResourceShape::Object, "{name}");
    }
    let put_acl = requirement::<dto::PutObjectAcl>();
    assert_eq!(put_acl.for_version(false).action, "s3:PutObjectAcl");
    assert_eq!(put_acl.for_version(true).action, "s3:PutObjectVersionAcl");
}

/// Negative — a request naming no version keeps the unversioned action: a principal allowed only
/// versions is not thereby allowed the current object.
#[test]
fn n_a_request_naming_no_version_is_never_asked_the_version_action() {
    for (name, requirement, action, _) in versioned() {
        assert_eq!(requirement.action, action, "{name}");
        assert_eq!(requirement.for_version(false).actions(), [action], "{name}");
    }
}

/// Negative — the operations AWS authorises with the same action whether or not a version is named
/// declare no version requirement, so naming one changes nothing they are asked.
#[test]
fn n_retention_legal_hold_restore_and_encryption_updates_keep_their_action_for_a_version() {
    for (name, requirement) in [
        ("GetObjectRetention", requirement::<dto::GetObjectRetention>()),
        ("PutObjectRetention", requirement::<dto::PutObjectRetention>()),
        ("GetObjectLegalHold", requirement::<dto::GetObjectLegalHold>()),
        ("PutObjectLegalHold", requirement::<dto::PutObjectLegalHold>()),
        ("RestoreObject", requirement::<dto::RestoreObject>()),
        ("UpdateObjectEncryption", requirement::<dto::UpdateObjectEncryption>()),
    ] {
        assert_eq!(requirement.version_requirement(), None, "{name}");
        assert_eq!(requirement.for_version(true), requirement, "{name}");
    }
}
