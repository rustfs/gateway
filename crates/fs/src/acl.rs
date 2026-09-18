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

//! The four ACL operations, with the answers RustFS gives them.
//!
//! Responsible for: `GetBucketAcl`, `GetObjectAcl`, `PutBucketAcl` and `PutObjectAcl` on the
//! reference backend — the owner's `FULL_CONTROL` read back for every bucket and object that
//! exists, a canned or grant-header write accepted after the shared contract validated it, and an
//! `AccessControlPolicy` document refused as not implemented.
//! NOT responsible for: storing or enforcing grants. This backend does not, and neither does the
//! RustFS it stands in for.
//! Upstream: `rustfs_gateway::resolve_input` (the two-channel ACL contract), `versioning` for the
//! object selection. Downstream: the production ACL routes.
//!
//! # Why the ACL is a fixed answer and not a stored document
//!
//! RustFS answers `GetBucketAcl`/`GetObjectAcl` with one `FULL_CONTROL` grant to the owner, accepts
//! a canned-ACL or grant-header write without storing it, and refuses an XML grant document with
//! `501 NotImplemented`; access is decided by policy, never by an ACL (rustfs/gateway#812,
//! `rustfs/src/storage/s3_api/acl.rs` and `ecfs.rs` upstream). A reference backend that stored
//! and enforced grants would pass suites RustFS fails and hide the difference this launcher
//! exists to measure. What is implemented here is therefore the RustFS surface exactly: the four
//! routes stop answering `501` for the setup steps of every suite that touches them, the
//! contract's refusals (both channels at once, neither, a canned value outside the target's set,
//! a malformed grant header) are answered before RustFS would see the request, and an ACL that
//! would have to be stored to mean anything is refused with RustFS's own message.

use rustfs_gateway::dto::{
    AccessControlPolicy, GetBucketAcl, GetBucketAclOutput, GetObjectAcl, GetObjectAclOutput, Grant, Grantee, Permission,
    PutBucketAcl, PutBucketAclOutput, PutObjectAcl, PutObjectAclOutput,
};
use rustfs_gateway::{
    AclHeaders, AclInput, AclRejection, AclTarget, GranteeType, Handler, HandlerError, HandlerResult, Req, Resp, resolve_input,
};

use super::FsBackend;

/// RustFS's answer to a grant document: it has nowhere to keep one.
const DOCUMENT_NOT_SUPPORTED: &str = "ACL XML grants are not supported; use canned ACL headers or omit ACL";

impl FsBackend {
    /// The one policy every bucket and object here has: the configured owner holds `FULL_CONTROL`.
    ///
    /// An unconfigured owner is an owner with no id, as `ListBuckets` already reports it, so the
    /// document is always well-formed and a client parsing it finds the grantee it expects.
    fn owner_policy(&self) -> AccessControlPolicy {
        let owner = self.reported_owner().cloned().unwrap_or_default();
        AccessControlPolicy {
            grants: vec![Grant {
                grantee: Some(Grantee {
                    id: owner.id.clone(),
                    display_name: owner.display_name.clone(),
                    r#type: Some(GranteeType::CanonicalUser.as_dto()),
                    ..Grantee::default()
                }),
                permission: Some(Permission::FULL_CONTROL),
            }],
            owner: Some(owner),
        }
    }
}

/// Validates one ACL write through the shared contract and answers it as RustFS does.
///
/// The contract decides the channel: both used at once, neither used, a canned value outside the
/// target's set and a grant header outside the grammar are its refusals and not a second copy of
/// them here. A header-channel write is then accepted and not stored; a document is refused.
fn accept_headers_only(
    headers: AclHeaders<'_>,
    document: Option<AccessControlPolicy>,
    target: AclTarget,
) -> Result<(), HandlerError> {
    match resolve_input(headers, document, target).map_err(refused)? {
        AclInput::Headers { .. } => Ok(()),
        AclInput::Document(_) => Err(HandlerError::not_implemented(DOCUMENT_NOT_SUPPORTED)),
    }
}

fn refused(rejection: AclRejection) -> HandlerError {
    HandlerError::new(rejection.code(), rejection.reason().to_owned())
}

impl Handler<GetBucketAcl> for FsBackend {
    async fn call(&self, request: Req<GetBucketAcl>) -> HandlerResult<GetBucketAcl> {
        self.require_bucket(request.input().bucket.as_str()).await?;
        let policy = self.owner_policy();
        Ok(Resp::new(GetBucketAclOutput {
            owner: policy.owner,
            grants: policy.grants,
        }))
    }
}

impl Handler<PutBucketAcl> for FsBackend {
    async fn call(&self, request: Req<PutBucketAcl>) -> HandlerResult<PutBucketAcl> {
        let input = request.input();
        self.require_bucket(input.bucket.as_str()).await?;
        accept_headers_only(
            AclHeaders {
                canned: input.acl.as_ref().map(|acl| acl.as_str()),
                full_control: input.grant_full_control.as_deref(),
                read: input.grant_read.as_deref(),
                write: input.grant_write.as_deref(),
                read_acp: input.grant_read_acp.as_deref(),
                write_acp: input.grant_write_acp.as_deref(),
            },
            input.access_control_policy.clone(),
            AclTarget::Bucket,
        )?;
        Ok(Resp::new(PutBucketAclOutput::default()))
    }
}

impl Handler<GetObjectAcl> for FsBackend {
    /// The object's policy, for the version named or the current one; `NoSuchKey`,
    /// `NoSuchVersion` and the delete-marker `405` are the tagging read's, shared through
    /// `object_tag_target`, so the four subresource reads agree on which object is not there.
    async fn call(&self, request: Req<GetObjectAcl>) -> HandlerResult<GetObjectAcl> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let _target = self
            .object_tag_target(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let policy = self.owner_policy();
        Ok(Resp::new(GetObjectAclOutput {
            owner: policy.owner,
            grants: policy.grants,
            ..GetObjectAclOutput::default()
        }))
    }
}

impl Handler<PutObjectAcl> for FsBackend {
    async fn call(&self, request: Req<PutObjectAcl>) -> HandlerResult<PutObjectAcl> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let _target = self
            .object_tag_target(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        accept_headers_only(
            AclHeaders {
                canned: input.acl.as_ref().map(|acl| acl.as_str()),
                full_control: input.grant_full_control.as_deref(),
                read: input.grant_read.as_deref(),
                write: input.grant_write.as_deref(),
                read_acp: input.grant_read_acp.as_deref(),
                write_acp: input.grant_write_acp.as_deref(),
            },
            input.access_control_policy.clone(),
            AclTarget::Object,
        )?;
        Ok(Resp::new(PutObjectAclOutput::default()))
    }
}
