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

//! Which identity owns which bucket, and what the other identity may therefore not do.
//!
//! Responsible for: recording the fixed data-root owner of a bucket when creation is admitted,
//! answering `x-amz-expected-bucket-owner` through [`BucketOwnerSource`], and producing the
//! authorization [`Decision`] that refuses one identity on another identity's bucket.
//! NOT responsible for: storing objects (`rustfs-gateway-fs`), verifying signatures
//! (`rustfs-gateway-sig`), or ACLs and bucket policies — this launcher implements neither, and an
//! ACL grant therefore cannot widen anything decided here.
//! Upstream: `crate::identity`, which says who the principals are. Downstream: `crate::service`,
//! which installs this as both the authorizer and the bucket-owner source.
//!
//! # Why the registry lives in memory
//!
//! The reference backend enumerates its data root and requires every entry to be a `b-`-prefixed
//! bucket directory (`crates/fs/src/lifecycle.rs`), so an owner sidecar cannot be written beside
//! the buckets without breaking every lifecycle sweep. The registry is therefore process-scoped:
//! a launcher restarted against a **populated** data root has forgotten who owned what, and the
//! first identity to name such a bucket is allowed. Every suite this launcher exists for starts it
//! against a fresh, single-tenant data root whose configured primary owner is authoritative; a
//! secondary identity may request creation as a guest, but does not acquire the bucket. Nothing
//! here should be read as a durable authorization store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustfs_gateway::{AuthzRequest, BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, Decision, Operation, dto};

use crate::identity::Accounts;

/// The bucket-to-owner map this launcher enforces.
#[derive(Debug, Default)]
pub(crate) struct BucketOwners {
    owners: Mutex<HashMap<String, Arc<str>>>,
}

impl BucketOwners {
    /// Records `owner` as the owner of `bucket` unless the data root already recorded it.
    ///
    /// Returns the owner that stands afterwards, which is the *existing* one when there was one.
    /// A second identity therefore cannot take a bucket over by asking to create it again: that
    /// request is admitted, the reference backend answers `BucketAlreadyExists`, and the first
    /// identity is still the owner.
    fn claim(&self, bucket: &str, owner: &str) -> Option<Arc<str>> {
        let mut owners = self.owners.lock().ok()?;
        Some(Arc::clone(owners.entry(bucket.to_owned()).or_insert_with(|| Arc::from(owner))))
    }

    /// The recorded owner of `bucket`, when this process recorded one.
    fn owner_of(&self, bucket: &str) -> Option<Arc<str>> {
        self.owners.lock().ok()?.get(bucket).map(Arc::clone)
    }

    /// How many buckets this process has recorded an owner for.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.owners.lock().map_or(0, |owners| owners.len())
    }
}

impl BucketOwnerSource for BucketOwners {
    /// A bucket nobody claimed has no trustworthy owner, and an unanswerable lookup fails closed
    /// as `403` rather than matching whatever the caller asserted.
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        let found = self.owner_of(bucket.as_str());
        Box::pin(async move { found.ok_or_else(BucketOwnerError::unavailable) })
    }
}

/// The operation that mints a bucket, and therefore the only one that may claim one.
///
/// Taken from the operation itself rather than written out as a literal: `AuthzRequest::operation`
/// carries `Operation::NAME`, and a second spelling of that string here would compare unequal
/// forever without anything saying so.
const CREATE_BUCKET: &str = <dto::CreateBucket as Operation>::NAME;

/// Decides one already-authenticated request against the registered operation set and the
/// bucket-owner registry.
///
/// The order matters and each step is a refusal in its own right:
///
/// 1. an operation this assembly never registered is refused, so that "we do not have it" stays
///    distinguishable from "we have it and answered wrongly";
/// 2. an anonymous request is refused — this launcher publishes nothing publicly;
/// 3. an access key that resolves to no registered account is refused, rather than allowed on the
///    grounds that the authenticator ought to have caught it;
/// 4. a request naming no bucket is a service-level request and is allowed;
/// 5. `CreateBucket` claims the name for the fixed data-root owner and is allowed;
/// 6. everything else must be the recorded owner, or is refused.
pub(crate) fn decide(
    owners: &BucketOwners,
    accounts: &Accounts,
    supported: &[&'static str],
    request: &AuthzRequest<'_>,
) -> Decision {
    if !supported.contains(&request.operation) {
        return Decision::Deny;
    }
    let Some(identity) = request.identity else {
        return Decision::Deny;
    };
    let Some(caller) = accounts.owner_of(identity.access_key_id()) else {
        return Decision::Deny;
    };
    let Some(bucket) = request.bucket else {
        return Decision::Allow;
    };
    if request.operation == CREATE_BUCKET {
        let (data_root_owner, _) = accounts.data_root_owner();
        return match owners.claim(bucket.as_str(), data_root_owner) {
            // A poisoned registry is not an allowance: it is a lookup that could not be made.
            None => Decision::Indeterminate,
            Some(_) => Decision::Allow,
        };
    }
    match owners.owner_of(bucket.as_str()) {
        None => Decision::Allow,
        Some(owner) if owner.as_ref() == caller => Decision::Allow,
        Some(_) => Decision::Deny,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{BucketOwners, decide};
    use crate::identity::{AccountArgs, Accounts};
    use rustfs_gateway::{AuthzRequest, BucketName, Decision, Identity, ResourceShape, TargetOrigin};

    const SUPPORTED: &[&str] = &["CreateBucket", "GetObject", "ListObjects"];

    fn accounts() -> Accounts {
        let primary = AccountArgs {
            access_key: Some("MAIN".to_owned()),
            secret_key: Some("main-secret".to_owned()),
            owner_id: Some("s3gate-main".to_owned()),
            display_name: Some("s3gate-main".to_owned()),
        };
        let secondary = AccountArgs {
            access_key: Some("ALT".to_owned()),
            secret_key: Some("alt-secret".to_owned()),
            owner_id: Some("s3gate-alt".to_owned()),
            display_name: Some("s3gate-alt".to_owned()),
        };
        Accounts::build(primary, secondary).expect("two distinct identities")
    }

    fn request<'a>(operation: &'a str, bucket: Option<&'a BucketName>, identity: Option<&'a Identity>) -> AuthzRequest<'a> {
        AuthzRequest {
            operation,
            action: "s3:GetObject",
            resource: ResourceShape::Bucket,
            bucket,
            key: None,
            copy_source_identity: None,
            version_id: None,
            route_action: "s3:GetObject",
            route_bucket: bucket,
            route_key: None,
            identity,
            target_origin: TargetOrigin::Path,
            subject: None,
        }
    }

    /// Positive — the creator of a bucket keeps reaching it afterwards.
    #[test]
    fn the_creator_of_a_bucket_may_use_it() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let bucket = BucketName::new("owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(owners.len(), 1);
    }

    /// Negative — the second identity is refused on the first identity's bucket.
    #[test]
    fn n_a_second_identity_is_refused_on_the_first_identitys_bucket() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let alt = Identity::new("ALT").expect("a valid access key id");
        let bucket = BucketName::new("owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&alt))),
            Decision::Deny
        );
    }

    /// Negative — creation by the secondary guest does not transfer ownership away from the
    /// single-tenant data root: the guest is refused afterwards and the primary owner is allowed.
    #[test]
    fn n_the_secondary_creator_is_refused_on_the_data_root_owners_bucket() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let alt = Identity::new("ALT").expect("a valid access key id");
        let bucket = BucketName::new("alt-owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&alt))),
            Decision::Allow
        );
        assert_eq!(owners.owner_of(bucket.as_str()).as_deref(), Some("s3gate-main"));
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&alt))),
            Decision::Deny
        );
    }

    /// Negative — asking to create a bucket somebody else owns does not transfer it.
    #[test]
    fn n_a_second_create_does_not_take_the_bucket_over() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let alt = Identity::new("ALT").expect("a valid access key id");
        let bucket = BucketName::new("contested").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&alt))),
            Decision::Allow
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&alt))),
            Decision::Deny
        );
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&main))),
            Decision::Allow
        );
    }

    /// Negative — an anonymous request is refused even for an operation this assembly registers.
    #[test]
    fn n_an_anonymous_request_is_refused() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let bucket = BucketName::new("owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), None)),
            Decision::Deny
        );
    }

    /// Negative — an operation outside the registered set is refused before ownership is consulted.
    #[test]
    fn n_an_unregistered_operation_is_refused() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let bucket = BucketName::new("owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("PutBucketAcl", Some(&bucket), Some(&main))),
            Decision::Deny
        );
        assert_eq!(owners.len(), 0);
    }

    /// Negative — a verified key this launcher never registered is refused rather than trusted.
    #[test]
    fn n_an_unregistered_access_key_is_refused() {
        let owners = BucketOwners::default();
        let accounts = accounts();
        let stranger = Identity::new("STRANGER").expect("a valid access key id");
        let bucket = BucketName::new("owned").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("GetObject", Some(&bucket), Some(&stranger))),
            Decision::Deny
        );
    }

    /// Negative — an unclaimed bucket has no owner to assert against, so the source fails closed.
    #[tokio::test]
    async fn n_an_unclaimed_bucket_has_no_assertable_owner() {
        use rustfs_gateway::BucketOwnerSource as _;

        let owners = BucketOwners::default();
        let accounts = accounts();
        let main = Identity::new("MAIN").expect("a valid access key id");
        let bucket = BucketName::new("claimed").expect("a valid bucket name");
        let absent = BucketName::new("unclaimed").expect("a valid bucket name");
        assert_eq!(
            decide(&owners, &accounts, SUPPORTED, &request("CreateBucket", Some(&bucket), Some(&main))),
            Decision::Allow
        );
        assert_eq!(owners.owner(&bucket).await.expect("a recorded owner").as_ref(), "s3gate-main");
        assert!(owners.owner(&absent).await.is_err());
    }
}
