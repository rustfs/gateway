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

//! The launcher's authorizer: ownership first, then the bucket policy, as RustFS decides.
//!
//! Responsible for: the [`Authorizer`] the assembly installs — [`decide`]
//! for the operation set, the identity and the ownership registry, and then, for a request that
//! decision alone does not allow, the bucket's stored policy evaluated the way RustFS's
//! `PolicySys::is_allowed` evaluates it. Accepted ACL header facts reach both stages; missing
//! request facts or malformed ACL header values make a stored-policy decision indeterminate.
//! NOT responsible for: parsing or matching statements (`rustfs_gateway_fs::policy::evaluate`),
//! storing the policy (the fs backend), or the ownership rules themselves (`ownership`).
//! Upstream: `crate::ownership`, `rustfs_gateway_fs::FsBackend::bucket_policy`. Downstream:
//! `crate::service`, which installs this in place of the bare ownership decision.
//!
//! # The order, and why the policy is consulted only after ownership says no
//!
//! RustFS asks the bucket policy for every request and lets the owner through unless a `Deny`
//! names them. Here ownership is decided first because that is what this launcher already proved
//! (one owner per data root, guests refused), and the policy is the second word: an anonymous
//! request or another identity's request that ownership refuses is allowed when the stored policy
//! allows it, and the owner's request is refused when a `Deny` names it. A bucket with no policy
//! is exactly the ownership decision — RustFS's `ConfigNotFound => is_owner` — and a policy that
//! cannot be read fails closed, because an unreadable policy is not an absent one.
//!
//! The account a principal is matched against is the identity's configured owner id, the same
//! string `x-amz-expected-bucket-owner` and the ACL owner report. A suite that writes
//! `{"AWS": ["<alt owner id>"]}` therefore addresses the second identity by the id the launcher
//! published for it.

use std::sync::Arc;

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Decision, InputAuthzRequest, InputDecisions, RequestContext, ResourceShape,
};
use rustfs_gateway_fs::FsBackend;
use rustfs_gateway_fs::policy::evaluate::{BucketPolicy, PolicyRequest, RequestFacts};

use crate::identity::Accounts;
use crate::ownership::{BucketOwners, decide};

/// Ownership, then the bucket policy.
pub(crate) struct PolicyAuthorizer {
    backend: Arc<FsBackend>,
    owners: Arc<BucketOwners>,
    accounts: Accounts,
    supported: Vec<&'static str>,
}

/// The policy of one bucket as the authorizer saw it: absent, readable, or unreadable.
enum Stored {
    None,
    Policy(BucketPolicy),
    Unreadable,
}

impl PolicyAuthorizer {
    pub(crate) fn new(
        backend: Arc<FsBackend>,
        owners: Arc<BucketOwners>,
        accounts: Accounts,
        supported: Vec<&'static str>,
    ) -> Self {
        Self {
            backend,
            owners,
            accounts,
            supported,
        }
    }

    async fn stored(&self, bucket: &str) -> Stored {
        match self.backend.bucket_policy(bucket).await {
            Ok(None) => Stored::None,
            Ok(Some(document)) => BucketPolicy::parse(&document).map_or(Stored::Unreadable, Stored::Policy),
            // A bucket that does not exist has no policy; the handler answers NoSuchBucket.
            Err(error) if error.code() == &rustfs_gateway::ErrorCode::NO_SUCH_BUCKET => Stored::None,
            Err(_) => Stored::Unreadable,
        }
    }

    /// One stage's verdict: ownership, then the policy when there is one.
    ///
    /// With a policy stored, the policy's answer *is* the verdict, in RustFS's order: a matching
    /// `Deny` refuses anyone, the owner is otherwise allowed, and everyone else needs a matching
    /// `Allow`. Without one, ownership alone decides.
    fn verdict(&self, request: &AuthzRequest<'_>, stored: &Stored, context: &RequestContext<'_>) -> Decision {
        let ownership = decide(&self.owners, &self.accounts, &self.supported, request);
        if !self.supported.contains(&request.operation) {
            return Decision::Deny;
        }
        let Some(bucket) = request.bucket else {
            return ownership;
        };
        let policy = match stored {
            Stored::None => return ownership,
            Stored::Unreadable => return Decision::Indeterminate,
            Stored::Policy(policy) => policy,
        };
        // Missing request facts are not proof that a conditional Deny does not match.
        // Without a stored policy, the existing ownership decision above remains sufficient.
        let Some(headers) = context.headers() else {
            return Decision::Indeterminate;
        };
        let mut facts = RequestFacts::default();
        for (name, slot) in [
            ("x-amz-acl", &mut facts.acl),
            ("x-amz-server-side-encryption", &mut facts.server_side_encryption),
        ] {
            let name = http::HeaderName::from_static(name);
            *slot = match acl_value(headers.count(&name), headers.get_bytes(&name)) {
                Ok(value) => value,
                Err(decision) => return decision,
            };
        }
        let account = request
            .identity
            .and_then(|identity| self.accounts.owner_of(identity.access_key_id()));
        let is_owner = account.is_some_and(|caller| {
            self.owners
                .owner_of(bucket.as_str())
                .is_none_or(|owner| owner.as_ref() == caller)
        });
        let key = match request.resource {
            ResourceShape::Bucket => None,
            _ => request.key.map(|key| key.as_str()),
        };
        let allowed = policy.allows_with_facts(
            PolicyRequest {
                account,
                is_owner,
                action: request.action,
                bucket: bucket.as_str(),
                key,
            },
            facts,
        );
        if allowed { Decision::Allow } else { Decision::Deny }
    }
}

impl Authorizer for PolicyAuthorizer {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        Box::pin(async move {
            let stored = match request.bucket {
                Some(bucket) => self.stored(bucket.as_str()).await,
                None => Stored::None,
            };
            self.verdict(request, &stored, context)
        })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        Box::pin(async move {
            // Every bucket the stage names, read once each: the route's, each derived resource's
            // (a copy source may live in another bucket) and the visibility check's.
            let mut policies: Vec<(String, Stored)> = Vec::new();
            for named in std::iter::once(request.route())
                .chain(request.resources())
                .chain(request.visibility())
            {
                if let Some(bucket) = named.bucket
                    && !policies.iter().any(|(name, _)| name == bucket.as_str())
                {
                    let stored = self.stored(bucket.as_str()).await;
                    policies.push((bucket.as_str().to_owned(), stored));
                }
            }
            let lookup = |named: &AuthzRequest<'_>| -> Decision {
                let stored = named
                    .bucket
                    .and_then(|bucket| policies.iter().find(|(name, _)| name == bucket.as_str()))
                    .map_or(&Stored::None, |(_, stored)| stored);
                self.verdict(named, stored, context)
            };
            let stage = lookup(request.route());
            request.decide_all(stage, lookup)
        })
    }
}

fn acl_value(count: usize, bytes: Option<&[u8]>) -> Result<Option<&str>, Decision> {
    if count > 1 {
        return Err(Decision::Indeterminate);
    }
    bytes
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| Decision::Indeterminate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_condition_header_failures_are_not_absence() {
        assert_eq!(acl_value(2, Some(b"private")), Err(Decision::Indeterminate));
        assert_eq!(acl_value(3, Some(b"public-read")), Err(Decision::Indeterminate));
        assert_eq!(acl_value(1, Some(&[0xff])), Err(Decision::Indeterminate));
        assert_eq!(acl_value(0, None), Ok(None));
        assert_eq!(acl_value(1, Some(b"private")), Ok(Some("private")));
    }
}
