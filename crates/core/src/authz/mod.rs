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

//! The consuming transition between decoded input and dispatchable input.
//!
//! Responsible for: `Decoded<O>`, [`Authorized`], [`Decision`], [`Denied`], derived-resource
//! declarations, and the crate-private consuming transition that constructs an authorized request.
//! NOT responsible for: evaluating a policy language, choosing the primary route resource, or
//! invoking a handler. Those belong to the deployment, routing, and registry respectively.
//! Upstream: [`crate::Operation`]. Downstream: `crate::registry` and the facade pipeline.

use rustfs_gateway_types::{BucketName, ErrorCode, ObjectKey};

use crate::Operation;

/// One policy decision.
///
/// `Indeterminate` is distinct for audit purposes and is a refusal for continuation purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use = "dropping an authorization decision means it was never enforced"]
pub enum Decision {
    /// The policy permits the action on the resource.
    Allow,
    /// The policy has an answer and it is no.
    Deny,
    /// The policy could not obtain an answer. The framework fails closed.
    Indeterminate,
}

impl Decision {
    /// Converts the three-state verdict into the framework's two continuations.
    ///
    /// `Indeterminate` is deliberately the same refusal as `Deny`: a policy backend failure is
    /// never permission and never a retryable `5xx`.
    pub const fn settle(self) -> Result<(), Denied> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny | Self::Indeterminate => Err(Denied { decision: self }),
        }
    }
}

/// A refusal to create [`Authorized`].
///
/// The decision is retained for operator-side audit. Both refusing values render as the same
/// `AccessDenied` response in the facade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Denied {
    decision: Decision,
}

impl Denied {
    /// The policy outcome that prevented authorization.
    pub const fn decision(self) -> Decision {
        self.decision
    }

    /// A fail-closed refusal for an internal authorization-boundary mismatch.
    #[must_use]
    pub const fn indeterminate() -> Self {
        Self {
            decision: Decision::Indeterminate,
        }
    }
}

/// An owned derived resource that can cross the operation-erasure boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedResource {
    action: &'static str,
    bucket: Option<BucketName>,
    key: Option<ObjectKey>,
    identity: Option<ResourceIdentity>,
    version_id: Option<String>,
}

impl OwnedResource {
    /// Copies one borrowed resource without changing its normalized values.
    #[must_use]
    pub fn from_ref(resource: ResourceRef<'_>) -> Self {
        Self {
            action: resource.action(),
            bucket: resource.bucket().cloned(),
            key: resource.key().cloned(),
            identity: resource.identity().cloned(),
            version_id: resource.version_id().map(ToOwned::to_owned),
        }
    }

    /// The IAM action required on this resource.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }

    /// The bucket, when the resource names one explicitly.
    #[must_use]
    pub const fn bucket(&self) -> Option<&BucketName> {
        self.bucket.as_ref()
    }

    /// The object key, when this is an object resource.
    #[must_use]
    pub const fn key(&self) -> Option<&ObjectKey> {
        self.key.as_ref()
    }

    /// The addressing identity carried by a derived resource, when it is significant.
    #[must_use]
    pub const fn identity(&self) -> Option<&ResourceIdentity> {
        self.identity.as_ref()
    }

    /// The exact object version this resource names, when any.
    #[must_use]
    pub fn version_id(&self) -> Option<&str> {
        self.version_id.as_deref()
    }

    fn matches(&self, resource: ResourceRef<'_>) -> bool {
        self.action == resource.action()
            && self.bucket.as_ref() == resource.bucket()
            && self.key.as_ref() == resource.key()
            && self.identity.as_ref() == resource.identity()
            && self.version_id() == resource.version_id()
    }
}

/// The addressing identity of a resource whose bucket/key pair is not sufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceIdentity {
    /// A regular bucket-and-key path.
    Path,
    /// An S3 access point, named independently of the bucket behind it.
    AccessPoint {
        /// ARN partition.
        partition: String,
        /// ARN region.
        region: String,
        /// ARN account.
        account: String,
        /// Access point name.
        name: String,
    },
    /// An Outposts resource, scoped by its outpost identifier.
    Outposts {
        /// ARN partition.
        partition: String,
        /// ARN region.
        region: String,
        /// ARN account.
        account: String,
        /// Outpost identifier.
        outpost_id: String,
    },
}

/// A failure while deriving the resources that must be authorized.
///
/// Derivation is fallible because some resources, notably `x-amz-copy-source`, are parsed and
/// normalized exactly once at this boundary. A malformed resource must not become an empty set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedResourceError {
    code: ErrorCode,
    message: &'static str,
}

impl DerivedResourceError {
    /// Builds a non-secret rejection for malformed derived-resource input.
    #[must_use]
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The static, non-echoing explanation.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// A resource derived after routing, usually from a decoded header or request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceRef<'a> {
    /// A service-level resource.
    Service {
        /// The IAM action required on this resource.
        action: &'static str,
    },
    /// A bucket-level resource.
    Bucket {
        /// The IAM action required on this resource.
        action: &'static str,
        /// The bucket.
        bucket: &'a BucketName,
    },
    /// An object resource. The bucket is absent only when the operation's primary routed bucket
    /// supplies it and the derived value contributes only the key.
    Object {
        /// The IAM action required on this resource.
        action: &'static str,
        /// The bucket when the derived value names one explicitly.
        bucket: Option<&'a BucketName>,
        /// The object key.
        key: &'a ObjectKey,
        /// Addressing identity when bucket/key alone would alias another resource.
        identity: Option<&'a ResourceIdentity>,
        /// Exact object version, when the resource names one.
        version_id: Option<&'a str>,
    },
}

impl<'a> ResourceRef<'a> {
    /// An object resource.
    #[must_use]
    pub const fn object(action: &'static str, bucket: Option<&'a BucketName>, key: &'a ObjectKey) -> Self {
        Self::Object {
            action,
            bucket,
            key,
            identity: None,
            version_id: None,
        }
    }

    /// A copy-source object whose addressing identity must survive authorization.
    #[must_use]
    pub const fn copy_source(
        action: &'static str,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
        identity: &'a ResourceIdentity,
        version_id: Option<&'a str>,
    ) -> Self {
        Self::Object {
            action,
            bucket: Some(bucket),
            key,
            identity: Some(identity),
            version_id,
        }
    }

    /// A derived object version.
    #[must_use]
    pub const fn object_version(
        action: &'static str,
        bucket: Option<&'a BucketName>,
        key: &'a ObjectKey,
        version_id: &'a str,
    ) -> Self {
        Self::Object {
            action,
            bucket,
            key,
            identity: None,
            version_id: Some(version_id),
        }
    }

    /// The IAM action required on this resource.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Service { action } | Self::Bucket { action, .. } | Self::Object { action, .. } => action,
        }
    }

    /// The bucket carried by this resource, when any.
    #[must_use]
    pub const fn bucket(self) -> Option<&'a BucketName> {
        match self {
            Self::Bucket { bucket, .. }
            | Self::Object {
                bucket: Some(bucket), ..
            } => Some(bucket),
            Self::Service { .. } | Self::Object { bucket: None, .. } => None,
        }
    }

    /// The object key carried by this resource, when any.
    #[must_use]
    pub const fn key(self) -> Option<&'a ObjectKey> {
        match self {
            Self::Object { key, .. } => Some(key),
            Self::Service { .. } | Self::Bucket { .. } => None,
        }
    }

    /// The addressing identity carried by this resource, when any.
    #[must_use]
    pub const fn identity(self) -> Option<&'a ResourceIdentity> {
        match self {
            Self::Object { identity, .. } => identity,
            Self::Service { .. } | Self::Bucket { .. } => None,
        }
    }

    /// The exact object version carried by this resource, when any.
    #[must_use]
    pub const fn version_id(self) -> Option<&'a str> {
        match self {
            Self::Object { version_id, .. } => version_id,
            Self::Service { .. } | Self::Bucket { .. } => None,
        }
    }
}

/// The resources an operation derives from its decoded input.
///
/// The callback form keeps this trait object-safe and allocation-free. A deployment may collect
/// the values for audit, but the framework does not allocate merely to prove it visited them.
pub trait DerivedResourceSet: Send + Sync + 'static {
    /// Visits every derived resource exactly once.
    fn visit(&self, visitor: &mut dyn FnMut(ResourceRef<'_>));

    /// The number of resources in the set.
    #[must_use]
    fn len(&self) -> usize {
        let mut count = 0_usize;
        self.visit(&mut |_| count = count.saturating_add(1));
        count
    }

    /// Whether the set contains no resource.
    #[must_use]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An explicit declaration that an operation derives no second-stage resources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoDerived;

impl DerivedResourceSet for NoDerived {
    fn visit(&self, _visitor: &mut dyn FnMut(ResourceRef<'_>)) {}
}

/// A decoded request that has not passed input authorization.
pub(crate) struct Decoded<O: Operation> {
    input: O::Input,
    resources: O::DerivedResources,
}

impl<O: Operation> Decoded<O> {
    /// The resources parsed from this exact input.
    #[must_use]
    pub(crate) const fn resources(&self) -> &O::DerivedResources {
        &self.resources
    }
}

/// Parses and freezes every derived resource before input authorization.
///
/// This is intentionally a free function rather than `Decoded::new`: `Decoded` is a pipeline
/// state, not a general-purpose wrapper, and callers cannot bypass resource derivation.
pub(crate) fn prepare_input<O: Operation>(mut input: O::Input) -> Result<Decoded<O>, DerivedResourceError> {
    let resources = O::derive_resources(&input)?;
    O::seal_derived_input(&mut input);
    Ok(Decoded { input, resources })
}

/// A proof that every resource derived from one decoded request was allowed.
///
/// All fields are private and there is no `new`, `Default`, `From<Decoded<_>>`, or public function
/// returning `Self`. The crate-private authorization transition is the only constructor.
pub struct Authorized<O: Operation> {
    input: O::Input,
    resources: O::DerivedResources,
    read: AuthorizedRead,
}

impl<O: Operation> Authorized<O> {
    /// The input the policy allowed.
    #[must_use]
    pub const fn input(&self) -> &O::Input {
        &self.input
    }

    /// Every resource derived from that same input.
    #[must_use]
    pub const fn resources(&self) -> &O::DerivedResources {
        &self.resources
    }

    /// The proof used by sealed resource types to reveal the exact value that was authorized.
    #[must_use]
    pub const fn read_proof(&self) -> &AuthorizedRead {
        &self.read
    }

    /// Consumes the proof into the request shape a handler receives.
    #[must_use]
    pub fn into_request(self) -> crate::Req<O> {
        crate::Req::from_authorized(self)
    }

    pub(crate) fn into_parts(self) -> (O::Input, O::DerivedResources, AuthorizedRead) {
        (self.input, self.resources, self.read)
    }
}

/// Proof that the derived-resource pass completed with only `Allow` decisions.
///
/// The field is private. Code can receive this from [`Authorized::read_proof`] but cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedRead {
    resources: Vec<OwnedResource>,
}

impl AuthorizedRead {
    pub(crate) const fn empty() -> Self {
        Self { resources: Vec::new() }
    }

    pub(crate) fn permits(&self, resource: ResourceRef<'_>) -> bool {
        self.resources.iter().any(|allowed| allowed.matches(resource))
    }
}

/// Consumes decoded input and creates the only value dispatch may accept.
///
/// Every resource is visited even after one refuses, so audit never loses the tail of a batch.
/// `Deny` and `Indeterminate` both prevent construction; the first refusing decision is retained.
pub(crate) fn authorize_input<O, F>(decoded: Decoded<O>, mut decide: F) -> Result<Authorized<O>, Denied>
where
    O: Operation,
    F: FnMut(ResourceRef<'_>) -> Decision,
{
    let mut refusal = None;
    let mut resources = Vec::with_capacity(decoded.resources.len());
    decoded.resources.visit(&mut |resource| {
        let decision = decide(resource);
        resources.push(OwnedResource::from_ref(resource));
        if decision != Decision::Allow && refusal.is_none() {
            refusal = Some(decision);
        }
    });
    if let Some(decision) = refusal {
        return Err(Denied { decision });
    }
    Ok(Authorized {
        input: decoded.input,
        resources: decoded.resources,
        read: AuthorizedRead { resources },
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use rustfs_gateway_sig::{OperationFloor, SigService};
    use rustfs_gateway_types::ObjectKey;

    use super::*;
    use crate::{AuthRequirement, OperationOrigin, OperationSpec, ResourceShape};

    static SPEC: OperationSpec = OperationSpec {
        name: "example:DeleteMany",
        success_status: 200,
        required_params: &[],
        not_configured_error: None,
        auth: Some(AuthRequirement::new("example:Delete", ResourceShape::Object)),
    };
    static FLOOR: OperationFloor = OperationFloor::builtin("example:DeleteMany", SigService::S3);

    struct DeleteMany;
    struct DeleteManyInput(Vec<ObjectKey>);
    struct DeleteManyResources(Vec<ObjectKey>);

    impl DerivedResourceSet for DeleteManyResources {
        fn visit(&self, visitor: &mut dyn FnMut(ResourceRef<'_>)) {
            for key in &self.0 {
                visitor(ResourceRef::object("example:Delete", None, key));
            }
        }
    }

    impl Operation for DeleteMany {
        const NAME: &'static str = "example:DeleteMany";
        const ORIGIN: OperationOrigin = OperationOrigin::ThirdParty;
        type Input = DeleteManyInput;
        type Output = ();
        type DerivedResources = DeleteManyResources;

        fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(DeleteManyResources(input.0.clone()))
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &SPEC
        }

        fn floor() -> &'static OperationFloor {
            &FLOOR
        }
    }

    fn key(value: &str) -> ObjectKey {
        ObjectKey::new(value).expect("a valid object key")
    }

    #[test]
    fn every_derived_resource_must_be_allowed_before_authorized_exists() {
        let decoded =
            prepare_input::<DeleteMany>(DeleteManyInput(vec![key("one"), key("two"), key("three")])).expect("resources derive");
        let mut seen = Vec::new();
        let refused = authorize_input(decoded, |resource| {
            let key = resource.key().expect("an object resource").as_str().to_owned();
            seen.push(key.clone());
            if key == "two" { Decision::Deny } else { Decision::Allow }
        });
        let Err(refused) = refused else {
            panic!("one refused resource produced an authorized request");
        };
        assert_eq!(seen, ["one", "two", "three"]);
        assert_eq!(refused.decision(), Decision::Deny);
    }

    #[test]
    fn allowing_every_resource_is_the_only_success_path() {
        let decoded =
            prepare_input::<DeleteMany>(DeleteManyInput(vec![key("one"), key("two"), key("three")])).expect("resources derive");
        let authorized = authorize_input(decoded, |_| Decision::Allow).expect("all resources allowed");
        assert_eq!(authorized.resources().len(), 3);
        assert_eq!(authorized.input().0.len(), 3);
    }

    #[test]
    fn an_empty_set_is_authorized_without_invoking_the_resource_callback() {
        let decoded = prepare_input::<rustfs_gateway_types::dto::GetObject>(Default::default()).expect("resources derive");
        let calls = std::cell::Cell::new(0);
        let authorized = authorize_input(decoded, |_| {
            calls.set(calls.get() + 1);
            Decision::Allow
        })
        .expect("empty set allowed");
        assert_eq!(calls.get(), 0);
        assert!(authorized.resources().is_empty());
    }

    #[test]
    fn indeterminate_is_a_refusal_not_an_authorized_value() {
        let decoded = prepare_input::<DeleteMany>(DeleteManyInput(vec![key("one")])).expect("resources derive");
        let denied = authorize_input(decoded, |_| Decision::Indeterminate);
        let Err(denied) = denied else {
            panic!("indeterminate produced an authorized request");
        };
        assert_eq!(denied.decision(), Decision::Indeterminate);
    }
}
