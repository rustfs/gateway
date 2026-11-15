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

//! `DeleteObjects`: many keys removed in one request, each with its own outcome.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteObjects`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/delete_objects.rs` from `generated/ir/DeleteObjects.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the checksum-header rule with every operation that accepts one.
//!
//! Two facts shape it. The request body is in the `httpChecksumRequired` set, so a request with
//! neither `Content-MD5` nor an `x-amz-checksum-*` header is a `400` before the handler runs —
//! `http_checksum_required` in the overlay, not an `if` here. And every key in the request must
//! appear exactly once in the result, as either a deleted entry or an error entry: a caller that
//! gets back fewer entries than it sent cannot tell which of its keys survived.
//!
//! A third fact bounds the work: S3 caps one multi-object delete at [`MAX_KEYS_PER_DELETE`] keys
//! and refuses a larger body as `MalformedXML` before deleting anything (rustfs/gateway#810). The
//! cap is enforced where the keys become resources, so it runs before authorization and before any
//! backend, and no handler holds one deadline over an unbounded batch.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ObjectKey;
use rustfs_gateway_types::dto::{DeleteObjects, DeleteObjectsInput, DeleteObjectsOutput, ObjectIdentifier};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// The most keys one `DeleteObjects` body may name, as S3 documents and enforces it.
pub const MAX_KEYS_PER_DELETE: usize = 1000;

/// Every key carried by one multi-object delete body.
struct DeleteObjectResource {
    action: &'static str,
    object: ObjectIdentifier,
}

impl DeleteObjectResource {
    fn as_ref(&self) -> crate::ResourceRef<'_> {
        match self.object.version_id.as_deref() {
            Some(version_id) => crate::ResourceRef::object_version(self.action, None, &self.object.key, version_id),
            None => crate::ResourceRef::object(self.action, None, &self.object.key),
        }
    }
}

/// Every key carried by one multi-object delete body.
pub struct DeleteObjectResources(Vec<DeleteObjectResource>);

impl DeleteObjectResources {
    /// Reveals the exact authorized delete list, never the mutable raw DTO list.
    #[must_use]
    pub fn resolve<'a>(
        &'a self,
        proof: &'a crate::AuthorizedRead,
    ) -> Option<impl ExactSizeIterator<Item = (&'a ObjectKey, Option<&'a str>)> + 'a> {
        self.resolve_objects(proof)
            .map(|objects| objects.map(|object| (&object.key, object.version_id.as_deref())))
    }

    /// Borrows the frozen key, version ID, ETag, last-modified time and size of every entry.
    ///
    /// The iterator yields immutable references in request order, including duplicate entries.
    /// Returns `None` if the proof does not cover every resource in the batch.
    #[must_use]
    pub fn resolve_objects<'a>(
        &'a self,
        proof: &crate::AuthorizedRead,
    ) -> Option<impl ExactSizeIterator<Item = &'a ObjectIdentifier> + 'a> {
        self.0
            .iter()
            .all(|resource| proof.permits(resource.as_ref()))
            .then(|| self.0.iter().map(|resource| &resource.object))
    }
}

impl crate::DerivedResourceSet for DeleteObjectResources {
    fn visit(&self, visitor: &mut dyn FnMut(crate::ResourceRef<'_>)) {
        for resource in &self.0 {
            visitor(resource.as_ref());
        }
    }
}

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::standard("DeleteObjects")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:DeleteObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteObjects", SigService::S3);

impl Operation for DeleteObjects {
    const NAME: &'static str = "DeleteObjects";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteObjectsInput;
    type Output = DeleteObjectsOutput;
    type DerivedResources = DeleteObjectResources;

    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        if input.delete.objects.len() > MAX_KEYS_PER_DELETE {
            return Err(crate::authz::DerivedResourceError::new(
                rustfs_gateway_types::ErrorCode::MALFORMED_XML,
                "a multi-object delete names at most 1000 keys",
            ));
        }
        Ok(DeleteObjectResources(
            input
                .delete
                .objects
                .iter()
                .map(|object| DeleteObjectResource {
                    action: if object.version_id.is_some() {
                        "s3:DeleteObjectVersion"
                    } else {
                        "s3:DeleteObject"
                    },
                    object: object.clone(),
                })
                .collect(),
        ))
    }

    fn seal_derived_input(input: &mut Self::Input) {
        input.delete.objects.clear();
    }

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for DeleteObjectsInput {
    type Op = DeleteObjects;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::Decision;
    use crate::authz::{authorize_input, prepare_input};
    use rustfs_gateway_types::{ETag, Timestamp};

    fn authorize_objects(objects: Vec<ObjectIdentifier>) -> crate::authz::Authorized<DeleteObjects> {
        let mut input = DeleteObjectsInput::default();
        input.delete.objects = objects;
        authorize_input(prepare_input::<DeleteObjects>(input).expect("derived"), |_| Decision::Allow).expect("authorized")
    }

    fn conditioned_object(key: &str) -> ObjectIdentifier {
        ObjectIdentifier {
            key: ObjectKey::new(key).expect("valid key"),
            version_id: Some("version".into()),
            e_tag: Some(ETag::new_weak("conditional").expect("valid tag")),
            last_modified_time: Some(Timestamp::from_secs_nanos(1_700_000_000, 123).expect("valid timestamp")),
            size: Some(-1),
        }
    }

    fn fields(object: &ObjectIdentifier) -> (&ObjectKey, Option<&str>, Option<&ETag>, Option<&Timestamp>, Option<i64>) {
        (
            &object.key,
            object.version_id.as_deref(),
            object.e_tag.as_ref(),
            object.last_modified_time.as_ref(),
            object.size,
        )
    }

    #[test]
    fn resolves_frozen_objects_in_input_order_with_duplicates() {
        let versioned = conditioned_object("z");
        let null_version = ObjectIdentifier {
            key: ObjectKey::new("a").expect("valid key"),
            version_id: Some("null".into()),
            e_tag: Some(ETag::ANY),
            size: Some(0),
            ..Default::default()
        };
        let current = ObjectIdentifier {
            key: versioned.key.clone(),
            ..Default::default()
        };
        let expected = [versioned.clone(), null_version, current, versioned];
        let authorized = authorize_objects(expected.to_vec());
        let resolved = authorized
            .resources()
            .resolve_objects(authorized.read_proof())
            .expect("proof covers all original entries");
        assert_eq!(resolved.map(fields).collect::<Vec<_>>(), expected.iter().map(fields).collect::<Vec<_>>());
    }

    #[test]
    fn partial_proof_cannot_resolve_any_frozen_objects() {
        let first = ObjectIdentifier {
            key: ObjectKey::new("first").expect("valid key"),
            ..Default::default()
        };
        let second = ObjectIdentifier {
            key: ObjectKey::new("second").expect("valid key"),
            version_id: Some("required".into()),
            ..Default::default()
        };
        let other_version = ObjectIdentifier {
            version_id: Some("other".into()),
            ..second.clone()
        };
        let partial = authorize_objects(vec![first.clone(), other_version]);
        let target = authorize_objects(vec![first, second]);
        assert!(target.resources().resolve_objects(partial.read_proof()).is_none());
    }

    #[test]
    fn a_post_authorization_input_mutation_cannot_add_a_delete() {
        let first = conditioned_object("allowed");
        let authorized = authorize_objects(vec![first.clone()]);
        let mut request = authorized.into_request(
            crate::SseEnforced::empty_for_unit_test(),
            crate::RequestContextView::detached("DeleteObjects"),
        );
        let injected = ObjectIdentifier {
            key: ObjectKey::new("injected").expect("valid key"),
            ..Default::default()
        };
        let replacement = ObjectIdentifier {
            size: Some(50),
            ..first.clone()
        };
        request.input_mut().delete.objects.extend([replacement, injected]);

        assert_eq!(
            request.input().delete.objects.len(),
            2,
            "the raw input contains only the injected entries"
        );
        let resolved = request
            .resources()
            .resolve(request.read_proof())
            .expect("the original resource proof matches");
        let identities = resolved
            .map(|(key, version_id)| (key.as_str(), version_id))
            .collect::<Vec<_>>();
        assert_eq!(identities, [("allowed", Some("version"))]);

        let objects = request
            .resources()
            .resolve_objects(request.read_proof())
            .expect("the original resource proof matches");
        assert_eq!(objects.map(fields).collect::<Vec<_>>(), [fields(&first)]);
    }

    /// Negative — 1001 keys are refused as `MalformedXML` before any resource is derived, so
    /// nothing is authorized and no handler runs; 1000 keys derive 1000 resources (rustfs/gateway#810).
    #[test]
    fn n_a_thousand_and_first_key_is_refused_before_derivation() {
        let body = |count: usize| {
            let mut input = DeleteObjectsInput::default();
            for index in 0..count {
                input.delete.objects.push(ObjectIdentifier {
                    key: ObjectKey::new(format!("k{index}")).expect("valid key"),
                    ..Default::default()
                });
            }
            input
        };
        // The literals are the documented cap, not the constant, so a moved cap turns this red.
        let refused = DeleteObjects::derive_resources(&body(1001))
            .err()
            .expect("1001 keys are refused");
        assert_eq!(refused.code(), &rustfs_gateway_types::ErrorCode::MALFORMED_XML);
        assert_eq!(refused.message(), "a multi-object delete names at most 1000 keys");
        let derived = DeleteObjects::derive_resources(&body(1000)).map(|derived| derived.0.len());
        assert_eq!((derived.ok(), MAX_KEYS_PER_DELETE), (Some(1000), 1000));
    }
}
