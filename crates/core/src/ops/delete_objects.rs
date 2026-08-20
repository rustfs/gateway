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

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ObjectKey;
use rustfs_gateway_types::dto::{DeleteObjects, DeleteObjectsInput, DeleteObjectsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// Every key carried by one multi-object delete body.
struct DeleteObjectResource {
    action: &'static str,
    key: ObjectKey,
    version_id: Option<String>,
}

impl DeleteObjectResource {
    fn as_ref(&self) -> crate::ResourceRef<'_> {
        match self.version_id.as_deref() {
            Some(version_id) => crate::ResourceRef::object_version(self.action, None, &self.key, version_id),
            None => crate::ResourceRef::object(self.action, None, &self.key),
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
        self.0
            .iter()
            .all(|resource| proof.permits(resource.as_ref()))
            .then(|| self.0.iter().map(|resource| (&resource.key, resource.version_id.as_deref())))
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
                    key: object.key.clone(),
                    version_id: object.version_id.clone(),
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

    #[test]
    fn a_post_authorization_input_mutation_cannot_add_a_delete() {
        let mut input = DeleteObjectsInput::default();
        let first = rustfs_gateway_types::dto::ObjectIdentifier {
            key: ObjectKey::new("allowed").expect("valid key"),
            ..Default::default()
        };
        input.delete.objects.push(first);

        let authorized =
            authorize_input(prepare_input::<DeleteObjects>(input).expect("derived"), |_| Decision::Allow).expect("authorized");
        let mut request = authorized.into_request();
        let injected = rustfs_gateway_types::dto::ObjectIdentifier {
            key: ObjectKey::new("injected").expect("valid key"),
            ..Default::default()
        };
        request.input_mut().delete.objects.push(injected);

        assert_eq!(request.input().delete.objects.len(), 1, "the mutable raw input received the injected key");
        let resolved = request
            .resources()
            .resolve(request.read_proof())
            .expect("the original resource proof matches");
        let keys = resolved.map(|(key, _)| key.as_str()).collect::<Vec<_>>();
        assert_eq!(keys, ["allowed"]);
    }
}
