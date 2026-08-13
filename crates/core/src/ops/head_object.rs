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

//! `HeadObject`: the header set of a `GetObject`, and never a body.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `HeadObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/head_object.rs` from `generated/ir/HeadObject.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: precondition, etag
//!
//! It also shares its entire header contract with `GetObject`, by derivation rather than by copy.
//!
//! [`CONDITION_KIND`] and [`CONDITIONS`] repeat `GetObject`'s two values, because a `HEAD` really
//! does evaluate the same conditions against the same representation. They are declared here
//! rather than re-exported so that this file states its own membership — that is what the
//! `//! Members:` line in [`crate::ops::shared::precondition`] is checked against. The evaluation
//! call is not here, for the reason recorded in [`crate::ops::get_object`].
//!
//! The header set is not written twice. The overlay declares `head_mirrors = "GetObject"`, so the
//! two encoders are generated from one binding table; upstream lost the entity tag on this
//! response precisely because its two tables were hand-written and only one of them was fixed.
//!
//! The absent body is not this file's rule either: `EncodedResponse::enforce_http_invariants` drops
//! the body of every `HEAD` response, on every status, once — RFC 9110 says so about HTTP, not
//! about `HeadObject`.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{HeadObject, HeadObjectInput, HeadObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::etag::ConditionalHeader;
use crate::ops::shared::precondition::RequestKind;
use crate::registry::OperationSpec;

/// Which side of the read/write split this operation's conditions are evaluated on.
///
/// A read, and identical to `GetObject`'s: a `HEAD` that answered a condition differently from the
/// `GET` it mirrors would let a client revalidate against one answer and fetch against another.
pub static CONDITION_KIND: RequestKind = RequestKind::Read;

/// The entity-tag conditions evaluated against the object this request names.
pub static CONDITIONS: [ConditionalHeader; 2] = [ConditionalHeader::IfMatch, ConditionalHeader::IfNoneMatch];

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("HeadObject", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("HeadObject", SigService::S3);

impl Operation for HeadObject {
    const NAME: &'static str = "HeadObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = HeadObjectInput;
    type Output = HeadObjectOutput;
    type DerivedResources = crate::authz::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Ok(crate::authz::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for HeadObjectInput {
    type Op = HeadObject;
}
