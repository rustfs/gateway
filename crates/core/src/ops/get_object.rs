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

//! `GetObject`: one object read, with the response headers the request may overwrite.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/get_object.rs` from `generated/ir/GetObject.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: precondition, etag
//!
//! Also shares object attributes, user metadata, checksum and the `response-*` overrides with the
//! object family; those have no module under `ops/shared/` because the generated codec carries
//! them, so they are named here in prose rather than in the machine-readable line above. The range
//! rules are part of `shared::precondition` and not a module of their own.
//!
//! [`CONDITION_KIND`] and [`CONDITIONS`] are what this file contributes to the conditional
//! cluster, in the shape `ListObjects::CURSOR` contributes to the List cluster: the operation owns
//! the facts that are constant about it, and the shared module owns the rules. What is *not* here
//! is the call to [`evaluate`](crate::ops::shared::precondition::evaluate) — that needs the
//! representation a handler resolved, so its call site is the backend's, and a backend outside
//! this workspace cannot reach the function yet. See `crates/core/MAP.md`, "Open for maintainer
//! review".
//!
//! The `response-*` query parameters are applied by the generated encoder as a final pass over
//! the header set, from `OperationCodec::RESPONSE_OVERRIDES` — so an override wins over whatever
//! the object's own attributes wrote, without the ordering being something a reader has to work
//! out. `x-amz-storage-class` is suppressed for the default class, which is the exact opposite of
//! the listing body element; both are `omit_when` data in `model/overlays/ops/object.toml`, and
//! neither is a branch anybody wrote.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObject, GetObjectInput, GetObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::etag::ConditionalHeader;
use crate::ops::shared::precondition::RequestKind;
use crate::registry::OperationSpec;

/// Which side of the read/write split this operation's conditions are evaluated on.
///
/// A read, so a satisfied `If-None-Match` is a `304` here and a `412` on `PutObject`. Declared
/// rather than left to the caller for the reason the same split exists at all: a write answered
/// with `304` tells a client its object is unchanged when it was never written, and "which kind is
/// this operation?" is a fact this file owns and no backend should have to re-derive.
pub static CONDITION_KIND: RequestKind = RequestKind::Read;

/// The entity-tag conditions evaluated against the object this request names.
///
/// Both are evaluated against the *target*, which is the whole difference from `CopyObject` — it
/// carries these two plus the `x-amz-copy-source-if-*` pair, and the two pairs answer to different
/// representations.
pub static CONDITIONS: [ConditionalHeader; 2] = [ConditionalHeader::IfMatch, ConditionalHeader::IfNoneMatch];

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("GetObject", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object))
    .build();

/// Header and presigned signatures, matching `spec/operations/GetObject.toml`.
static FLOOR: OperationFloor = OperationFloor::builtin_presigned("GetObject", SigService::S3);

impl Operation for GetObject {
    const NAME: &'static str = "GetObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectInput;
    type Output = GetObjectOutput;
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

impl HasOperation for GetObjectInput {
    type Op = GetObject;
}
