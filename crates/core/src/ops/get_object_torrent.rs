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

//! `GetObjectTorrent`: retrieval of an object's binary torrent descriptor.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `GET /{Bucket}/{Key+}?torrent` independently of backend registration.
//! NOT responsible for: producing torrent descriptors, implementing the handler, or returning the
//! parent object's body.
//! Upstream: the generated GetObjectTorrent dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without the generated route row, first-match sends the request to `GetObject`. That returns
//! the parent object's bytes rather than a torrent descriptor. Keeping routing independent of
//! registration makes an unsupported backend answer `NotImplemented` before object data can be
//! disclosed through the wrong response contract.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObjectTorrent, GetObjectTorrentInput, GetObjectTorrentOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing has selected the torrent subresource.
static SPEC: OperationSpec = OperationSpec::standard("GetObjectTorrent")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object))
    .build();

/// Torrent retrieval uses the S3 signature service and streams its binary response.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectTorrent", SigService::S3);

impl Operation for GetObjectTorrent {
    const NAME: &'static str = "GetObjectTorrent";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectTorrentInput;
    type Output = GetObjectTorrentOutput;
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

impl HasOperation for GetObjectTorrentInput {
    type Op = GetObjectTorrent;
}
