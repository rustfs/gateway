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

//! `CopyObject`: one server-side copy, and the two directives that decide what the copy carries.
//!
//! Shares: copy_source, precondition. The conditional headers this operation carries are the
//! precondition contract's to evaluate, and this file does not reach the entity-tag module
//! directly — `shared/etag.rs`'s `Members:` line records that from the other end, and it states
//! the use graph rather than what the use graph ought to be.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `CopyObject`, the [`HasOperation`] reverse mapping from its input type, and the one rule this
//! operation owns alone — what `x-amz-metadata-directive` and `x-amz-tagging-directive` mean.
//! NOT responsible for: parsing `x-amz-copy-source` or authorizing the source it names
//! ([`shared::copy_source`](super::shared::copy_source), shared with `UploadPartCopy`), evaluating
//! the conditions ([`shared::precondition`](super::shared::precondition)), the wire bindings, which
//! are generated into `generated/codec/ops/copy_object.rs` from `generated/ir/CopyObject.json` and
//! mounted by `crate::codec`, and moving any bytes.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! # Why this is not `PutObject` with an extra header
//!
//! On the wire it is exactly that: `PUT /{Bucket}/{Key+}` with `x-amz-copy-source` present. The
//! difference is that the header names a second resource the caller chose, so the request has two
//! authorization stages instead of one, and the request body is empty where `PutObject`'s is the
//! object. Routing separates them with `Predicate::HeaderPresent` at precedence 790, ahead of
//! `PutObject` at 800; `crates/core/src/route/shadowing.rs` records why that order is the correct
//! one.
//!
//! # Why the directives are a type and not two booleans
//!
//! `MetadataDirective: REPLACE` **rebuilds** the destination's metadata from the request; `COPY`
//! takes the source's and discards every `x-amz-meta-*` header the request carried. Upstream
//! ignored the field entirely and always copied (s3s#584), which no client can work around. A
//! `bool` named `replace` invites the third behaviour nobody wants — a merge — so the two answers
//! are named and [`MetadataSource`] is what a handler matches on.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput, CopyObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::copy_source::CopySourceResources;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The action is the destination's. The source's `s3:GetObject` is the second stage, and it is not
/// expressible here: [`AuthRequirement`] carries one action and one resource shape, which is P4-05's
/// open item. Until it carries two, the stage that cannot be skipped is the type state in
/// [`shared::copy_source`](super::shared::copy_source), not this field.
static SPEC: OperationSpec = OperationSpec::standard("CopyObject")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged. The request carries no body, so no payload mode
/// beyond the empty one is reachable.
static FLOOR: OperationFloor = OperationFloor::builtin("CopyObject", SigService::S3);

impl Operation for CopyObject {
    const NAME: &'static str = "CopyObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CopyObjectInput;
    type Output = CopyObjectOutput;
    type DerivedResources = CopySourceResources;

    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        CopySourceResources::parse(&input.copy_source)
    }

    fn derive_resources_under(
        input: &Self::Input,
        names: &rustfs_gateway_types::NamePolicy,
    ) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        CopySourceResources::parse_under(&input.copy_source, names)
    }

    fn seal_derived_input(input: &mut Self::Input) {
        input.copy_source.clear();
    }

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for CopyObjectInput {
    type Op = CopyObject;
}

/// Where the destination's metadata — or its tag set — comes from.
///
/// One type for both directives because they are one rule applied to two field groups, and holding
/// two answers for "what does REPLACE mean?" is how the copy family grew its second bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataSource {
    /// The source object's. Every `x-amz-meta-*` and object attribute on the request is discarded.
    /// This is the answer when the directive is absent.
    FromSource,
    /// The request's, rebuilt from scratch. Nothing is inherited from the source and nothing is
    /// merged: a metadata key the source had and the request omits is gone.
    FromRequest,
}

impl MetadataSource {
    /// Reads a directive header value.
    ///
    /// An unrecognised value is [`None`] rather than an error, and the caller renders that as
    /// `InvalidArgument`. Returning the default for an unknown spelling would silently copy the
    /// source's metadata for a client that asked for something else and had a typo.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value {
            None => Some(Self::FromSource),
            Some("COPY") => Some(Self::FromSource),
            Some("REPLACE") => Some(Self::FromRequest),
            Some(_) => None,
        }
    }

    /// Whether this directive changes the stored object on its own.
    ///
    /// This is what makes a self copy legal: `source == dest` with `REPLACE` is the documented way
    /// to rewrite metadata in place, and `source == dest` with `COPY` changes nothing and is
    /// refused. See `shared::copy_source`'s `classify_self_copy`.
    #[must_use]
    pub const fn changes_the_object(self) -> bool {
        matches!(self, Self::FromRequest)
    }
}

#[cfg(test)]
// Test code only. The crate denies these three so that no request path can panic; a test that
// cannot assert an `Ok` is a test that says less than it should.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_directive_copies_the_source_metadata() {
        assert_eq!(MetadataSource::parse(None), Some(MetadataSource::FromSource));
        assert_eq!(MetadataSource::parse(Some("COPY")), Some(MetadataSource::FromSource));
    }

    #[test]
    fn replace_rebuilds_from_the_request_and_counts_as_a_change() {
        assert_eq!(MetadataSource::parse(Some("REPLACE")), Some(MetadataSource::FromRequest));
        assert!(MetadataSource::FromRequest.changes_the_object());
        assert!(!MetadataSource::FromSource.changes_the_object());
    }

    #[test]
    fn an_unknown_or_miscased_directive_is_not_silently_the_default() {
        for value in ["replace", "Replace", "REPLACE ", "", "COPY_ALL"] {
            assert_eq!(MetadataSource::parse(Some(value)), None, "{value}");
        }
    }
}
