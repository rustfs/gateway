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

//! Static error declarations for bucket-configuration operation triples.
//!
//! Responsible for: proving each read's unconfigured error and each sibling write/delete's
//! absence of one. NOT responsible for: routing or dispatch, which `params_and_dispatch.rs`
//! covers. Upstream: generated operation specs. Downstream: backend error selection.

use http::StatusCode;
use rustfs_gateway_core::op::Operation;
use rustfs_gateway_types::ErrorCode;

/// The encryption read declares its own unconfigured code, and its two siblings declare none.
///
/// The declaration is what a backend outside this workspace reads to learn which 404 an
/// unconfigured bucket owes; the conformance fixture answers the code from its own constant, so
/// without this test the spec field could be deleted and every encryption case would still pass —
/// a value declared and never observed, which is the defect the Measurement rules exist for.
///
/// Both directions are asserted deliberately. A spec field stuck on `Some(..)` would satisfy the
/// first assertion alone, and the write and the delete are exactly the operations that must carry
/// `None`: neither reads a configuration, and a 404 from either would mean "no such bucket" to a
/// client that branches on the code.
#[test]
fn the_encryption_read_declares_its_own_not_configured_code() {
    let code = rustfs_gateway_types::dto::GetBucketEncryption::spec()
        .not_configured_error
        .clone()
        .expect("the bucket subresource read declares one");
    assert_eq!(code, ErrorCode::SERVER_SIDE_ENCRYPTION_CONFIGURATION_NOT_FOUND);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert_eq!(
        code.as_str(),
        "ServerSideEncryptionConfigurationNotFoundError",
        "the literal ends in Error, which is the spelling clients branch on"
    );
    for (name, declared) in [
        (
            "PutBucketEncryption",
            rustfs_gateway_types::dto::PutBucketEncryption::spec()
                .not_configured_error
                .is_none(),
        ),
        (
            "DeleteBucketEncryption",
            rustfs_gateway_types::dto::DeleteBucketEncryption::spec()
                .not_configured_error
                .is_none(),
        ),
    ] {
        assert!(declared, "{name} reads no configuration and must declare no unconfigured code");
    }
}

/// The lifecycle read declares its own unconfigured code, and its two siblings declare none.
///
/// Same claim as the encryption block above, for the family beside it:
/// `params_and_dispatch::an_unconfigured_subresource_has_its_own_code` asserts the code against
/// its local `GET_LIFECYCLE` fixture, so it holds the fixture rather than the generated operation.
/// Nothing else reads `GetBucketLifecycleConfiguration`'s own declaration.
///
/// The delete is spelled `DeleteBucketLifecycle`, without the `Configuration` suffix its two
/// siblings carry — the asymmetry is AWS's, and naming it here is why the `None` direction cannot
/// be satisfied by asserting the wrong operation.
#[test]
fn the_lifecycle_read_declares_its_own_not_configured_code() {
    let code = rustfs_gateway_types::dto::GetBucketLifecycleConfiguration::spec()
        .not_configured_error
        .clone()
        .expect("the bucket subresource read declares one");
    assert_eq!(code, ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert_eq!(code.as_str(), "NoSuchLifecycleConfiguration", "the spelling clients branch on");
    for (name, declared) in [
        (
            "PutBucketLifecycleConfiguration",
            rustfs_gateway_types::dto::PutBucketLifecycleConfiguration::spec()
                .not_configured_error
                .is_none(),
        ),
        (
            "DeleteBucketLifecycle",
            rustfs_gateway_types::dto::DeleteBucketLifecycle::spec()
                .not_configured_error
                .is_none(),
        ),
    ] {
        assert!(declared, "{name} reads no configuration and must declare no unconfigured code");
    }
}

/// The CORS read declares its own unconfigured code, and its two siblings declare none.
///
/// The third of the three bucket-configuration triples, asserted for the same reason: the 404 a
/// conformance case observes comes from the fixture, so only this test holds the field a backend
/// outside the workspace reads.
///
/// The literal is asserted because `CORS` is upper-case in the middle of an otherwise camel-cased
/// code. A client matching `NoSuchCorsConfiguration` gets no match, so the casing is part of the
/// contract and not a spelling detail.
#[test]
fn the_cors_read_declares_its_own_not_configured_code() {
    let code = rustfs_gateway_types::dto::GetBucketCors::spec()
        .not_configured_error
        .clone()
        .expect("the bucket subresource read declares one");
    assert_eq!(code, ErrorCode::NO_SUCH_CORS_CONFIGURATION);
    assert_eq!(code.default_status(), StatusCode::NOT_FOUND);
    assert_eq!(code.as_str(), "NoSuchCORSConfiguration", "the acronym stays upper-case");
    for (name, declared) in [
        (
            "PutBucketCors",
            rustfs_gateway_types::dto::PutBucketCors::spec()
                .not_configured_error
                .is_none(),
        ),
        (
            "DeleteBucketCors",
            rustfs_gateway_types::dto::DeleteBucketCors::spec()
                .not_configured_error
                .is_none(),
        ),
    ] {
        assert!(declared, "{name} reads no configuration and must declare no unconfigured code");
    }
}
