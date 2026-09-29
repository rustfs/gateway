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

//! Legacy RustFS's operation selection held across every pair of operation keys and every `x-id`
//! of every method and target (rustfs/gateway#1127): the RustFS-profile gateway against the legacy
//! stack as RustFS main configures it.
//!
//! Responsible for: showing that wherever both stacks name an operation it is the same one, that
//! every operation the legacy stack selects and this pairing registers is the one the gateway
//! reaches, and that an `x-id` the legacy stack refuses the gateway refuses with the same code; and
//! the control that proves a gateway without the switch is caught.
//! NOT responsible for: the order itself (`rustfs-gateway-core`'s `legacy_rustfs` tests), or an
//! operation this pairing does not register, which the gateway answers `501` without naming.
//! Upstream: the RustFS pairing. Downstream: none.

use http::Method;

use crate::decode::{DecodeDiff, Differ};
use crate::{DIFFED_OPERATIONS, Profile, RawRequest, rustfs_decode_diff};

const BUCKET_KEYS: &[&str] = &[
    "abac",
    "accelerate",
    "acl",
    "analytics",
    "analytics&id=1",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory&id=1",
    "lifecycle",
    "location",
    "logging",
    "metadataConfiguration",
    "metadataTable",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "session",
    "tagging",
    "uploads",
    "versioning",
    "versions",
    "website",
    "list-type=2",
    "delete",
];

const OBJECT_KEYS: &[&str] = &[
    "acl",
    "attributes",
    "legal-hold",
    "retention",
    "tagging",
    "torrent",
    "uploadId=u",
    "uploads",
    "partNumber=1&uploadId=u",
    "restore",
    "select&select-type=2",
    "annotation",
    "renameObject",
    "encryption",
];

/// Every operation name legacy RustFS reads an `x-id` against, and a few it does not know.
const DECLARED: &[&str] = &[
    "ListBuckets",
    "ListObjects",
    "ListObjectsV2",
    "ListObjectVersions",
    "ListMultipartUploads",
    "GetBucketLocation",
    "GetBucketVersioning",
    "PutBucketVersioning",
    "GetBucketAcl",
    "HeadBucket",
    "HeadObject",
    "GetObject",
    "ListParts",
    "PutObject",
    "CopyObject",
    "UploadPart",
    "UploadPartCopy",
    "CreateBucket",
    "DeleteBucket",
    "DeleteObject",
    "DeleteObjects",
    "AbortMultipartUpload",
    "CreateMultipartUpload",
    "CompleteMultipartUpload",
    "PutObjectTagging",
    "NoSuchOp",
    "getobject",
];

const SHAPES: &[(Method, &str, &[&str])] = &[
    (Method::GET, "/bkt", BUCKET_KEYS),
    (Method::PUT, "/bkt", BUCKET_KEYS),
    (Method::DELETE, "/bkt", BUCKET_KEYS),
    (Method::POST, "/bkt", BUCKET_KEYS),
    (Method::HEAD, "/bkt", BUCKET_KEYS),
    (Method::GET, "/bkt/src", OBJECT_KEYS),
    (Method::PUT, "/bkt/src", OBJECT_KEYS),
    (Method::DELETE, "/bkt/src", OBJECT_KEYS),
    (Method::POST, "/bkt/src", OBJECT_KEYS),
    (Method::HEAD, "/bkt/src", OBJECT_KEYS),
];

/// Every request the cross-check sends: each key alone, each pair of keys, and each `x-id` of
/// every method and target, also beside a key.
fn requests() -> Vec<RawRequest> {
    let mut requests = Vec::new();
    for (method, path, keys) in SHAPES {
        for (index, first) in keys.iter().enumerate() {
            requests.push(RawRequest::with_body(method.clone(), &format!("{path}?{first}"), b""));
            // A pair naming one key twice is left out: a repeated single-valued parameter is a
            // refusal of its own on the gateway (it is two answers to one question), not a choice.
            for second in keys.iter().skip(index + 1).filter(|second| !shares_a_key(first, second)) {
                requests.push(RawRequest::with_body(method.clone(), &format!("{path}?{second}&{first}"), b""));
            }
        }
        for name in DECLARED {
            requests.push(RawRequest::with_body(method.clone(), &format!("{path}?x-id={name}"), b""));
            requests.push(RawRequest::with_body(method.clone(), &format!("{path}?{}&x-id={name}", keys[2]), b""));
        }
    }
    for name in DECLARED {
        requests.push(RawRequest::get(&format!("/?x-id={name}")));
    }
    requests
}

/// Whether two query fragments name a key in common.
fn shares_a_key(first: &str, second: &str) -> bool {
    fn names(fragment: &str) -> impl Iterator<Item = &str> {
        fragment.split('&').map(|pair| pair.split('=').next().unwrap_or_default())
    }
    names(first).any(|name| names(second).any(|other| other == name))
}

/// What is wrong with one comparison, if anything.
fn problem(diff: &DecodeDiff) -> Option<String> {
    let (gateway, legacy) = (diff.operation.gateway.as_deref(), diff.operation.s3s.as_deref());
    let code = |side: &Option<crate::S3ErrorView>| side.as_ref().and_then(|error| error.code.clone());
    match (gateway, legacy) {
        (Some(gateway), Some(legacy)) if gateway != legacy => Some(format!("gateway {gateway}, legacy {legacy}")),
        (None, Some(legacy)) if DIFFED_OPERATIONS.contains(&legacy) => {
            Some(format!("legacy {legacy}, which the gateway registers, and the gateway none"))
        }
        (Some(gateway), None) if code(&diff.error.s3s).as_deref() == Some("InvalidRequest") => {
            Some(format!("gateway {gateway}, legacy InvalidRequest"))
        }
        (None, None) if diff.error.s3s.as_ref().map(|error| error.status) == Some(400) => {
            let (gateway, legacy) = (diff.error.gateway.as_ref(), diff.error.s3s.as_ref());
            (gateway.map(|error| (error.status, error.code.clone())) != legacy.map(|error| (error.status, error.code.clone())))
                .then(|| format!("gateway {gateway:?}, legacy {legacy:?}"))
        }
        _ => None,
    }
}

/// Positive — across every pair of keys and every `x-id`, the gateway selects what legacy RustFS
/// selects wherever this pairing can see the operation, and refuses what it refuses.
#[test]
fn every_pair_of_keys_and_every_x_id_selects_what_legacy_rustfs_selects() {
    let mut problems = Vec::new();
    let mut compared = 0usize;
    for request in requests() {
        let diff = rustfs_decode_diff(&request).unwrap_or_else(|error| panic!("{request:?}: {error}"));
        if diff.operation.gateway.is_some() && diff.operation.s3s.is_some() {
            compared += 1;
        }
        if let Some(problem) = problem(&diff) {
            problems.push(format!("{} {}: {problem}", request.method, request.target));
        }
    }
    assert!(problems.is_empty(), "{} request(s):\n{}", problems.len(), problems.join("\n"));
    assert!(compared > 200, "only {compared} request(s) reached an operation on both stacks");
}

/// Negative — a gateway without the legacy selection, against the same legacy stack, is caught.
#[test]
fn n_a_gateway_without_the_legacy_selection_is_caught() {
    let differ = Differ::with_profiles(Profile::Generic, Profile::Rustfs).expect("the stacks build");
    for target in [
        "/bkt?versioning&location",
        "/bkt?location&x-id=GetBucketVersioning",
        "/bkt?x-id=NoSuchOp",
    ] {
        let diff = differ.diff(&RawRequest::get(target)).expect("a comparison");
        assert!(problem(&diff).is_some(), "{target}: the default gateway was not caught");
    }
}
