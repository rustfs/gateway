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

//! The AWS operation names this macro validates against.
//!
//! Responsible for: [`OPERATION_NAMES`], and the note about where it really comes from.
//! NOT responsible for: the mapping between a method name and one of these
//! (`crate::mapping`), or for deciding anything about a name that is in the list.
//! Upstream: the generated route table, by way of the test below. Downstream: `crate::mapping`.
//!
//! # This is a mirror, and the mirror is checked
//!
//! The set of AWS operation names exists once, in the generated route table that
//! `rustfs-gateway-core` mounts. A proc-macro crate cannot read it at expansion time without
//! depending on that crate — which would put the whole generated dto tree into the build graph of
//! every crate that uses the macro, for a list of strings.
//!
//! So the list is mirrored here and `tests/op_names.rs` fails the moment it disagrees with
//! `rustfs_gateway_core::standard_operation_names()`. That is the same guarantee a generated file
//! would give, without the dependency: there is still exactly one source of truth, and drift is
//! still a red test rather than a silent divergence.
//!
//! When codegen owns this file, the test stays: it is what proves the generator ran.

/// Every AWS operation name this build knows, sorted.
///
/// Kept in step with `rustfs_gateway_core::standard_operation_names()` by `tests/op_names.rs`.
pub(crate) static OPERATION_NAMES: &[&str] = &[
    "AbortMultipartUpload",
    "CompleteMultipartUpload",
    "CopyObject",
    "CreateMultipartUpload",
    "DeleteObject",
    "DeleteObjects",
    "GetBucketLocation",
    "GetObject",
    "GetObjectAttributes",
    "HeadObject",
    "ListBuckets",
    "ListMultipartUploads",
    "ListObjectVersions",
    "ListObjects",
    "ListObjectsV2",
    "ListParts",
    "PutObject",
    "UploadPart",
    "UploadPartCopy",
];

/// Method names that would collide with a Rust keyword if derived mechanically.
///
/// Expected to stay empty: no AWS operation name snake-cases into a keyword. If one ever does, it
/// is registered here and named in the pull request, rather than silently special-cased in the
/// mapping.
pub(crate) static SNAKE_ALIASES: &[(&str, &str)] = &[];
