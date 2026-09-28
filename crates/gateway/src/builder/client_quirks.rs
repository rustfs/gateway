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

//! The RustFS-profile waiver of the modelled checksum requirement for MinIO clients
//! (rustfs/gateway#916).
//!
//! Responsible for: [`ServiceBuilder::accept_minio_client_checksum_omissions`], the closed set of
//! operations it covers, and the per-request decision the assembly applies to the routed view.
//! NOT responsible for: the requirement itself or verifying a digest a request does send
//! (`rustfs_gateway_core::codec::value`), which the waiver never touches.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, which applies [`ChecksumWaiver`]
//! to the view every decoder reads.
//!
//! # Why the set is exactly these operations
//!
//! The pinned AWS model marks both `httpChecksumRequired`, and the core keeps that default. The
//! MinIO SDKs the RustFS user base runs omit the digest on exactly these two writes, and RustFS
//! (through s3s) accepts them today, so a RustFS deployment that kept the requirement would break
//! `mc anonymous set` on the day it moved to the gateway:
//!
//! - `PutBucketPolicy`: minio-go v7.0.97 `SetBucketPolicy` sends no `Content-MD5`
//!   (<https://github.com/minio/minio-go/blob/v7.0.97/api-bucket-policy.go>), and `mc anonymous
//!   set` goes through it; minio-js 8.0.6 `setBucketPolicy` sends none either. Both were executed
//!   against `compat-sut` and refused with `400 InvalidRequest` (rustfs/gateway#756).
//! - `PutBucketVersioning`: minio-js 8.0.6 `setBucketVersioning` sends no `Content-MD5`
//!   (<https://github.com/minio/minio-js/blob/212f2821110e01b0ba5d81b27e11d10fdcb29d7b/src/internal/client.ts>).
//!
//! Every other checksum-required bucket write is checksummed by minio-go, minio-js and minio-py,
//! so it stays required.

use super::ServiceBuilder;
use rustfs_gateway_core::codec::MetaView;

/// The operations the MinIO-client waiver makes checksum-optional, and no others.
pub const MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS: [&str; 2] = ["PutBucketPolicy", "PutBucketVersioning"];

/// Whether an assembly waives the modelled checksum requirement for MinIO clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChecksumWaiver {
    minio_clients: bool,
}

impl ChecksumWaiver {
    /// The routed view of `operation`, with its integrity requirement waived when this assembly
    /// accepts MinIO clients' omissions and the operation is one they omit it on.
    pub(crate) fn apply<'a>(self, operation: &str, meta: MetaView<'a>) -> MetaView<'a> {
        if self.minio_clients && MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS.contains(&operation) {
            meta.with_integrity_optional()
        } else {
            meta
        }
    }
}

impl ServiceBuilder {
    /// Accepts the MinIO clients' omission of the body checksum the AWS model requires, on
    /// exactly [`MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS`] (rustfs/gateway#916).
    ///
    /// Off by default: the core answers the AWS model, `400 InvalidRequest` for a body with no
    /// integrity claim. The RustFS profile turns it on so that `mc anonymous set` and the MinIO
    /// SDKs keep working as they do against RustFS today. A `Content-MD5` or `x-amz-checksum-*`
    /// the request does send is still verified.
    #[must_use]
    pub fn accept_minio_client_checksum_omissions(mut self) -> Self {
        self.checksum_waiver = ChecksumWaiver { minio_clients: true };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_waiver_set_is_closed_and_off_by_default() {
        let waiver = ChecksumWaiver { minio_clients: true };
        assert!(waiver.minio_clients);
        assert_eq!(ChecksumWaiver::default(), ChecksumWaiver { minio_clients: false });
        assert!(MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS.contains(&"PutBucketPolicy"));
        assert!(!MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS.contains(&"PutBucketLifecycleConfiguration"));
        assert!(!MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS.contains(&"DeleteObjects"));
    }
}
