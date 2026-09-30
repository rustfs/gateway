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

//! Clean-room concrete dialect fields and operations for MinIO-compatible protocol bytes.
//!
//! Responsible for: registering the lifecycle `DelMarkerExpiration` field against the production
//! ExtField mechanism, and the replica write `minio:PutObjectReplica` ([`replication`]) against the
//! dialect operation mechanism. NOT responsible for: literal bodies, error rendering, other
//! extensions, or MinIO server implementation details. Upstream: public protocol observations,
//! ADR-0007 and `rustfs-gateway-core`'s dialect module. Downstream: applications that explicitly
//! select this dialect.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
// No stdout, no stderr, no `dbg!` outside tests: a diagnostic is a `tracing` event (docs/observability.md).
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro))]

pub mod ops;
pub mod replication;

pub use replication::{PutObjectReplica, PutObjectReplicaInput, ReplicaWriteResources, replication_dialect};

use rustfs_gateway_types::ext::{CodecPolicy, ExtError, ExtField, PersistedXml};
use rustfs_gateway_types::persistence::{
    ExtensibleLifecycleConfiguration, parse_lifecycle_with_policy, serialize_lifecycle_with_policy,
};
use rustfs_gateway_xml::{XmlNode, XmlWriter};

/// A delete-marker expiration age carried below one Lifecycle rule.
///
/// Evidence: <https://github.com/s3s-project/s3s/pull/611> — this self-written summary records that
/// a real S3-compatible client family sends `DelMarkerExpiration` as a child of `LifecycleRule`,
/// which previously forced a second generated codec surface.
#[derive(Debug, Eq, PartialEq)]
pub struct DelMarkerExpiration {
    /// Days before the delete marker expires.
    pub days: i32,
}

impl ExtField for DelMarkerExpiration {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "DelMarkerExpiration";
    const INSERT_AFTER: &'static str = "Expiration";

    fn decode_xml(node: &XmlNode) -> Result<Self, ExtError> {
        if node.name != Self::LOCAL_NAME {
            return Err(ExtError::InvalidXml);
        }
        let mut days = None;
        for child in &node.children {
            if child.name != "Days" || !child.children.is_empty() || days.is_some() {
                return Err(ExtError::UnknownElement(child.name.clone()));
            }
            days = Some(
                child
                    .text
                    .parse()
                    .map_err(|_| ExtError::InvalidValue("DelMarkerExpiration.Days"))?,
            );
        }
        days.map(|days| Self { days })
            .ok_or(ExtError::MissingRequired("DelMarkerExpiration.Days"))
    }

    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), ExtError> {
        writer.open(Self::LOCAL_NAME, None);
        writer.element_i64("Days", i64::from(self.days));
        writer.close();
        Ok(())
    }
}

/// The clean-room lifecycle portion of the MinIO-compatible dialect.
///
/// It owns a per-instance policy rather than a process-global registry, so two gateway instances
/// may select different dialects in the same process.
pub struct MinioLifecycleDialect {
    policy: CodecPolicy,
}

impl MinioLifecycleDialect {
    /// Registers the one lifecycle extension implemented by this slice.
    ///
    /// # Errors
    ///
    /// [`ExtError::DuplicateRegistration`] if the concrete registration is duplicated by a future
    /// edit rather than composed deliberately.
    pub fn new() -> Result<Self, ExtError> {
        let mut policy = CodecPolicy::security_relevant();
        policy.register::<DelMarkerExpiration>()?;
        Ok(Self { policy })
    }

    /// Builds the no-registration control used to prove the field cannot bypass selection.
    #[must_use]
    pub fn without_extensions() -> Self {
        Self {
            policy: CodecPolicy::security_relevant(),
        }
    }

    /// Decodes persisted Lifecycle bytes without giving up their exact original form on refusal.
    #[must_use]
    pub fn decode_persisted(&self, input: &[u8]) -> PersistedXml<ExtensibleLifecycleConfiguration> {
        parse_lifecycle_with_policy(input, &self.policy)
    }

    /// Encodes and authorizes replacement only after the original document decoded completely.
    ///
    /// # Errors
    ///
    /// [`ExtError::PersistedRewriteBlocked`] after any registration miss or parse failure; another
    /// [`ExtError`] if a registered field or its static parent cannot encode.
    pub fn rewrite(&self, persisted: &PersistedXml<ExtensibleLifecycleConfiguration>) -> Result<Vec<u8>, ExtError> {
        let Ok(value) = persisted.value() else {
            return persisted.replacement(Vec::new());
        };
        let encoded = serialize_lifecycle_with_policy(value, &self.policy)?;
        persisted.replacement(encoded)
    }
}
