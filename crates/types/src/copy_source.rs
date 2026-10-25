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

//! Owned decoded copy-source fields for input migration.
//!
//! Responsible for: retaining source shape and text before deployment validation and authorization.
//! NOT responsible for: parsing headers, validating names or granting access to the source object.
//! Upstream: request decoders and compatibility adapters. Downstream: application authorization.

/// A decoded source description, not a validated name or an authorization proof.
///
/// Fields intentionally retain empty and otherwise invalid text. Converting a legacy request
/// must not move a later validation failure ahead of its existing authorization checks. Consumers
/// apply their deployment policy and authorize the full source identity at the same stage as before.
/// `None` and `Some("")` versions are distinct: presence can select a versioned read action.
/// The core's proof-gated copy resource remains the type used to execute an authorized copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopySourceValue {
    /// A source addressed by bucket and key.
    Bucket {
        /// Source bucket spelling, before deployment name validation.
        bucket: String,
        /// Already-decoded object key, without another decode or normalization.
        key: String,
        /// Decoded version identifier; explicit emptiness is retained.
        version_id: Option<String>,
    },
    /// An access point source whose full ARN identity must survive.
    AccessPoint {
        /// ARN partition.
        partition: String,
        /// ARN region.
        region: String,
        /// ARN account identifier.
        account_id: String,
        /// ARN access point name.
        access_point_name: String,
        /// Already-decoded object key.
        key: String,
        /// Decoded version identifier; explicit emptiness is retained.
        version_id: Option<String>,
    },
    /// An Outposts source whose full ARN identity must survive.
    Outpost {
        /// ARN partition.
        partition: String,
        /// ARN region.
        region: String,
        /// ARN account identifier.
        account_id: String,
        /// Decoded outpost component, including any remaining path segments.
        outpost_id: String,
        /// Already-decoded object key.
        key: String,
        /// Decoded version identifier; explicit emptiness is retained.
        version_id: Option<String>,
    },
}
