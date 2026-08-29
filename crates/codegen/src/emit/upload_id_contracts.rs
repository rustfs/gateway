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

//! Generated upload-id capability inputs for the private types exchange.
//!
//! Responsible for: rendering the typed resource-ownership policy consumed while resolving an
//! upload id. NOT responsible for: exposing raw upload ids or granting caller-selectable policy.
//! Upstream: typed overlay contract rules. Downstream: the private upload-id exchange in types.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::{ContractRule, ContractValue, MutationDimension, UploadIdCapabilityScopeValue};

use super::dto::LICENSE;
use super::runtime_contracts::{unique, wrong_type};

pub(super) const fn quirk_toml_entry(value: UploadIdCapabilityScopeValue) -> &'static str {
    match value {
        UploadIdCapabilityScopeValue::BucketAndKey => "contract_value = \"bucket_and_key\"\n",
        UploadIdCapabilityScopeValue::UploadIdOnly => "contract_value = \"upload_id_only\"\n",
    }
}

/// Renders the private upload-id capability contract module.
pub fn render(rules: &BTreeMap<String, ContractRule>) -> Result<String, String> {
    let scope = unique(rules, MutationDimension::UploadIdCapabilityScope)?;
    let requires_bucket_and_key = match scope {
        ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::BucketAndKey) => true,
        ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::UploadIdOnly) => false,
        _ => return Err(wrong_type(MutationDimension::UploadIdCapabilityScope)),
    };

    let mut out = String::from(LICENSE);
    out.push_str("\n// Generated upload-id capability contract input.\n\n");
    writeln!(
        out,
        "/// Whether a resolved upload id must belong to the requested bucket and key.\npub(super) const UPLOAD_ID_REQUIRES_BUCKET_AND_KEY: bool = {requires_bucket_and_key};"
    )
    .expect("writing to String cannot fail");
    Ok(out)
}
