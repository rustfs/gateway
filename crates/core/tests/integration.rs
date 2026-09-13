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

//! Consolidated integration-test entry point for `rustfs-gateway-core`.
//!
//! Responsible for: registering every core integration-test source in one Cargo target.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the core integration-test modules. Downstream: Cargo's test harness.

mod support;

#[path = "acl_contract.rs"]
mod acl_contract;

#[path = "acl_roundtrip.rs"]
mod acl_roundtrip;

#[path = "authz_consumption.rs"]
mod authz_consumption;

#[path = "bucketconfig_roundtrip.rs"]
mod bucketconfig_roundtrip;

#[path = "codec_binding.rs"]
mod codec_binding;

#[path = "committed_head.rs"]
mod committed_head;

#[path = "compile_fail.rs"]
mod compile_fail;

#[path = "configuration_error_declarations.rs"]
mod configuration_error_declarations;

#[path = "cors_roundtrip.rs"]
mod cors_roundtrip;

#[path = "dialect.rs"]
mod dialect;

#[path = "dialect_claims.rs"]
mod dialect_claims;

#[path = "dialect_claims_refusals.rs"]
mod dialect_claims_refusals;

#[path = "dto_cold_split.rs"]
mod dto_cold_split;

#[path = "encryption_roundtrip.rs"]
mod encryption_roundtrip;

#[path = "error_resolution.rs"]
mod error_resolution;

#[path = "ext_field_policy.rs"]
mod ext_field_policy;

#[path = "golden.rs"]
mod golden;

#[path = "hot_path.rs"]
mod hot_path;

#[path = "lifecycle_roundtrip.rs"]
mod lifecycle_roundtrip;

#[path = "limit_layering.rs"]
mod limit_layering;

#[path = "lock_roundtrip.rs"]
mod lock_roundtrip;

#[path = "not_configured_declarations.rs"]
mod not_configured_declarations;

#[path = "notification_roundtrip.rs"]
mod notification_roundtrip;

#[path = "operation_spec_semver.rs"]
mod operation_spec_semver;

#[path = "params_and_dispatch.rs"]
mod params_and_dispatch;

#[path = "policy_json_replay.rs"]
mod policy_json_replay;

#[path = "post_object.rs"]
mod post_object;

#[path = "precondition_range.rs"]
mod precondition_range;

#[path = "purity_guard.rs"]
mod purity_guard;

#[path = "range_part_table.rs"]
mod range_part_table;

#[path = "registration.rs"]
mod registration;

#[path = "replication_invariants.rs"]
mod replication_invariants;

#[path = "replication_roundtrip.rs"]
mod replication_roundtrip;

#[path = "response_override_safety.rs"]
mod response_override_safety;

#[path = "route_only.rs"]
mod route_only;

#[path = "route_sizes.rs"]
mod route_sizes;

#[path = "route_table.rs"]
mod route_table;

#[path = "rule_filter_boundaries.rs"]
mod rule_filter_boundaries;

#[path = "security_request_policy.rs"]
mod security_request_policy;

#[path = "select_restore_roundtrip.rs"]
mod select_restore_roundtrip;

#[path = "static_dispatch.rs"]
mod static_dispatch;

#[path = "tagging_contract.rs"]
mod tagging_contract;

#[path = "tagging_roundtrip.rs"]
mod tagging_roundtrip;

#[path = "tolerant_conditions.rs"]
mod tolerant_conditions;

#[path = "update_object_encryption_roundtrip.rs"]
mod update_object_encryption_roundtrip;

#[path = "upload_capability.rs"]
mod upload_capability;

#[path = "website_roundtrip.rs"]
mod website_roundtrip;

#[path = "xml_character_range.rs"]
mod xml_character_range;

#[path = "xml_parse_replay.rs"]
mod xml_parse_replay;
