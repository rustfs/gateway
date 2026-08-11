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

#[path = "authz_consumption.rs"]
mod authz_consumption;

#[path = "codec_binding.rs"]
mod codec_binding;

#[path = "compile_fail.rs"]
mod compile_fail;

#[path = "configuration_error_declarations.rs"]
mod configuration_error_declarations;

#[path = "dialect.rs"]
mod dialect;

#[path = "error_resolution.rs"]
mod error_resolution;

#[path = "golden.rs"]
mod golden;

#[path = "hot_path.rs"]
mod hot_path;

#[path = "limit_layering.rs"]
mod limit_layering;

#[path = "params_and_dispatch.rs"]
mod params_and_dispatch;

#[path = "precondition_range.rs"]
mod precondition_range;

#[path = "purity_guard.rs"]
mod purity_guard;

#[path = "registration.rs"]
mod registration;

#[path = "route_table.rs"]
mod route_table;

#[path = "static_dispatch.rs"]
mod static_dispatch;

#[path = "tagging_contract.rs"]
mod tagging_contract;

#[path = "tolerant_conditions.rs"]
mod tolerant_conditions;
