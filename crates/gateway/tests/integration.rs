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

//! Consolidated integration-test entry point for `rustfs-gateway`.
//!
//! Responsible for: registering every gateway integration-test source in one Cargo target.
//! NOT responsible for: test behavior or production implementation.
//! Upstream: the gateway integration-test modules. Downstream: Cargo's test harness.

mod support;

#[path = "assembly.rs"]
mod assembly;
#[path = "assembly_order.rs"]
mod assembly_order;
#[path = "authz_consumption.rs"]
mod authz_consumption;
#[path = "authz_contract.rs"]
mod authz_contract;
#[path = "authz_implementations.rs"]
mod authz_implementations;
#[path = "backend_reachability.rs"]
mod backend_reachability;
#[path = "compat_aliases.rs"]
mod compat_aliases;
#[path = "compile_fail.rs"]
mod compile_fail;
#[path = "connection_teardown.rs"]
mod connection_teardown;
#[path = "cors_runtime.rs"]
mod cors_runtime;
#[path = "credential_runtime.rs"]
mod credential_runtime;
#[path = "custom_signature_verifier.rs"]
mod custom_signature_verifier;
#[path = "error_context_filters.rs"]
mod error_context_filters;
#[path = "facade_probe.rs"]
mod facade_probe;
#[path = "governor_runtime.rs"]
mod governor_runtime;
#[path = "handler_panic.rs"]
mod handler_panic;
#[path = "middleware.rs"]
mod middleware;
#[path = "monomorphic.rs"]
mod monomorphic;
#[path = "naming_policy.rs"]
mod naming_policy;
#[path = "object_lock_intent.rs"]
mod object_lock_intent;
#[path = "patch_layer_landings.rs"]
mod patch_layer_landings;
#[path = "pipeline.rs"]
mod pipeline;
#[path = "precondition_contract.rs"]
mod precondition_contract;
#[path = "refusal_order_guards.rs"]
mod refusal_order_guards;
#[path = "reject_rendering.rs"]
mod reject_rendering;
#[path = "replication_token.rs"]
mod replication_token;
#[path = "select_restore_intent.rs"]
mod select_restore_intent;
#[path = "service_clone_allocations.rs"]
mod service_clone_allocations;
#[path = "service_concurrency.rs"]
mod service_concurrency;
#[path = "service_config.rs"]
mod service_config;
#[path = "sse_runtime.rs"]
mod sse_runtime;
#[path = "vhost_resolution.rs"]
mod vhost_resolution;
