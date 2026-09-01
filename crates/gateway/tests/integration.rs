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
#[path = "chunked_allocations.rs"]
mod chunked_allocations;
#[path = "committed_head_runtime.rs"]
mod committed_head_runtime;
#[path = "committed_progress.rs"]
mod committed_progress;
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
#[path = "dialect_entry.rs"]
mod dialect_entry;
#[path = "error_context_filters.rs"]
mod error_context_filters;
#[path = "facade_probe.rs"]
mod facade_probe;
#[path = "file_transfer.rs"]
mod file_transfer;
#[path = "governor_runtime.rs"]
mod governor_runtime;
#[path = "governor_streaming.rs"]
mod governor_streaming;
#[path = "handler_panic.rs"]
mod handler_panic;
#[path = "ingest_assembly.rs"]
mod ingest_assembly;
#[path = "lifecycle_reachability.rs"]
mod lifecycle_reachability;
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
#[path = "payload_transport.rs"]
mod payload_transport;
#[path = "pipeline.rs"]
mod pipeline;
#[path = "precondition_contract.rs"]
mod precondition_contract;
#[path = "precondition_reachability.rs"]
mod precondition_reachability;
#[path = "refusal_order_guards.rs"]
mod refusal_order_guards;
#[path = "reject_rendering.rs"]
mod reject_rendering;
#[path = "replication_token.rs"]
mod replication_token;
#[path = "request_allocations.rs"]
mod request_allocations;
#[path = "response_invariants.rs"]
mod response_invariants;
#[path = "select_restore_intent.rs"]
mod select_restore_intent;
#[path = "self_held_http1.rs"]
mod self_held_http1;
#[path = "service_clone_allocations.rs"]
mod service_clone_allocations;
#[path = "service_concurrency.rs"]
mod service_concurrency;
#[path = "service_config.rs"]
mod service_config;
#[path = "sigv2_runtime.rs"]
mod sigv2_runtime;
#[path = "sse_runtime.rs"]
mod sse_runtime;
#[path = "streaming_request.rs"]
mod streaming_request;
#[path = "tagging_reachability.rs"]
mod tagging_reachability;
#[path = "throughput_request.rs"]
mod throughput_request;
#[path = "vhost_resolution.rs"]
mod vhost_resolution;
