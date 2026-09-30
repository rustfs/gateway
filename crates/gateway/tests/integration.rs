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

#[path = "action_rules_runtime.rs"]
mod action_rules_runtime;
#[path = "anonymous_chunked_upload.rs"]
mod anonymous_chunked_upload;
#[path = "anonymous_delegation_runtime.rs"]
mod anonymous_delegation_runtime;
#[path = "assembly.rs"]
mod assembly;
#[path = "assembly_order.rs"]
mod assembly_order;
#[path = "assembly_snapshot.rs"]
mod assembly_snapshot;
#[path = "authz_consumption.rs"]
mod authz_consumption;
#[path = "authz_contract.rs"]
mod authz_contract;
#[path = "authz_implementations.rs"]
mod authz_implementations;
#[path = "backend_reachability.rs"]
mod backend_reachability;
#[path = "body_literals.rs"]
mod body_literals;
#[path = "body_refusal_sentences.rs"]
mod body_refusal_sentences;
#[path = "bodyless_payload_digest.rs"]
mod bodyless_payload_digest;
#[path = "bucket_config_reachability.rs"]
mod bucket_config_reachability;
#[path = "checksum_omissions.rs"]
mod checksum_omissions;
#[path = "chunked_allocations.rs"]
mod chunked_allocations;
#[path = "classification.rs"]
mod classification;
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
#[path = "copy_source_reachability.rs"]
mod copy_source_reachability;
#[path = "cors_runtime.rs"]
mod cors_runtime;
#[path = "credential_runtime.rs"]
mod credential_runtime;
#[path = "custom_signature_verifier.rs"]
mod custom_signature_verifier;
#[path = "dialect_claims_runtime.rs"]
mod dialect_claims_runtime;
#[path = "dialect_entry.rs"]
mod dialect_entry;
#[path = "empty_headers_absent.rs"]
mod empty_headers_absent;
#[path = "empty_upload_without_length.rs"]
mod empty_upload_without_length;
#[path = "error_context_filters.rs"]
mod error_context_filters;
#[path = "extra_response_headers.rs"]
mod extra_response_headers;
#[path = "facade_probe.rs"]
mod facade_probe;
#[path = "file_responses.rs"]
mod file_responses;
#[path = "file_transfer.rs"]
mod file_transfer;
#[path = "governor_runtime.rs"]
mod governor_runtime;
#[path = "governor_streaming.rs"]
mod governor_streaming;
#[path = "handler_panic.rs"]
mod handler_panic;
#[path = "host_deadlines.rs"]
mod host_deadlines;
#[path = "host_resolve_replay.rs"]
mod host_resolve_replay;
#[path = "ingest_assembly.rs"]
mod ingest_assembly;
#[path = "lifecycle_reachability.rs"]
mod lifecycle_reachability;
#[path = "lock_encryption_reachability.rs"]
mod lock_encryption_reachability;
#[path = "macro_scenarios.rs"]
mod macro_scenarios;
#[path = "middleware.rs"]
mod middleware;
#[path = "monomorphic.rs"]
mod monomorphic;
#[path = "naming_policy.rs"]
mod naming_policy;
#[path = "object_attributes_etag.rs"]
mod object_attributes_etag;
#[path = "object_lock_intent.rs"]
mod object_lock_intent;
#[path = "observer_panic.rs"]
mod observer_panic;
#[path = "operation_registry_hot_update.rs"]
mod operation_registry_hot_update;
#[path = "operation_registry_wire.rs"]
mod operation_registry_wire;
#[path = "patch_layer_landings.rs"]
mod patch_layer_landings;
#[path = "payload_transport.rs"]
mod payload_transport;
#[path = "perf_evidence.rs"]
mod perf_evidence;
#[path = "pipeline.rs"]
mod pipeline;
#[path = "policy_reachability.rs"]
mod policy_reachability;
#[path = "post_object_legacy_fields.rs"]
mod post_object_legacy_fields;
#[path = "post_object_legacy_form.rs"]
mod post_object_legacy_form;
#[path = "post_object_runtime.rs"]
mod post_object_runtime;
#[path = "post_object_streaming.rs"]
mod post_object_streaming;
#[path = "precondition_contract.rs"]
mod precondition_contract;
#[path = "precondition_reachability.rs"]
mod precondition_reachability;
#[path = "presigned_put.rs"]
mod presigned_put;
#[path = "raw_path_fallback.rs"]
mod raw_path_fallback;
#[path = "refusal_order_guards.rs"]
mod refusal_order_guards;
#[path = "reject_rendering.rs"]
mod reject_rendering;
#[path = "replica_put.rs"]
mod replica_put;
#[path = "replication_token.rs"]
mod replication_token;
#[path = "request_allocations.rs"]
mod request_allocations;
#[path = "request_context_runtime.rs"]
mod request_context_runtime;
#[path = "response_invariants.rs"]
mod response_invariants;
#[path = "response_stream_termination.rs"]
mod response_stream_termination;
#[path = "rustfs_addressing.rs"]
mod rustfs_addressing;
#[path = "rustfs_key_floor.rs"]
mod rustfs_key_floor;
#[path = "rustfs_selection.rs"]
mod rustfs_selection;
#[path = "rustfs_vhost.rs"]
mod rustfs_vhost;
#[path = "scope_refusals.rs"]
mod scope_refusals;
#[path = "select_frame_records.rs"]
mod select_frame_records;
#[path = "select_restore_intent.rs"]
mod select_restore_intent;
#[path = "select_restore_reachability.rs"]
mod select_restore_reachability;
#[path = "self_held_http1.rs"]
mod self_held_http1;
#[path = "service_clone_allocations.rs"]
mod service_clone_allocations;
#[path = "service_concurrency.rs"]
mod service_concurrency;
#[path = "service_config.rs"]
mod service_config;
#[path = "signed_header_reading.rs"]
mod signed_header_reading;
#[path = "signing_services.rs"]
mod signing_services;
#[path = "sigv2_runtime.rs"]
mod sigv2_runtime;
#[path = "sse_runtime.rs"]
mod sse_runtime;
#[path = "steady_state_allocations.rs"]
mod steady_state_allocations;
#[path = "streaming_request.rs"]
mod streaming_request;
#[path = "streaming_without_length.rs"]
mod streaming_without_length;
#[path = "tagging_reachability.rs"]
mod tagging_reachability;
#[path = "throughput_request.rs"]
mod throughput_request;
#[path = "tracing_events.rs"]
mod tracing_events;
#[path = "unknown_checksum_algorithms.rs"]
mod unknown_checksum_algorithms;
#[path = "unread_body_refusal.rs"]
mod unread_body_refusal;
#[path = "upload_object_ceiling.rs"]
mod upload_object_ceiling;
#[path = "verified_scope_runtime.rs"]
mod verified_scope_runtime;
#[path = "vhost_resolution.rs"]
mod vhost_resolution;
