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

//! One AWS operation per file: its spec, its security floor, its `Operation` implementation.
//!
//! Responsible for: mounting the operation modules, and nothing else. Each module declares exactly
//! one [`crate::op::Operation`] implementation, and no other module declares it.
//! NOT responsible for: handlers — a backend implements [`crate::handler::Handler`] in its own
//! crate — or the dto, which is generated into `rustfs-gateway-types`.
//! Upstream: `rustfs-gateway-types`' generated operation types, `rustfs-gateway-sig`'s
//! `OperationFloor`. Downstream: `crate::registry`, and every backend that registers one.
//!
//! # Why one operation per file
//!
//! Not for `grep` — nobody ever failed to find `GetObject`. It is the unit of parallel edit
//! conflict: two agents changing two operations produce no git conflict at all. The three modules
//! here are the whole set the model whitelist has admitted so far; the rest arrive with codegen,
//! in this shape.
//!
//! # What a P5 operation module has to contain
//!
//! A spec `static`, a floor `static`, one `impl Operation`, and one `impl HasOperation` for the
//! input type. Registration refuses the module if the spec or the floor is named differently from
//! the operation, or if the spec declares no authorisation action — so the four pieces cannot
//! drift apart quietly.

/// The explicit shared contracts. See `shared/mod.rs` for the two-way declaration rule.
pub mod shared;

pub mod abort_multipart_upload;
pub mod complete_multipart_upload;
pub mod copy_object;
pub mod create_bucket;
pub mod create_multipart_upload;
pub mod delete_bucket;
pub mod delete_bucket_cors;
pub mod delete_bucket_encryption;
pub mod delete_bucket_lifecycle;
pub mod delete_bucket_policy;
pub mod delete_bucket_replication;
pub mod delete_bucket_tagging;
pub mod delete_bucket_website;
pub mod delete_object;
pub mod delete_object_annotation;
pub mod delete_object_tagging;
pub mod delete_objects;
pub mod delete_public_access_block;
pub mod get_bucket_accelerate_configuration;
pub mod get_bucket_acl;
pub mod get_bucket_cors;
pub mod get_bucket_encryption;
pub mod get_bucket_lifecycle_configuration;
pub mod get_bucket_location;
pub mod get_bucket_logging;
pub mod get_bucket_notification_configuration;
pub mod get_bucket_policy;
pub mod get_bucket_policy_status;
pub mod get_bucket_replication;
pub mod get_bucket_request_payment;
pub mod get_bucket_tagging;
pub mod get_bucket_versioning;
pub mod get_bucket_website;
pub mod get_object;
pub mod get_object_acl;
pub mod get_object_attributes;
pub mod get_object_legal_hold;
pub mod get_object_lock_configuration;
pub mod get_object_retention;
pub mod get_object_tagging;
pub mod get_public_access_block;
pub mod head_bucket;
pub mod head_object;
pub mod list_buckets;
pub mod list_multipart_uploads;
pub mod list_object_versions;
pub mod list_objects;
pub mod list_objects_v2;
pub mod list_parts;
pub mod put_bucket_accelerate_configuration;
pub mod put_bucket_acl;
pub mod put_bucket_cors;
pub mod put_bucket_encryption;
pub mod put_bucket_lifecycle_configuration;
pub mod put_bucket_logging;
pub mod put_bucket_notification_configuration;
pub mod put_bucket_policy;
pub mod put_bucket_replication;
pub mod put_bucket_request_payment;
pub mod put_bucket_tagging;
pub mod put_bucket_versioning;
pub mod put_bucket_website;
pub mod put_object;
pub mod put_object_acl;
pub mod put_object_legal_hold;
pub mod put_object_lock_configuration;
pub mod put_object_retention;
pub mod put_object_tagging;
pub mod put_public_access_block;
pub mod rename_object;
pub mod restore_object;
pub mod select_object_content;
pub mod upload_part;
pub mod upload_part_copy;
