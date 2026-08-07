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

//! The explicit contracts several operations share, one module per contract.
//!
//! Responsible for: mounting the shared modules, and stating the rule that governs them. Each
//! module names its member operations in a `//! Members:` line, and each member names the module
//! in its own `//! Shares:` line.
//! NOT responsible for: anything operation-specific. A rule that belongs to one operation belongs
//! in that operation's file, where changing it conflicts with nobody.
//! Upstream: nothing. Downstream: the operation modules under [`crate::ops`] that list it.
//!
//! # Why this directory is the counterweight to one operation per file
//!
//! One operation per file removes the merge conflict, and would — on its own — reintroduce the
//! defect it was meant to avoid: a rule copied into four files gets fixed in three of them. The
//! upstream case is s3s#499 against s3s#632, where one entity-tag rule lived in two places and the
//! two fixes contradicted each other.
//!
//! So a rule with more than one member lives here, in exactly one file, and the membership is
//! written down on both sides. Both directions matter. A module whose `//! Members:` lists an
//! operation that does not `use` it is a stale claim; an operation that `use`s a module without
//! being listed is a member nobody knew about, and it is the one that will be broken by the next
//! change to the shared rule.

pub mod bucket_region;
pub mod copy_source;
pub mod cors;
pub mod encryption;
pub mod etag;
pub mod lifecycle;
pub mod location_constraint;
pub mod pagination;
pub mod precondition;
pub mod tagging;
