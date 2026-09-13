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

//! The single-operation decode/encode and request-context diffs, compiled once per s3s revision the
//! migration seam is built against.
//!
//! Responsible for: binding each seam revision (`compat::s3s_9c4690d8`, the baseline oracle every
//! proof was first measured against, and `compat::s3s_f3e17541`, the revision RustFS main links) to
//! one compilation of the same harness and proofs, so every proof runs against the s3s service and
//! the seam conversion of that revision.
//! NOT responsible for: any proof itself (`operation_diff/*.rs`), or choosing which revision a
//! ruling follows (`migration_inventory/request_divergences.rs`).
//! Upstream: `rustfs_gateway_types::compat`. Downstream: none; test-only (rustfs/backlog#1762,
//! rustfs/backlog#1752).
//!
//! The harness and the proofs name s3s only as `super::s3s` / `super::oracle` and the seam only as
//! `super::seam`, so a proof that forgets the revision it runs under does not compile. A proof whose
//! answer genuinely depends on the revision branches on [`SEAM_REVISION`](self) of its compilation.

/// s3s `9c4690d8`, the baseline oracle.
#[path = "operation_diff"]
mod s3s_9c4690d8 {
    use rustfs_gateway_types::compat::OracleRevision;
    use rustfs_gateway_types::compat::s3s_9c4690d8 as seam;
    use s3s::dto as oracle;
    use seam::s3s;

    /// The revision this compilation measures.
    const SEAM_REVISION: OracleRevision = OracleRevision::Baseline;

    mod harness;
    use harness::*;

    mod context;
    mod put_object;
}

/// s3s `f3e17541`, the revision RustFS main links and the RustFS adapter converts through.
#[path = "operation_diff"]
#[allow(clippy::duplicate_mod)] // Deliberate: one harness source is compiled once per seam revision.
mod s3s_f3e17541 {
    use rustfs_gateway_types::compat::OracleRevision;
    use rustfs_gateway_types::compat::s3s_f3e17541 as seam;
    use s3s::dto as oracle;
    use seam::s3s;

    /// The revision this compilation measures.
    const SEAM_REVISION: OracleRevision = OracleRevision::Candidate;

    mod harness;
    use harness::*;

    mod context;
    mod put_object;
}
