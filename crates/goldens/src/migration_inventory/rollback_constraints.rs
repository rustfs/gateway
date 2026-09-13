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

//! Decided rollback constraints: state a release can create that the previous release cannot read
//! back, and what an operator must do before rolling back across it.
//!
//! Responsible for: one entry per constraint — the state, what the previous gateway release does
//! with it, whether rolling back to the s3s stack is affected, the operator action, and the issues
//! that decided it (always including the writer-admission / rollback issue, rustfs/backlog#1768) —
//! and for refusing a register whose entry is malformed or not bound to its pinned test.
//! NOT responsible for: proving a constraint (its pinned test in `rollback_constraints/tests.rs`
//! does, against the real algorithm set and the pinned s3s model), persisted-byte refusals (the
//! parent module), or the metadata-writer switch itself (rustfs/backlog#1768).
//! Upstream: `rustfs_gateway_types::ChecksumAlgorithm`, and the fs reference backend's upload
//! record (`crates/fs/src/uploads.rs`). Downstream: the migration inventory report, and through it
//! `corpus-report` and the strict gate.
//!
//! # `rb-mpu-0001` (rustfs/gateway#751)
//!
//! rustfs-gateway 0.42.0 accepts the five checksum algorithms S3 added in 2026-04. A multipart
//! upload negotiated with one of them, or carrying part checksums under one, is state the previous
//! release cannot read. That release refuses the five headers on UploadPart and
//! CompleteMultipartUpload with `400 InvalidRequest`. Its fs reference backend resolves an upload
//! record's algorithm through the old five-name set and answers a storage error. Nothing can be
//! persisted in a form the previous release tolerates: its algorithm set is closed, and recording
//! the upload without its algorithm would silently drop the integrity claim the client made.
//!
//! Completed objects are unaffected: the fs backend persists no object checksum, and RustFS stores
//! the checksum through the s3s member it always had. Rolling back to the s3s stack is unaffected
//! too, because every admitted s3s revision names all five algorithms. Rolling back to an older
//! gateway release therefore requires draining the in-flight multipart uploads that use one of the
//! five: complete or abort them first (`ListMultipartUploads` lists them).

use core::fmt;

/// Source text of the pinned tests, so an entry cannot name a test that does not exist or that
/// does not carry its id.
const PINNED_TESTS: &str = include_str!("rollback_constraints/tests.rs");

/// The writer-admission and rollback issue every constraint answers to.
pub const ROLLBACK_AUTHORITY: &str = "https://github.com/rustfs/backlog/issues/1768";

/// One decided rollback constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackConstraint {
    /// Stable id, `rb-<family>-NNNN`; the pinned test's doc carries it as ``Constraint: `id` ``.
    pub id: &'static str,
    /// The release that can first create the state, as `crate@version`.
    pub introduced_by: &'static str,
    /// The state that release can create and the previous release cannot read back.
    pub state: &'static str,
    /// What the previous gateway release does with that state.
    pub previous_release: &'static str,
    /// What rolling back to the s3s stack does with it; starts with `unaffected` or `affected`.
    pub s3s_rollback: &'static str,
    /// What an operator must do before rolling back.
    pub operator_action: &'static str,
    /// Stable report label for the operator action.
    pub action_slug: &'static str,
    /// The issues that decided the constraint; must include [`ROLLBACK_AUTHORITY`].
    pub decisions: &'static [&'static str],
    /// The pinned test that proves the constraint.
    pub test: &'static str,
}

/// Every decided rollback constraint.
pub const ROLLBACK_CONSTRAINTS: [RollbackConstraint; 1] = [RollbackConstraint {
    id: "rb-mpu-0001",
    introduced_by: "rustfs-gateway@0.42.0",
    state: "an in-flight multipart upload negotiated with, or carrying part checksums under, SHA512, MD5, XXHASH64, \
            XXHASH3 or XXHASH128",
    previous_release: "refuses x-amz-checksum-sha512, -md5, -xxhash64, -xxhash3 and -xxhash128 on UploadPart and \
                       CompleteMultipartUpload with 400 InvalidRequest, and its fs reference backend reads an upload \
                       record naming one of them as a storage error (crates/fs/src/uploads.rs, UploadChecksum::decode)",
    s3s_rollback: "unaffected: every admitted s3s revision names all five algorithms, and RustFS stores them",
    operator_action: "before rolling back to a gateway release older than 0.42.0, drain in-flight multipart uploads \
                      that use one of the five algorithms (complete or abort them; ListMultipartUploads lists them), \
                      or roll back to the s3s stack instead",
    action_slug: "drain-in-flight-multipart-uploads-using-the-2026-04-checksums",
    decisions: &[ROLLBACK_AUTHORITY, "https://github.com/rustfs/gateway/issues/751"],
    test: "rollback_past_the_2026_04_checksums_requires_draining_their_multipart_uploads",
}];

/// A register entry that cannot stand as recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackConstraintError {
    /// The register is empty; the inventory always carries at least `rb-mpu-0001`.
    Empty,
    /// The id is not `rb-<family>-NNNN`.
    MalformedId(&'static str),
    /// Two entries share an id.
    DuplicateId(&'static str),
    /// A field that must say something is blank.
    EmptyField {
        /// The entry.
        id: &'static str,
        /// The blank field.
        field: &'static str,
    },
    /// The entry does not answer to [`ROLLBACK_AUTHORITY`].
    MissingAuthority(&'static str),
    /// The pinned test does not exist, or does not carry the entry's id.
    UnboundTest(&'static str),
}

impl fmt::Display for RollbackConstraintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("the rollback-constraint register is empty"),
            Self::MalformedId(id) => write!(formatter, "rollback constraint id `{id}` is not rb-<family>-NNNN"),
            Self::DuplicateId(id) => write!(formatter, "rollback constraint `{id}` is registered twice"),
            Self::EmptyField { id, field } => write!(formatter, "rollback constraint `{id}` has an empty {field}"),
            Self::MissingAuthority(id) => write!(formatter, "rollback constraint `{id}` does not cite {ROLLBACK_AUTHORITY}"),
            Self::UnboundTest(id) => write!(formatter, "rollback constraint `{id}` names no pinned test carrying its id"),
        }
    }
}

impl std::error::Error for RollbackConstraintError {}

/// The validated register.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackConstraintReport {
    entries: Vec<RollbackConstraint>,
}

impl RollbackConstraintReport {
    /// The validated entries, in register order.
    #[must_use]
    pub fn entries(&self) -> &[RollbackConstraint] {
        &self.entries
    }

    /// Renders the register, one line per constraint.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("rollback constraints: entries={} authority={ROLLBACK_AUTHORITY}\n", self.entries.len());
        for entry in &self.entries {
            let s3s = entry.s3s_rollback.split(':').next().unwrap_or(entry.s3s_rollback);
            out.push_str(&format!(
                "constraint {} introduced-by={} s3s-rollback={s3s} action={} test={}\n",
                entry.id, entry.introduced_by, entry.action_slug, entry.test
            ));
        }
        out
    }
}

/// Validates the real register against its pinned tests.
///
/// # Errors
///
/// The first malformed, duplicated, unauthorised or unbound entry.
pub fn build_rollback_constraints() -> Result<RollbackConstraintReport, RollbackConstraintError> {
    validate(&ROLLBACK_CONSTRAINTS, PINNED_TESTS)?;
    Ok(RollbackConstraintReport {
        entries: ROLLBACK_CONSTRAINTS.to_vec(),
    })
}

fn validate(entries: &[RollbackConstraint], pinned: &str) -> Result<usize, RollbackConstraintError> {
    if entries.is_empty() {
        return Err(RollbackConstraintError::Empty);
    }
    for (index, entry) in entries.iter().enumerate() {
        if !well_formed_id(entry.id) {
            return Err(RollbackConstraintError::MalformedId(entry.id));
        }
        if entries[..index].iter().any(|earlier| earlier.id == entry.id) {
            return Err(RollbackConstraintError::DuplicateId(entry.id));
        }
        for (field, value) in [
            ("introduced_by", entry.introduced_by),
            ("state", entry.state),
            ("previous_release", entry.previous_release),
            ("s3s_rollback", entry.s3s_rollback),
            ("operator_action", entry.operator_action),
            ("action_slug", entry.action_slug),
            ("test", entry.test),
        ] {
            if value.trim().is_empty() {
                return Err(RollbackConstraintError::EmptyField { id: entry.id, field });
            }
        }
        if !entry.decisions.contains(&ROLLBACK_AUTHORITY) {
            return Err(RollbackConstraintError::MissingAuthority(entry.id));
        }
        let carries_id = pinned.contains(&format!("Constraint: `{}`", entry.id));
        let defines_test = pinned.contains(&format!("fn {}()", entry.test));
        if !carries_id || !defines_test {
            return Err(RollbackConstraintError::UnboundTest(entry.id));
        }
    }
    Ok(entries.len())
}

fn well_formed_id(id: &str) -> bool {
    let mut parts = id.split('-');
    let (Some("rb"), Some(family), Some(number), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !family.is_empty()
        && family.bytes().all(|byte| byte.is_ascii_lowercase())
        && number.len() == 4
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests;
