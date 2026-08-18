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

//! The hand-written protocol exception source.
//!
//! Responsible for: the operation whitelist, the scalar vocabulary map, per-operation and
//! per-shape wire overrides, and the quirk records with their evidence — merged from one file per
//! operation family, with every cross-file collision reported as a load failure.
//! NOT responsible for: applying any of it (that is [`mod@crate::lower`]).
//! Upstream: [`crate::toml_lite`]. Downstream: [`mod@crate::lower`].
//!
//! Everything a human is allowed to decide about the wire lives here and nowhere else. The
//! Smithy model is read-only and every artefact below the overlay is generated, so this is the
//! only file an agent may edit to change wire behaviour.
//!
//! # Why the overlay is a directory of family files
//!
//! One file per operation family is the unit of parallel edit conflict, exactly as one operation
//! per file is in `rustfs-gateway-core`. Sixteen agents landing sixteen families into one
//! `operations.toml` would conflict on every merge; landing them into
//! `overlays/ops/<family>.toml` produces no textual conflict at all.
//!
//! What that trades away is the single file in which a duplicate was previously impossible: with
//! ten files, two families can both claim `CopyObject` and neither diff shows it. So every merge
//! here is collision-checked and a collision is a hard failure naming **both** files. A last-write
//! -wins merge would silently disable whichever rule lost, which is the worst outcome a
//! hand-written file can have.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::ir::{ChecksumAlgo, EmptyValue, Quirk};
use crate::toml_lite::{self, Toml};
use error_status::ERROR_STATUS_FILE;

mod codec;
mod codec_inputs;
mod contract_values;
mod cors_contract_inputs;
mod cors_contract_values;
mod error_status;
mod mutation_dimension;
mod naming_contract_inputs;
mod precondition_contract_inputs;
mod precondition_contract_values;
mod quirks;
mod route;
mod select_restore_contract_inputs;
mod select_restore_contract_values;

pub use codec::{
    AclChannelPolicyValue, AclOwnerPolicyValue, BooleanSpellingValue, BucketStatePreconditionValue, CodecRule, CodecValue,
    ConditionConflictValue, ConditionalWildcardParseValue, ConditionalWildcardWriteValue, ConditionalWriteOrderValue,
    CopyValidatorScopeValue, DeleteAbsentPolicyValue, ErrorSecretFlowValue, EtagComparisonStrengthValue, HeaderToleranceValue,
    IfMatchAbsentPolicyValue, IfMatchDatePrecedenceValue, IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, SourceRule,
    TemporalRelationValue, UnknownElementPolicyValue, WireFormValue,
};
pub use contract_values::{
    AbsoluteOrUncPolicyValue, CaseFoldingValue, ClientIngressForbiddenCodepointsValue, ConditionFailureDetailValue, ContractRule,
    ContractValue, CopySourceGuardOrderValue, CopySourceIfMatchMissValue, DecodedUtf8Value, DefaultBucketValidatorValue,
    DefaultSlashPolicyValue, ErrorRootNamespaceValue, HeadBodyPolicyValue, PercentDecodePassesValue,
    ResidualEncodedDangerousValue, StoredLegacyControlPolicyValue, TraversalSegmentDelimitersValue, UnicodeNormalizationValue,
    ValidatorAuthorityValue, ValidatorReplaceabilityValue,
};
pub use cors_contract_values::*;
pub use error_status::ErrorStatus;
pub use mutation_dimension::MutationDimension;
pub use precondition_contract_values::*;
pub use route::{ROUTE_FILE, ShadowingDecl};
pub use select_restore_contract_values::*;

/// Whether a protocol record is a mechanically mutable quirk or a non-mutable contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleClassification {
    /// A typed rule whose value is consumed by generation and may be changed in memory.
    Mutable,
    /// A case-covered protocol contract that is not an input to generation.
    Contract,
}

/// Everything the overlay files declare.
#[derive(Debug, Default)]
pub struct Overlay {
    /// Operations that are generated.
    pub include: Vec<String>,
    /// Operations that are deliberately not generated yet, with the reason.
    pub deferred: BTreeMap<String, String>,
    /// Smithy shape local name to IR scalar spelling.
    pub scalars: BTreeMap<String, String>,
    /// The error code to HTTP status authority, in declaration order.
    pub error_status: Vec<ErrorStatus>,
    /// Per-operation overrides.
    pub ops: BTreeMap<String, OpOverlay>,
    /// Per-shape overrides.
    pub shapes: BTreeMap<String, ShapeOverlay>,
    /// Quirk records, keyed by id.
    pub quirks: BTreeMap<String, Quirk>,
    /// Typed quirk rules that directly control codec generation, keyed by quirk id.
    pub codec_rules: BTreeMap<String, CodecRule>,
    /// Typed mutation sources whose current values come from lowered operation IR.
    pub source_rules: BTreeMap<String, SourceRule>,
    /// Typed runtime contract inputs consumed by generated core code.
    pub contract_rules: BTreeMap<String, ContractRule>,
    /// Exhaustive classification for every protocol record, keyed by stable id.
    pub classifications: BTreeMap<String, RuleClassification>,
    /// The reviewed cross-precedence shadowing record, in `route.toml` order.
    pub shadowing: Vec<ShadowingDecl>,
}

/// Per-operation overrides. Every field is optional; absent means "take the model's answer".
#[derive(Debug, Default, Clone)]
pub struct OpOverlay {
    /// Route table position.
    pub precedence: Option<u32>,
    /// Override for what the path addresses.
    pub target: Option<String>,
    /// Override for the reverse-index path shape.
    pub path_shape: Option<String>,
    /// Override for the default success status.
    pub success_status: Option<u16>,
    /// Other legitimate success statuses.
    pub alt_success_statuses: Vec<u16>,
    /// Query keys that must be present for this route to match.
    ///
    /// The model's `http` uri pins a literal query for some operations (`?uploads`, `?delete`)
    /// and not for others: `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` and
    /// `ListParts` are spelled `/{Bucket}/{Key+}?x-id=<Operation>`, and `x-id` is inert. Without
    /// this field those four selectors would be indistinguishable from `PutObject`, `GetObject`
    /// and `DeleteObject`, so the discriminator is declared here rather than inferred.
    pub query_present: Vec<String>,
    /// Query keys that must be absent for this route to match.
    pub query_absent: Vec<String>,
    /// Headers that must be present for this route to match.
    pub header_present: Vec<String>,
    /// Headers that must be absent for this route to match.
    pub header_absent: Vec<String>,
    /// Authentication requirement.
    pub auth_requirement: Option<String>,
    /// IAM action.
    pub auth_action: Option<String>,
    /// Whether presigned URLs may reach it.
    pub auth_presigned: Option<bool>,
    /// SigV4 credential-scope service.
    pub auth_service: Option<String>,
    /// Request body kind, buffering and cap.
    pub request: PayloadOverlay,
    /// Response body kind, buffering and cap.
    pub response: PayloadOverlay,
    /// Force the `httpChecksumRequired` answer.
    pub http_checksum_required: Option<bool>,
    /// Override the accepted request checksum algorithms.
    pub request_algorithms: Option<Vec<ChecksumAlgo>>,
    /// Override the produced response checksum algorithms.
    pub response_algorithms: Option<Vec<ChecksumAlgo>>,
    /// Wire root element of the request body.
    pub request_root: Option<String>,
    /// Additional accepted request root names.
    pub request_root_aliases: Vec<String>,
    /// Wire root element of the response body.
    pub response_root: Option<String>,
    /// Namespace policy.
    pub xmlns: Option<String>,
    /// Force the unwrapped-output answer.
    pub unwrapped_output: Option<bool>,
    /// Wire order of the response root's children.
    pub element_order: Vec<String>,
    /// Members percent-encoded under `encoding-type=url`.
    pub url_encoded_fields: Vec<String>,
    /// Accept a bare literal body.
    pub body_literal: Option<bool>,
    /// Per member empty-value policy for the response root.
    pub empty_value: Vec<(String, EmptyValue)>,
    /// The unconfigured-subresource 404 code.
    pub not_configured: Option<String>,
    /// Whether an `Error` body may follow a flushed 200.
    pub allows_error_after_200: Option<bool>,
    /// Error codes this operation can produce.
    pub error_codes: Vec<String>,
    /// Operation-scoped quirk ids.
    pub quirk_refs: Vec<String>,
    /// The GET whose headers a HEAD mirrors.
    pub head_mirrors: Option<String>,
    /// Input members that are not part of the supported surface.
    pub input_drop: Vec<String>,
    /// Input members promoted to required.
    pub input_required: Vec<String>,
    /// Input members kept on the hot path.
    pub input_hot: Vec<String>,
    /// Output members that are not part of the supported surface.
    pub output_drop: Vec<String>,
    /// Output members promoted to required.
    pub output_required: Vec<String>,
    /// Output members kept on the hot path.
    pub output_hot: Vec<String>,
    /// Field-level overrides and synthesized fields.
    pub fields: Vec<FieldOverlay>,
}

/// Body handling overrides for one direction.
#[derive(Debug, Default, Clone)]
pub struct PayloadOverlay {
    /// Body kind.
    pub kind: Option<String>,
    /// Buffering discipline.
    pub buffering: Option<String>,
    /// Hard size cap.
    pub max_bytes: Option<u64>,
}

/// Per-shape overrides for a nested structure.
#[derive(Debug, Default, Clone)]
pub struct ShapeOverlay {
    /// Wire order of the shape's children.
    pub element_order: Vec<String>,
    /// Per member empty-value policy.
    pub empty_value: Vec<(String, EmptyValue)>,
    /// Members promoted to required.
    pub required: Vec<String>,
    /// Members kept on the hot path.
    pub hot: Vec<String>,
    /// Members dropped from the supported surface.
    pub drop: Vec<String>,
    /// XML attributes written on the element this shape occupies.
    pub attributes: Vec<AttributeOverlay>,
    /// Field-level overrides.
    pub fields: Vec<FieldOverlay>,
}

/// One XML attribute declared on the element a shape occupies.
///
/// The frozen IR reserves `xml.attributes` and names `xsi:type on Grantee` as the case it exists
/// for; this is the hand-written source that fills it. An attribute is either a fixed string —
/// the `xmlns:xsi` declaration AWS writes beside the discriminator — or one of the shape's own
/// members, which then stops being written as a child element.
#[derive(Debug, Default, Clone)]
pub struct AttributeOverlay {
    /// The element carrying the attribute. Defaults to the shape's own name.
    pub element: Option<String>,
    /// Attribute name, prefix included.
    pub name: String,
    /// The member whose value the attribute carries, when it is not a constant.
    pub field: Option<String>,
    /// The fixed value, when the attribute is not a member.
    pub value: Option<String>,
}

/// One field override, or one synthesized field.
#[derive(Debug, Default, Clone)]
pub struct FieldOverlay {
    /// `input` or `output`; ignored for shapes.
    pub side: Side,
    /// Member name.
    pub name: String,
    /// Whether the field has no model member behind it.
    pub synthesize: bool,
    /// Insert a synthesized field after this member.
    pub after: Option<String>,
    /// Override the wire name.
    pub wire_name: Option<String>,
    /// Override the binding.
    pub binding: Option<String>,
    /// Override the type.
    pub ty: Option<String>,
    /// Override the hot/cold split.
    pub hot: Option<bool>,
    /// Override the requirement.
    pub required: Option<bool>,
    /// Error code returned when a required field is missing.
    pub missing_error: Option<String>,
    /// String-valued wire default.
    pub default_string: Option<String>,
    /// Integer-valued wire default.
    pub default_int: Option<i64>,
    /// Boolean-valued wire default.
    pub default_bool: Option<bool>,
    /// `Empty`, `Default`, `ValueEquals` or `RequestField`.
    pub omit_when: Option<String>,
    /// Value for a `ValueEquals` suppression.
    pub omit_when_value: Option<String>,
    /// Request field consulted by a `RequestField` suppression.
    pub omit_when_field: Option<String>,
    /// Value of that request field which suppresses emission.
    pub omit_when_equals: Option<String>,
    /// Field-scoped quirk ids.
    pub quirks: Vec<String>,
}

/// Which half of an operation a field override applies to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The request.
    #[default]
    Input,
    /// The response.
    Output,
}

/// Which file first declared a name, so a second declaration can name both.
pub(super) type Origins = BTreeMap<String, String>;

/// The one cross-family file: the Smithy shape name to IR scalar vocabulary.
const SCALARS_FILE: &str = "scalars.toml";

/// The directory holding one operation-family file.
const OPS_DIR: &str = "ops";

/// The directory holding one quirk-family file.
const QUIRKS_DIR: &str = "quirks";

impl Overlay {
    /// Loads an overlay directory: `scalars.toml` and `error-status.toml`, then every
    /// `ops/*.toml`, then every `quirks/*.toml`, merged in file-name order.
    ///
    /// # Errors
    ///
    /// [`Error::Overlay`] when a directory is missing or empty, when a file is not readable, or
    /// when two family files declare the same operation, shape or quirk. A collision names both
    /// files: with sixteen families being written in parallel it is the failure that actually
    /// happens, and "declared twice" without the two paths is not actionable.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut overlay = Overlay::default();
        overlay.read_scalars(&dir.join(SCALARS_FILE))?;
        overlay.read_error_status(&dir.join(ERROR_STATUS_FILE))?;

        let mut include_origin = Origins::new();
        let mut deferred_origin = Origins::new();
        let mut op_origin = Origins::new();
        let mut shape_origin = Origins::new();
        for path in family_files(dir, OPS_DIR)? {
            overlay.read_operations(&path, &mut include_origin, &mut deferred_origin, &mut op_origin, &mut shape_origin)?;
        }

        let mut quirk_origin = Origins::new();
        for path in family_files(dir, QUIRKS_DIR)? {
            overlay.read_quirks(&path, &mut quirk_origin)?;
        }

        overlay.shadowing = route::read(&dir.join(ROUTE_FILE))?;

        overlay.check(&include_origin, &deferred_origin)?;
        Ok(overlay)
    }

    /// Every quirk id declared, sorted.
    pub fn quirk_ids(&self) -> Vec<String> {
        self.quirks.keys().cloned().collect()
    }

    /// Reads the one cross-family file. It carries `[scalar]` and nothing else.
    ///
    /// The scalar vocabulary is a decision about the whole surface — `ETag` renders the same way
    /// whichever family reads it — so it has one home rather than being merged out of ten files
    /// where two families could disagree about one shape.
    fn read_scalars(&mut self, path: &Path) -> Result<()> {
        let text = read(path)?;
        let doc = toml_lite::parse(&path.display().to_string(), &text)?;
        for key in ["include", "deferred", "op", "shape", "quirk"] {
            if doc.get(key).is_some() {
                return Err(Error::Overlay(format!(
                    "{SCALARS_FILE} carries `{key}`; it holds `[scalar]` alone, and everything \
                     per-operation belongs in `{OPS_DIR}/<family>.toml`"
                )));
            }
        }
        let Some(Toml::Table(entries)) = doc.get("scalar") else {
            return Err(Error::Overlay(format!("{SCALARS_FILE} declares no `[scalar]` table")));
        };
        for (name, value) in entries {
            let spelling = value
                .as_str()
                .ok_or_else(|| Error::Overlay(format!("scalar `{name}` must be a string")))?;
            self.scalars.insert(name.clone(), spelling.to_owned());
        }
        Ok(())
    }

    /// Reads the other cross-family file: the error code to HTTP status authority.
    ///
    /// Sharding it per family would let two families answer differently for one code, and a code
    /// means one status whoever raises it — so, like the scalar vocabulary, it has one home.
    fn read_error_status(&mut self, path: &Path) -> Result<()> {
        let text = read(path)?;
        let doc = toml_lite::parse(&path.display().to_string(), &text)?;
        self.error_status = error_status::read(&doc)?;
        Ok(())
    }

    fn read_operations(
        &mut self,
        path: &Path,
        include_origin: &mut Origins,
        deferred_origin: &mut Origins,
        op_origin: &mut Origins,
        shape_origin: &mut Origins,
    ) -> Result<()> {
        let file = label(path);
        let text = read(path)?;
        let doc = toml_lite::parse(&path.display().to_string(), &text)?;

        if doc.get("scalar").is_some() {
            return Err(Error::Overlay(format!(
                "{file} carries `[scalar]`; the scalar vocabulary is cross-family and lives in \
                 `{SCALARS_FILE}` alone"
            )));
        }
        if doc.get("shadowing").is_some() {
            return Err(Error::Overlay(format!(
                "{file} carries `[[shadowing]]`; a shadowing pair spans two families by \
                 construction and lives in `{ROUTE_FILE}` alone"
            )));
        }
        if let Some(include) = doc.get("include") {
            for op in include.string_array("include")? {
                claim(include_origin, &op, &file, "included")?;
                self.include.push(op);
            }
        }
        for group in array_of_tables(&doc, "deferred") {
            let reason = group
                .get("reason")
                .and_then(Toml::as_str)
                .ok_or_else(|| Error::Overlay(format!("{file}: every [[deferred]] group needs a `reason`")))?;
            let operations = group
                .get("operations")
                .ok_or_else(|| Error::Overlay(format!("{file}: every [[deferred]] group needs `operations`")))?
                .string_array("deferred.operations")?;
            for op in operations {
                claim(deferred_origin, &op, &file, "deferred")?;
                self.deferred.insert(op, reason.to_owned());
            }
        }
        if let Some(Toml::Table(entries)) = doc.get("op") {
            for (name, table) in entries {
                claim(op_origin, name, &file, "declared as `[op.<Operation>]`")?;
                self.ops.insert(name.clone(), op_overlay(name, table)?);
            }
        }
        if let Some(Toml::Table(entries)) = doc.get("shape") {
            for (name, table) in entries {
                claim(shape_origin, name, &file, "declared as `[shape.<Shape>]`")?;
                self.shapes.insert(name.clone(), shape_overlay(name, table)?);
            }
        }
        Ok(())
    }

    /// Checks the overlay against itself: id shapes, evidence presence, and no operation listed
    /// both as included and deferred.
    fn check(&self, include_origin: &Origins, deferred_origin: &Origins) -> Result<()> {
        for op in &self.include {
            if self.deferred.contains_key(op) {
                let included = include_origin.get(op).map_or("?", String::as_str);
                let deferred = deferred_origin.get(op).map_or("?", String::as_str);
                return Err(Error::Overlay(format!(
                    "`{op}` is included by `{included}` and deferred by `{deferred}`; one family owns \
                     an operation, and it decides which of the two it is"
                )));
            }
        }
        let included: std::collections::BTreeSet<&str> = self.include.iter().map(String::as_str).collect();
        for decl in &self.shadowing {
            for (role, op) in [("winner", &decl.winner), ("shadowed", &decl.shadowed)] {
                if !included.contains(op.as_str()) {
                    return Err(Error::Overlay(format!(
                        "shadowing declaration `{} over {}` names `{op}` as its {role}, and no family \
                         `include`s it; only an included operation emits a route row, so the pair \
                         describes an overlap that cannot happen",
                        decl.winner, decl.shadowed
                    )));
                }
            }
        }
        for (id, quirk) in &self.quirks {
            if !is_quirk_id(id) {
                return Err(Error::Overlay(format!("quirk id `{id}` does not match q-<slug>-NNNN")));
            }
            if quirk.evidence.is_empty() {
                return Err(Error::Overlay(format!("quirk `{id}` has no evidence")));
            }
            if quirk.cases.is_empty() {
                return Err(Error::Overlay(format!("quirk `{id}` references no conformance case")));
            }
            if quirk.summary.chars().count() < 16 {
                return Err(Error::Overlay(format!("quirk `{id}` summary is too short to be useful")));
            }
            for case in &quirk.cases {
                if !is_case_id(case) {
                    return Err(Error::Overlay(format!("quirk `{id}` references malformed case id `{case}`")));
                }
            }
        }
        Ok(())
    }
}

/// Whether a string is a well-formed quirk id.
pub fn is_quirk_id(id: &str) -> bool {
    matches_id(id, "q-")
}

/// Whether a string is a well-formed conformance case id.
pub fn is_case_id(id: &str) -> bool {
    matches_id(id, "c-")
}

fn matches_id(id: &str, prefix: &str) -> bool {
    let Some(rest) = id.strip_prefix(prefix) else {
        return false;
    };
    let Some((slug, number)) = rest.rsplit_once('-') else {
        return false;
    };
    let slug_ok = !slug.is_empty()
        && slug
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    let number_ok = number.len() == 4 && number.chars().all(|c| c.is_ascii_digit());
    slug_ok && number_ok
}

pub(super) fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))
}

/// How a file is named in a diagnostic: `ops/object.toml`, not the caller's absolute path.
///
/// A collision message has to be pasteable into an editor and comparable between two machines, and
/// an absolute path under somebody's home directory is neither.
pub(super) fn label(path: &Path) -> String {
    let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let parent = path
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned());
    match (parent, file) {
        (Some(dir), Some(name)) => format!("{dir}/{name}"),
        (None, Some(name)) => name,
        _ => path.display().to_string(),
    }
}

/// Every `*.toml` directly under `<dir>/<sub>`, in file-name order.
///
/// Sorted rather than in readdir order: the merge is order-independent by construction (a
/// collision is refused rather than resolved), but a run whose file order depends on the
/// filesystem would make an unrelated failure message reorder itself between machines.
fn family_files(dir: &Path, sub: &str) -> Result<Vec<std::path::PathBuf>> {
    let directory = dir.join(sub);
    let entries = std::fs::read_dir(&directory).map_err(|e| Error::io(directory.display().to_string(), e))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(directory.display().to_string(), e))?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }
    if files.is_empty() {
        return Err(Error::Overlay(format!(
            "overlay directory `{sub}/` holds no `.toml` file; every family file is one, and an \
             empty directory means the overlay was moved rather than sharded"
        )));
    }
    files.sort();
    Ok(files)
}

/// Records that `file` declares `name`, or fails naming the file that already did.
pub(super) fn claim(origins: &mut Origins, name: &str, file: &str, what: &str) -> Result<()> {
    if let Some(first) = origins.get(name) {
        return Err(Error::Overlay(format!(
            "`{name}` is {what} by both `{first}` and `{file}`; one family owns it, and merging the \
             two would silently drop whichever rule lost"
        )));
    }
    origins.insert(name.to_owned(), file.to_owned());
    Ok(())
}

pub(super) fn array_of_tables<'a>(doc: &'a Toml, key: &str) -> Vec<&'a Toml> {
    doc.get(key)
        .and_then(Toml::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

pub(super) fn required_str(table: &Toml, key: &str, what: &str) -> Result<String> {
    table
        .get(key)
        .and_then(Toml::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Overlay(format!("{what}: missing `{key}`")))
}

fn opt_str(table: &Toml, key: &str) -> Option<String> {
    table.get(key).and_then(Toml::as_str).map(str::to_owned)
}

fn opt_bool(table: &Toml, key: &str) -> Option<bool> {
    table.get(key).and_then(Toml::as_bool)
}

fn opt_u32(table: &Toml, key: &str) -> Option<u32> {
    table.get(key).and_then(Toml::as_int).and_then(|i| u32::try_from(i).ok())
}

fn list(table: &Toml, key: &str, what: &str) -> Result<Vec<String>> {
    match table.get(key) {
        Some(v) => v.string_array(&format!("{what}.{key}")),
        None => Ok(Vec::new()),
    }
}

fn empty_value_table(table: &Toml, what: &str) -> Result<Vec<(String, EmptyValue)>> {
    let Some(Toml::Table(entries)) = table.get("empty_value") else {
        return Ok(Vec::new());
    };
    entries
        .iter()
        .map(|(name, value)| {
            let policy = value
                .as_str()
                .and_then(EmptyValue::parse)
                .ok_or_else(|| Error::Overlay(format!("{what}.empty_value.{name} must be `emit` or `omit`")))?;
            Ok((name.clone(), policy))
        })
        .collect()
}

fn algorithms(table: &Toml, key: &str, what: &str) -> Result<Option<Vec<ChecksumAlgo>>> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let names = value.string_array(&format!("{what}.{key}"))?;
    names
        .iter()
        .map(|n| {
            ChecksumAlgo::parse(n).ok_or_else(|| Error::Overlay(format!("{what}.{key}: `{n}` is not an IR checksum algorithm")))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn payload_overlay(table: &Toml, prefix: &str) -> PayloadOverlay {
    PayloadOverlay {
        kind: opt_str(table, &format!("{prefix}_kind")),
        buffering: opt_str(table, &format!("{prefix}_buffering")),
        max_bytes: table
            .get(&format!("{prefix}_max_bytes"))
            .and_then(Toml::as_int)
            .and_then(|i| u64::try_from(i).ok()),
    }
}

fn op_overlay(name: &str, table: &Toml) -> Result<OpOverlay> {
    let what = format!("op.{name}");
    Ok(OpOverlay {
        precedence: opt_u32(table, "precedence"),
        target: opt_str(table, "target"),
        path_shape: opt_str(table, "path_shape"),
        success_status: opt_u32(table, "success_status").and_then(|v| u16::try_from(v).ok()),
        alt_success_statuses: table
            .get("alt_success_statuses")
            .and_then(Toml::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Toml::as_int)
                    .filter_map(|i| u16::try_from(i).ok())
                    .collect()
            })
            .unwrap_or_default(),
        query_present: list(table, "query_present", &what)?,
        query_absent: list(table, "query_absent", &what)?,
        header_present: list(table, "header_present", &what)?,
        header_absent: list(table, "header_absent", &what)?,
        auth_requirement: opt_str(table, "auth_requirement"),
        auth_action: opt_str(table, "auth_action"),
        auth_presigned: opt_bool(table, "auth_presigned"),
        auth_service: opt_str(table, "auth_service"),
        request: payload_overlay(table, "request"),
        response: payload_overlay(table, "response"),
        http_checksum_required: opt_bool(table, "http_checksum_required"),
        request_algorithms: algorithms(table, "request_algorithms", &what)?,
        response_algorithms: algorithms(table, "response_algorithms", &what)?,
        request_root: opt_str(table, "request_root"),
        request_root_aliases: list(table, "request_root_aliases", &what)?,
        response_root: opt_str(table, "response_root"),
        xmlns: opt_str(table, "xmlns"),
        unwrapped_output: opt_bool(table, "unwrapped_output"),
        element_order: list(table, "element_order", &what)?,
        url_encoded_fields: list(table, "url_encoded_fields", &what)?,
        body_literal: opt_bool(table, "body_literal"),
        empty_value: empty_value_table(table, &what)?,
        not_configured: opt_str(table, "not_configured"),
        allows_error_after_200: opt_bool(table, "allows_error_after_200"),
        error_codes: list(table, "error_codes", &what)?,
        quirk_refs: list(table, "quirk_refs", &what)?,
        head_mirrors: opt_str(table, "head_mirrors"),
        input_drop: list(table, "input_drop", &what)?,
        input_required: list(table, "input_required", &what)?,
        input_hot: list(table, "input_hot", &what)?,
        output_drop: list(table, "output_drop", &what)?,
        output_required: list(table, "output_required", &what)?,
        output_hot: list(table, "output_hot", &what)?,
        fields: field_overlays(table, &what, true)?,
    })
}

fn shape_overlay(name: &str, table: &Toml) -> Result<ShapeOverlay> {
    let what = format!("shape.{name}");
    Ok(ShapeOverlay {
        element_order: list(table, "element_order", &what)?,
        empty_value: empty_value_table(table, &what)?,
        required: list(table, "required", &what)?,
        hot: list(table, "hot", &what)?,
        drop: list(table, "drop", &what)?,
        attributes: attribute_overlays(table, &what)?,
        fields: field_overlays(table, &what, false)?,
    })
}

/// Reads the `[[shape.X.attribute]]` entries of one shape.
///
/// Exactly one source per attribute: a `field` or a `value`, never both and never neither. The
/// refusal is here rather than in lowering because an attribute with two sources has no
/// meaning to resolve — it is a typo in the one hand-written protocol-exception file.
fn attribute_overlays(table: &Toml, what: &str) -> Result<Vec<AttributeOverlay>> {
    let mut out = Vec::new();
    for entry in array_of_tables(table, "attribute") {
        let name = required_str(entry, "name", what)?;
        let field = opt_str(entry, "field");
        let value = opt_str(entry, "value");
        match (field.is_some(), value.is_some()) {
            (true, true) => {
                return Err(Error::Overlay(format!(
                    "{what}.attribute `{name}`: `field` and `value` are two sources and only one is allowed"
                )));
            }
            (false, false) => {
                return Err(Error::Overlay(format!(
                    "{what}.attribute `{name}`: needs either a `field` source or a constant `value`"
                )));
            }
            _ => {}
        }
        out.push(AttributeOverlay {
            element: opt_str(entry, "element"),
            name,
            field,
            value,
        });
    }
    Ok(out)
}

fn field_overlays(table: &Toml, what: &str, sided: bool) -> Result<Vec<FieldOverlay>> {
    let mut out = Vec::new();
    for entry in array_of_tables(table, "field") {
        let name = required_str(entry, "name", what)?;
        let side = match opt_str(entry, "side").as_deref() {
            None if !sided => Side::Input,
            Some("input") => Side::Input,
            Some("output") => Side::Output,
            Some(other) => return Err(Error::Overlay(format!("{what}.field `{name}`: unknown side `{other}`"))),
            None => return Err(Error::Overlay(format!("{what}.field `{name}`: `side` is required"))),
        };
        out.push(FieldOverlay {
            side,
            name,
            synthesize: opt_bool(entry, "synthesize").unwrap_or(false),
            after: opt_str(entry, "after"),
            wire_name: opt_str(entry, "wire_name"),
            binding: opt_str(entry, "binding"),
            ty: opt_str(entry, "type"),
            hot: opt_bool(entry, "hot"),
            required: opt_bool(entry, "required"),
            missing_error: opt_str(entry, "missing_error"),
            default_string: opt_str(entry, "default_string"),
            default_int: entry.get("default_int").and_then(Toml::as_int),
            default_bool: opt_bool(entry, "default_bool"),
            omit_when: opt_str(entry, "omit_when"),
            omit_when_value: opt_str(entry, "omit_when_value"),
            omit_when_field: opt_str(entry, "omit_when_field"),
            omit_when_equals: opt_str(entry, "omit_when_equals"),
            quirks: list(entry, "quirks", what)?,
        });
    }
    Ok(out)
}
