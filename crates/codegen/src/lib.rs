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

//! Code generator turning the rustfs-gateway IR into the checked-in artefacts.
//!
//! Responsible for: rendering `generated/**`, `spec/operations/*.toml` and `OPERATIONS.md`,
//! comparing the result with the frozen IR goldens, and answering the zero-diff question.
//! NOT responsible for: parsing Smithy or applying overlays (that is `rustfs-gateway-model`), and no
//! runtime behaviour.
//! Upstream: `rustfs-gateway-model`. Downstream: the checked-in generated sources and `xtask`.
//!
//! The whole pipeline is a pure function from `(model, overlays)` to a set of `(path, bytes)`
//! pairs. [`generate`] produces that set without touching the filesystem; [`write()`] puts it on
//! disk and [`verify`] compares it with what is already there. Zero-diff verification therefore
//! never needs a temporary directory, and determinism is structural rather than something a test
//! has to chase.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod emit;
pub mod golden;
pub mod mutate;
pub mod semantic;
pub mod why;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustfs_gateway_model::ir::OperationIr;
use rustfs_gateway_model::json;
use rustfs_gateway_model::{CodecRule, ContractRule, Model, Overlay, RuleClassification, lower};

/// Result alias for the generator.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can stop a codegen run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The model or the overlays could not be turned into IR.
    #[error(transparent)]
    Model(#[from] rustfs_gateway_model::Error),
    /// A file could not be read or written.
    #[error("io error on {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A checked-in artefact does not match what codegen produces.
    #[error("{0}")]
    Drift(String),
    /// The IR cannot be turned into a type surface the SemVer policy allows.
    ///
    /// ADR-0004 makes this a hard failure rather than a generator guess: a required field with no
    /// representable default, two operations disagreeing about one shape, or two enumeration
    /// values colliding on one constant name all need a human decision recorded in the overlays.
    #[error("{0}")]
    Policy(String),
    /// `xtask why` found nothing.
    #[error("{0}")]
    NotFound(String),
}

fn io(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Where the inputs live.
#[derive(Debug, Clone)]
pub struct CodegenInput {
    /// The pinned Smithy model.
    pub model: PathBuf,
    /// The overlay directory.
    pub overlays: PathBuf,
    /// The frozen IR goldens.
    pub samples: PathBuf,
    /// `model/PROVENANCE.md`, read only for the pinned commit in the run report.
    pub provenance: PathBuf,
}

/// Where the artefacts go.
#[derive(Debug, Clone)]
pub struct CodegenOutput {
    /// `spec/operations`.
    pub spec_dir: PathBuf,
    /// `OPERATIONS.md`.
    pub operations_md: PathBuf,
    /// `generated`.
    pub generated_dir: PathBuf,
}

impl CodegenInput {
    /// The standard input layout under a repository root.
    pub fn at(root: &Path) -> Self {
        CodegenInput {
            model: root.join("model/s3.json"),
            overlays: root.join("model").join("overlays"),
            samples: root.join("spec/ir/samples"),
            provenance: root.join("model/PROVENANCE.md"),
        }
    }
}

impl CodegenOutput {
    /// The standard output layout under a repository root.
    pub fn at(root: &Path) -> Self {
        CodegenOutput {
            spec_dir: root.join("spec/operations"),
            operations_md: root.join("OPERATIONS.md"),
            generated_dir: root.join("generated"),
        }
    }

    /// Every directory whose contents codegen owns completely.
    fn owned_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.spec_dir.clone(),
            self.quirks_dir(),
            self.contracts_dir(),
            self.generated_dir.join("ir"),
            self.generated_dir.join("codec").join("ops"),
            self.generated_dir.join("codec"),
            self.generated_dir.join("dto").join("ops").join("enums"),
            self.generated_dir.join("dto").join("ops").join("shapes"),
            self.generated_dir.join("dto").join("ops"),
            self.generated_dir.join("dto"),
            self.generated_dir.clone(),
        ]
    }

    fn quirks_dir(&self) -> PathBuf {
        self.spec_dir
            .parent()
            .map_or_else(|| PathBuf::from("spec/quirks"), |spec| spec.join("quirks"))
    }

    fn contracts_dir(&self) -> PathBuf {
        self.spec_dir
            .parent()
            .map_or_else(|| PathBuf::from("spec/contracts"), |spec| spec.join("contracts"))
    }

    fn macro_operation_names(&self) -> PathBuf {
        self.generated_dir.parent().map_or_else(
            || PathBuf::from("crates/macros/src/op_names.rs"),
            |root| root.join("crates/macros/src/op_names.rs"),
        )
    }

    fn required_external_files(&self) -> [PathBuf; 2] {
        [self.operations_md.clone(), self.macro_operation_names()]
    }
}

/// What one run produced.
#[derive(Debug)]
pub struct Report {
    /// The pinned upstream commit, when `PROVENANCE.md` could be read.
    pub pinned_commit: Option<String>,
    /// Operations generated.
    pub included: usize,
    /// Operations deliberately skipped.
    pub deferred: usize,
    /// Quirk records resolved into at least one IR document.
    pub quirks: usize,
    /// Trait occurrences deleted while loading the model.
    pub stripped_traits: usize,
    /// Artefact paths.
    pub files: Vec<PathBuf>,
    /// Golden comparison, one entry per sample.
    pub goldens: Vec<GoldenResult>,
}

/// One golden comparison.
#[derive(Debug)]
pub struct GoldenResult {
    /// Operation name.
    pub operation: String,
    /// Structural differences; empty means the generated IR matches the sample.
    pub differences: Vec<golden::Difference>,
}

/// The rendered artefacts, in a stable order.
#[derive(Debug)]
pub struct Artifacts {
    /// `(path, bytes)` pairs.
    pub files: Vec<(PathBuf, String)>,
    /// The IR documents behind them.
    pub operations: Vec<OperationIr>,
    /// Deferred operations and their reasons.
    pub deferred: BTreeMap<String, String>,
    /// Traits deleted while loading the model.
    pub stripped_traits: usize,
    /// What the dto emitter produced.
    pub dto: emit::dto::DtoReport,
    /// Typed quirk rules consumed by codec generation.
    pub codec_rules: BTreeMap<String, CodecRule>,
    /// Typed lowered-IR sources and their current values, keyed by mutable quirk id.
    pub source_rules: BTreeMap<String, Vec<emit::quirk_toml::ResolvedSource>>,
    /// Typed runtime contract inputs emitted for core consumers.
    pub contract_rules: BTreeMap<String, ContractRule>,
    /// The error code to `ErrorCode` constant index, from the error-status authority.
    pub error_codes: emit::error_status::Constants,
}

/// Loads the model and the overlays, lowers, and renders every artefact in memory.
pub fn generate(input: &CodegenInput, out: &CodegenOutput) -> Result<Artifacts> {
    generate_mutated(input, out, &[])
}

/// Renders every artefact with `mutations` written into its lowered IR or runtime contracts first.
///
/// This is the whole of what makes a mutation run a measurement rather than an opinion: the
/// mutation is applied to the same typed input code generation consumes, so whatever the mutated
/// artefacts do is what the built gateway does. Nothing on disk is touched — the caller decides
/// whether to write the result, and is responsible for putting the unmutated bytes back.
///
/// Each write is read back afterwards through the reader that produced the current value. A writer
/// that silently addressed a different field would otherwise produce a run in which every mutant
/// survives, which is indistinguishable from a corpus that checks nothing.
///
/// # Errors
///
/// Returns [`Error::Policy`] when a mutation names a path that does not resolve, replaces a value
/// that is not the one found there, or does not read back as written.
pub fn generate_mutated(input: &CodegenInput, out: &CodegenOutput, mutations: &[mutate::Mutation]) -> Result<Artifacts> {
    let model = Model::load(&input.model)?;
    let mut overlay = Overlay::load(&input.overlays)?;
    let mut lowered = lower(&model, &overlay)?;
    for mutation in mutations {
        if mutate::apply_codec(&mut overlay.codec_rules, mutation)
            .map_err(|message| Error::Policy(format!("quirk `{}`: {message}", mutation.quirk)))?
        {
            continue;
        }
        if mutate::apply_contract(&mut overlay.contract_rules, mutation)
            .map_err(|message| Error::Policy(format!("quirk `{}`: {message}", mutation.quirk)))?
        {
            continue;
        }
        mutate::apply::apply(&mut lowered.operations, mutation)
            .map_err(|message| Error::Policy(format!("quirk `{}`: {message}", mutation.quirk)))?;
        match emit::quirk_toml::resolve_at(&lowered.operations, &mutation.path) {
            Ok(written) if written == mutation.to => {}
            found => {
                return Err(Error::Policy(format!(
                    "quirk `{}`: source `{}` does not read back as the {:?} it was written; the reader \
                     answered {found:?}",
                    mutation.quirk, mutation.path, mutation.to
                )));
            }
        }
    }
    let lowered = lowered;

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    let mut resolved_source_rules = BTreeMap::new();
    for (id, rule) in &overlay.source_rules {
        let resolved = emit::quirk_toml::resolve_sources(&lowered.operations, rule)
            .map_err(|message| Error::Policy(format!("quirk `{id}`: {message}")))?;
        resolved_source_rules.insert(id.clone(), resolved);
    }
    for (id, quirk) in &overlay.quirks {
        let Some(classification) = overlay.classifications.get(id).copied() else {
            return Err(Error::Policy(format!("protocol record `{id}` has no classification")));
        };
        let dir = match classification {
            RuleClassification::Mutable => out.quirks_dir(),
            RuleClassification::Contract if overlay.contract_rules.contains_key(id) => out.contracts_dir(),
            RuleClassification::Contract => continue,
        };
        files.push((
            dir.join(format!("{id}.toml")),
            emit::quirk_toml::render(
                quirk,
                overlay.codec_rules.get(id),
                overlay.source_rules.get(id),
                overlay.contract_rules.get(id),
                resolved_source_rules.get(id).map(Vec::as_slice).unwrap_or_default(),
                classification,
            ),
        ));
    }
    for ir in &lowered.operations {
        files.push((
            out.generated_dir.join("ir").join(format!("{}.json", ir.operation)),
            json::write_canonical(&rustfs_gateway_model::ir::emit::to_json(ir)),
        ));
        files.push((out.spec_dir.join(format!("{}.toml", ir.operation)), emit::spec_toml::render(ir)));
    }
    files.push((
        out.operations_md.clone(),
        emit::operations_md::render(&lowered.operations, &lowered.route_only, &overlay.route_only, &lowered.deferred),
    ));
    files.push((
        out.generated_dir.join("OPERATIONS.json"),
        emit::operations_json::render(&lowered.operations),
    ));
    files.push((
        out.generated_dir.join("routes.rs"),
        emit::rust_files::routes(&lowered.operations, &lowered.route_only),
    ));
    files.push((
        out.generated_dir.join("subresource_bits.rs"),
        emit::rust_files::subresource_bits(&lowered.routing_query_keys).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("route_shadowing.rs"),
        emit::rust_files::route_shadowing(&overlay.shadowing),
    ));
    files.push((out.macro_operation_names(), emit::rust_files::macro_operation_names(&lowered.operations)));
    files.push((
        out.generated_dir.join("naming_contracts.rs"),
        emit::naming_contracts::render(&overlay.contract_rules).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("range_contracts.rs"),
        emit::range_contracts::render(&overlay.contract_rules).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("upload_id_contracts.rs"),
        emit::upload_id_contracts::render(&overlay.contract_rules).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("contracts.rs"),
        emit::runtime_contracts::render(&overlay.contract_rules).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("signature_contracts.rs"),
        emit::runtime_contracts::render_signature(&overlay.contract_rules).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("error_codes.rs"),
        emit::rust_files::error_codes(&lowered.operations),
    ));
    files.push((
        out.generated_dir.join("error_status.rs"),
        emit::error_status::render(&overlay.error_status).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("ERROR_CODES.md"),
        emit::error_status::render_markdown(&overlay.error_status).map_err(Error::Policy)?,
    ));
    files.push((
        out.generated_dir.join("error_codes.json"),
        emit::error_status::render_json(&overlay.error_status),
    ));
    let error_codes = emit::error_status::Constants::new(&overlay.error_status);
    let (dto_files, dto) = emit::dto::emit(&lowered.operations, &out.generated_dir).map_err(Error::Policy)?;
    files.extend(dto_files);
    files.extend(
        emit::codec::emit(&lowered.operations, &overlay.codec_rules, &error_codes, &out.generated_dir).map_err(Error::Policy)?,
    );
    for required in out.required_external_files() {
        if !files.iter().any(|(path, _)| *path == required) {
            return Err(Error::Policy(format!(
                "required codegen artefact was not emitted: {}",
                required.display()
            )));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(Artifacts {
        files,
        operations: lowered.operations,
        deferred: lowered.deferred,
        stripped_traits: model.stripped_trait_count(),
        dto,
        codec_rules: overlay.codec_rules,
        source_rules: resolved_source_rules,
        contract_rules: overlay.contract_rules,
        error_codes,
    })
}

/// Generates and writes every artefact, deleting stale files codegen no longer owns.
pub fn write(input: &CodegenInput, out: &CodegenOutput) -> Result<Report> {
    let artifacts = generate(input, out)?;
    let expected: Vec<PathBuf> = artifacts.files.iter().map(|(p, _)| p.clone()).collect();

    for (path, body) in &artifacts.files {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        // Rewriting an identical file would churn its mtime and defeat every downstream cache.
        let unchanged = std::fs::read_to_string(path).map(|old| old == *body).unwrap_or(false);
        if !unchanged {
            std::fs::write(path, body).map_err(|e| io(path, e))?;
        }
    }
    for dir in out.owned_dirs() {
        remove_stale(&dir, &expected)?;
    }
    report(input, artifacts)
}

/// Regenerates in memory and fails on any difference with the working tree.
///
/// This is the zero-diff gate. It names the files that differ and the first differing line, so a
/// failure points at the drift instead of only announcing it.
pub fn verify(input: &CodegenInput, out: &CodegenOutput) -> Result<usize> {
    let artifacts = generate(input, out)?;
    let mut drifted: Vec<String> = Vec::new();
    let expected: Vec<PathBuf> = artifacts.files.iter().map(|(p, _)| p.clone()).collect();

    for (path, body) in &artifacts.files {
        match std::fs::read_to_string(path) {
            Ok(found) if found == *body => {}
            Ok(found) => drifted.push(format!("{}: {}", path.display(), first_line_difference(&found, body))),
            Err(_) => drifted.push(format!("{}: missing", path.display())),
        }
    }
    for dir in out.owned_dirs() {
        for stale in stale_files(&dir, &expected)? {
            drifted.push(format!("{}: not produced by codegen", stale.display()));
        }
    }
    if drifted.is_empty() {
        return Ok(artifacts.files.len());
    }
    Err(Error::Drift(format!(
        "spec verify: {} file(s) differ from `cargo xtask codegen` output\n  {}\n\n\
         Regenerate with `cargo xtask codegen`; to change wire behaviour edit `overlays/`, never a generated file.",
        drifted.len(),
        drifted.join("\n  ")
    )))
}

fn first_line_difference(found: &str, expected: &str) -> String {
    for (n, (a, b)) in found.lines().zip(expected.lines()).enumerate() {
        if a != b {
            return format!("line {} differs\n    working tree: {}\n    codegen:      {}", n + 1, a.trim(), b.trim());
        }
    }
    format!(
        "{} line(s) in the working tree, {} from codegen",
        found.lines().count(),
        expected.lines().count()
    )
}

fn stale_files(dir: &Path, expected: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(stale);
    };
    for entry in entries {
        let entry = entry.map_err(|e| io(dir, e))?;
        let path = entry.path();
        if path.is_file() && !expected.contains(&path) {
            stale.push(path);
        }
    }
    stale.sort();
    Ok(stale)
}

fn remove_stale(dir: &Path, expected: &[PathBuf]) -> Result<()> {
    for path in stale_files(dir, expected)? {
        std::fs::remove_file(&path).map_err(|e| io(&path, e))?;
    }
    Ok(())
}

fn report(input: &CodegenInput, artifacts: Artifacts) -> Result<Report> {
    let mut goldens = Vec::new();
    for ir in &artifacts.operations {
        let sample = input.samples.join(format!("{}.json", ir.operation));
        let Ok(text) = std::fs::read_to_string(&sample) else {
            continue;
        };
        let expected = json::parse(&text).map_err(Error::Model)?;
        let produced = rustfs_gateway_model::ir::emit::to_json(ir);
        goldens.push(GoldenResult {
            operation: ir.operation.clone(),
            differences: golden::compare(&expected, &produced),
        });
    }
    let quirks: std::collections::BTreeSet<String> = artifacts
        .operations
        .iter()
        .flat_map(|ir| ir.quirks.iter().map(|q| q.id.clone()))
        .collect();
    Ok(Report {
        pinned_commit: pinned_commit(&input.provenance),
        included: artifacts.operations.len(),
        deferred: artifacts.deferred.len(),
        quirks: quirks.len(),
        stripped_traits: artifacts.stripped_traits,
        files: artifacts.files.into_iter().map(|(p, _)| p).collect(),
        goldens,
    })
}

/// Reads the pinned commit out of `model/PROVENANCE.md` for the run report. Best effort: the
/// report is diagnostics, and `model/tools/verify.py` is what actually asserts the pin.
fn pinned_commit(provenance: &Path) -> Option<String> {
    let text = std::fs::read_to_string(provenance).ok()?;
    for line in text.lines() {
        if !line.starts_with("| Pinned commit ") {
            continue;
        }
        // The value is the backticked token, not "any hex-looking characters on the line":
        // `Pinned commit` itself contributes `e`, `d` and `c`.
        let candidate = line.split('`').nth(1)?;
        if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(candidate.to_owned());
        }
    }
    None
}
