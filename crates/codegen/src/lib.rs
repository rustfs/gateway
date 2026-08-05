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
//! pairs. [`generate`] produces that set without touching the filesystem; [`write`] puts it on
//! disk and [`verify`] compares it with what is already there. Zero-diff verification therefore
//! never needs a temporary directory, and determinism is structural rather than something a test
//! has to chase.
#![forbid(unsafe_code)]

pub mod emit;
pub mod golden;
pub mod semantic;
pub mod why;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustfs_gateway_model::ir::OperationIr;
use rustfs_gateway_model::json;
use rustfs_gateway_model::{Model, Overlay, lower};

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
            self.generated_dir.join("ir"),
            self.generated_dir.join("dto").join("ops").join("enums"),
            self.generated_dir.join("dto").join("ops").join("shapes"),
            self.generated_dir.join("dto").join("ops"),
            self.generated_dir.join("dto"),
            self.generated_dir.clone(),
        ]
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
}

/// Loads the model and the overlays, lowers, and renders every artefact in memory.
pub fn generate(input: &CodegenInput, out: &CodegenOutput) -> Result<Artifacts> {
    let model = Model::load(&input.model)?;
    let overlay = Overlay::load(&input.overlays)?;
    let lowered = lower(&model, &overlay)?;

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for ir in &lowered.operations {
        files.push((
            out.generated_dir.join("ir").join(format!("{}.json", ir.operation)),
            json::write_canonical(&rustfs_gateway_model::ir::emit::to_json(ir)),
        ));
        files.push((out.spec_dir.join(format!("{}.toml", ir.operation)), emit::spec_toml::render(ir)));
    }
    files.push((
        out.operations_md.clone(),
        emit::operations_md::render(&lowered.operations, &lowered.deferred),
    ));
    files.push((out.generated_dir.join("routes.rs"), emit::rust_files::routes(&lowered.operations)));
    files.push((
        out.generated_dir.join("error_codes.rs"),
        emit::rust_files::error_codes(&lowered.operations),
    ));
    let (dto_files, dto) = emit::dto::emit(&lowered.operations, &out.generated_dir).map_err(Error::Policy)?;
    files.extend(dto_files);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(Artifacts {
        files,
        operations: lowered.operations,
        deferred: lowered.deferred,
        stripped_traits: model.stripped_trait_count(),
        dto,
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
