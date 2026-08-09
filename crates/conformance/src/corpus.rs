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

//! Discovery and loading of the case corpus.
//!
//! Responsible for: finding `conformance/`, reading every `cases/<domain>/*.toml`, validating each
//! against the frozen schema, and holding the goldens. A file that cannot be parsed or that the
//! schema rejects becomes a case with a failing diagnostic — never a case that is quietly skipped,
//! because a skipped case is indistinguishable from a case nobody wrote.
//! NOT responsible for: the conventions the schema cannot express (`crate::lint`) or execution
//! (`crate::runner`).
//! Upstream: `crate::toml`, `crate::schema`, `crate::diagnostic`. Downstream: `crate::lint`,
//! `crate::runner`.

use crate::diagnostic::Diagnostic;
use crate::keys::Inventory;
use crate::schema::Schema;
use crate::toml;
use crate::value::Value;
use std::path::{Path, PathBuf};

/// The corpus could not be located or read at all.
///
/// This is an environment failure, not a case failure: reporting it as a red case would poison a
/// baseline with a result that says nothing about the implementation under test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusError {
    /// What went wrong, and what to do about it.
    pub message: String,
}

impl core::fmt::Display for CorpusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CorpusError {}

/// One case file, loaded and schema-checked.
#[derive(Debug, Clone)]
pub struct Case {
    /// The identifier the file claims, or the file stem when the document is unreadable.
    pub id: String,
    /// The capability domain, which is the directory name.
    pub domain: String,
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Path relative to the corpus root, e.g. `cases/etag/c-etag-0001.toml`.
    pub relative: String,
    /// The parsed document, absent when the file could not be parsed.
    pub document: Option<Value>,
    /// Findings from loading and schema validation.
    pub diagnostics: Vec<Diagnostic>,
}

impl Case {
    /// The `[case]` table, when the file parsed.
    #[must_use]
    pub fn meta(&self) -> Option<&Value> {
        self.document.as_ref()?.read("case")
    }

    /// The title, for the report line.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.meta()?.read("caseMeta.title")?.as_str()
    }

    /// The polarity, which the corpus-wide balance requirement counts.
    #[must_use]
    pub fn polarity(&self) -> Option<&str> {
        self.meta()?.read("caseMeta.polarity")?.as_str()
    }

    /// The quirk identifiers this case declares.
    #[must_use]
    pub fn quirks(&self) -> Vec<&str> {
        self.meta()
            .and_then(|meta| meta.read_strings("caseMeta.quirks"))
            .unwrap_or_default()
    }

    /// The tags this case declares.
    #[must_use]
    pub fn tags(&self) -> Vec<&str> {
        self.meta()
            .and_then(|meta| meta.read_strings("caseMeta.tags"))
            .unwrap_or_default()
    }

    /// Whether the case is tagged `slow`, which moves it out of the pull-request gate.
    #[must_use]
    pub fn is_slow(&self) -> bool {
        self.tags().contains(&"slow")
    }

    /// The exchanges to run, as `(name, request, expect)` triples.
    ///
    /// The single-exchange form is presented as one unnamed exchange, so the runner has exactly
    /// one shape to execute and the schema's `oneOf` stays the only place the two forms differ.
    #[must_use]
    pub fn exchanges(&self) -> Vec<Exchange<'_>> {
        let Some(document) = self.document.as_ref() else { return Vec::new() };
        if let Some(Value::Array(items)) = document.read("exchanges") {
            return items
                .iter()
                .enumerate()
                .map(|(index, item)| Exchange {
                    index,
                    name: item.read("exchange.name").and_then(Value::as_str),
                    pointer: format!("/exchanges/{index}"),
                    request: item.read("exchange.request"),
                    expect: item.read("exchange.expect"),
                    delay_ms: item.read("exchange.delay_ms").and_then(Value::as_integer),
                    repeat: item.read("exchange.repeat").and_then(Value::as_integer).unwrap_or(1),
                })
                .collect();
        }
        vec![Exchange {
            index: 0,
            name: None,
            pointer: String::new(),
            request: document.read("request"),
            expect: document.read("expect"),
            delay_ms: None,
            repeat: 1,
        }]
    }
}

/// One request/response pair inside a case.
#[derive(Debug, Clone)]
pub struct Exchange<'a> {
    /// Zero-based position in the case.
    pub index: usize,
    /// The author's name for this exchange, when there is one.
    pub name: Option<&'a str>,
    /// JSON pointer prefix for diagnostics, e.g. `/exchanges/1`.
    pub pointer: String,
    /// The request specification.
    pub request: Option<&'a Value>,
    /// The expectation.
    pub expect: Option<&'a Value>,
    /// Pause before this exchange.
    pub delay_ms: Option<i64>,
    /// Number of identical attempts this exchange requests.
    pub repeat: i64,
}

impl Exchange<'_> {
    /// A short label for reports.
    #[must_use]
    pub fn label(&self) -> String {
        match self.name {
            Some(name) => format!("#{} {name}", self.index + 1),
            None => format!("#{}", self.index + 1),
        }
    }
}

/// The loaded corpus.
#[derive(Debug, Clone)]
pub struct Corpus {
    root: PathBuf,
    cases: Vec<Case>,
    inventory: Inventory,
}

impl Corpus {
    /// Locates `conformance/` without being told where it is.
    ///
    /// Order: the `RUSTFS_GATEWAY_CONFORMANCE_ROOT` environment variable, then the directory this
    /// crate was compiled from, then a walk up from the working directory. The environment
    /// variable comes first so the runner can be pointed at another project's corpus.
    ///
    /// # Errors
    ///
    /// Returns [`CorpusError`] when no candidate holds a `case.schema.json`.
    pub fn discover_root() -> Result<PathBuf, CorpusError> {
        let mut tried = Vec::new();
        if let Ok(configured) = std::env::var("RUSTFS_GATEWAY_CONFORMANCE_ROOT") {
            let path = PathBuf::from(configured);
            if path.join("case.schema.json").is_file() {
                return Ok(path);
            }
            tried.push(path);
        }
        let compiled_from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
        if compiled_from.join("case.schema.json").is_file() {
            return Ok(compiled_from);
        }
        tried.push(compiled_from);
        if let Ok(mut current) = std::env::current_dir() {
            loop {
                let candidate = current.join("conformance");
                if candidate.join("case.schema.json").is_file() {
                    return Ok(candidate);
                }
                if !current.pop() {
                    break;
                }
            }
        }
        let rendered: Vec<String> = tried.iter().map(|path| path.display().to_string()).collect();
        Err(CorpusError {
            message: format!(
                "could not find a conformance corpus (a directory holding case.schema.json). \
                 Tried: {}. Set RUSTFS_GATEWAY_CONFORMANCE_ROOT to the corpus directory.",
                rendered.join(", ")
            ),
        })
    }

    /// Loads the corpus rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`CorpusError`] when the schema is missing or uncompilable, or when `cases/` cannot
    /// be read. Individual unreadable case files do not fail the load; they become failing cases.
    pub fn load(root: &Path) -> Result<Corpus, CorpusError> {
        let schema_path = root.join("case.schema.json");
        let schema_text = std::fs::read_to_string(&schema_path).map_err(|error| CorpusError {
            message: format!("cannot read {}: {error}", schema_path.display()),
        })?;
        let schema = Schema::compile(&schema_text).map_err(|error| CorpusError {
            message: format!("{}: {error}", schema_path.display()),
        })?;
        let inventory = Inventory::compile(&schema_text).map_err(|message| CorpusError {
            message: format!("{}: {message}", schema_path.display()),
        })?;
        let cases_dir = root.join("cases");
        let mut files = Vec::new();
        collect_case_files(&cases_dir, &mut files)?;
        files.sort();
        let cases = files.iter().map(|path| load_case(root, path, &schema)).collect();
        Ok(Corpus {
            root: root.to_path_buf(),
            cases,
            inventory,
        })
    }

    /// Every key the frozen schema declares, and where a case may write each one.
    #[must_use]
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    /// Loads the corpus from the discovered root.
    ///
    /// # Errors
    ///
    /// See [`Corpus::discover_root`] and [`Corpus::load`].
    pub fn discover() -> Result<Corpus, CorpusError> {
        let root = Corpus::discover_root()?;
        Corpus::load(&root)
    }

    /// The corpus root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every case, in path order.
    #[must_use]
    pub fn cases(&self) -> &[Case] {
        &self.cases
    }

    /// Mutable access, used by `crate::lint` to append findings.
    pub fn cases_mut(&mut self) -> &mut [Case] {
        &mut self.cases
    }

    /// Reads a corpus-relative file, such as a golden.
    ///
    /// # Errors
    ///
    /// Returns [`CorpusError`] when the path escapes the corpus or cannot be read.
    pub fn read_relative(&self, relative: &str) -> Result<Vec<u8>, CorpusError> {
        if relative.contains("..") {
            return Err(CorpusError {
                message: format!("`{relative}` leaves the corpus directory"),
            });
        }
        let path = self.root.join(relative);
        std::fs::read(&path).map_err(|error| CorpusError {
            message: format!("cannot read {}: {error}", path.display()),
        })
    }
}

fn collect_case_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CorpusError> {
    let entries = std::fs::read_dir(dir).map_err(|error| CorpusError {
        message: format!("cannot read {}: {error}", dir.display()),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| CorpusError {
            message: format!("cannot read an entry of {}: {error}", dir.display()),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_case_files(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "toml") {
            out.push(path);
        }
    }
    Ok(())
}

fn load_case(root: &Path, path: &Path, schema: &Schema) -> Case {
    let relative = path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/");
    let domain = path
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = path
        .file_stem()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut diagnostics = Vec::new();

    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            diagnostics.push(Diagnostic::deny("corpus/unreadable", "", format!("cannot read the file: {error}")));
            return Case {
                id: stem,
                domain,
                path: path.to_path_buf(),
                relative,
                document: None,
                diagnostics,
            };
        }
    };
    let document = match toml::parse(&text) {
        Ok(document) => document,
        Err(error) => {
            diagnostics.push(Diagnostic::deny("corpus/parse", "", format!("not valid TOML: {error}")));
            return Case {
                id: stem,
                domain,
                path: path.to_path_buf(),
                relative,
                document: None,
                diagnostics,
            };
        }
    };
    let id = document
        .read("case")
        .and_then(|meta| meta.read("caseMeta.id"))
        .and_then(Value::as_str)
        .unwrap_or(&stem)
        .to_owned();
    for violation in schema.validate(&document) {
        diagnostics.push(Diagnostic::from_violation(&violation));
    }
    Case {
        id,
        domain,
        path: path.to_path_buf(),
        relative,
        document: Some(document),
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Corpus {
        let root = Corpus::discover_root().expect("the repository corpus is next to this crate");
        Corpus::load(&root).expect("the corpus loads")
    }

    #[test]
    fn the_repository_corpus_loads_every_case_file() {
        let corpus = corpus();
        assert!(corpus.cases().len() >= 22, "found {} cases", corpus.cases().len());
        assert!(corpus.cases().iter().all(|case| case.document.is_some()), "every case file must parse");
    }

    #[test]
    fn every_case_satisfies_the_frozen_schema() {
        let corpus = corpus();
        let failures: Vec<String> = corpus
            .cases()
            .iter()
            .flat_map(|case| case.diagnostics.iter().map(move |d| format!("{}: {d}", case.relative)))
            .collect();
        assert!(failures.is_empty(), "schema violations:\n{}", failures.join("\n"));
    }

    #[test]
    fn the_single_exchange_form_is_presented_as_one_exchange() {
        let corpus = corpus();
        let case = corpus
            .cases()
            .iter()
            .find(|case| case.id == "c-cond-0001")
            .expect("c-cond-0001");
        let exchanges = case.exchanges();
        assert_eq!(exchanges.len(), 1);
        assert!(exchanges[0].request.is_some());
        assert!(exchanges[0].expect.is_some());
    }

    #[test]
    fn the_multi_exchange_form_keeps_its_order_and_names() {
        let corpus = corpus();
        let case = corpus
            .cases()
            .iter()
            .find(|case| case.id == "c-list-0001")
            .expect("c-list-0001");
        let exchanges = case.exchanges();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0].name, Some("page-1"));
        assert_eq!(exchanges[1].name, Some("page-2"));
    }

    #[test]
    fn reading_outside_the_corpus_is_refused() {
        let corpus = corpus();
        assert!(corpus.read_relative("../Cargo.toml").is_err());
    }

    #[test]
    fn a_golden_referenced_by_a_case_is_readable() {
        let corpus = corpus();
        assert!(corpus.read_relative("goldens/c-list-0001.page1.xml").is_ok());
    }
}
