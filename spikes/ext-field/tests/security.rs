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

//! XML resource-limit, DTD, entity-expansion, and external-entity cases.

use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use ext_field_spike::{CodecPolicy, LifecycleRule, LimitKind, UnknownPolicy, XmlError, XmlLimits};
use syn::visit::{self, Visit};

struct CountingReader<'input> {
    input: &'input [u8],
    position: usize,
    bytes_read: &'input Cell<usize>,
}

struct TestSecret(PathBuf);

impl TestSecret {
    fn create(path: PathBuf, contents: &str) -> Self {
        std::fs::write(&path, contents).expect("create a real external-entity target");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestSecret {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.input[self.position..];
        let count = remaining.len().min(output.len());
        output[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        self.bytes_read.set(self.bytes_read.get() + count);
        Ok(count)
    }
}

#[derive(Default)]
struct CapabilityVisitor {
    violations: Vec<String>,
    std_aliases: HashSet<String>,
}

impl CapabilityVisitor {
    fn meta_contains_path(meta: &syn::Meta) -> bool {
        if meta.path().is_ident("path") {
            return true;
        }
        let syn::Meta::List(list) = meta else {
            return false;
        };
        let Ok(nested) = list.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) else {
            return false;
        };
        nested.iter().any(Self::meta_contains_path)
    }

    fn check_route(&mut self, route: &[String]) {
        let is_std = route
            .first()
            .is_some_and(|name| name == "std" || self.std_aliases.contains(name));
        let is_filesystem = is_std && route.get(1).is_some_and(|name| name == "fs");
        let is_process = is_std && route.get(1).is_some_and(|name| name == "process");
        let is_capability_type = route
            .last()
            .is_some_and(|name| matches!(name.as_str(), "File" | "OpenOptions" | "Command"));
        if is_filesystem || is_process || is_capability_type {
            self.violations.push(route.join("::"));
        }
    }

    fn visit_use_tree(&mut self, prefix: &mut Vec<String>, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.check_route(prefix);
                self.visit_use_tree(prefix, &path.tree);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                if name.ident != "self" {
                    prefix.push(name.ident.to_string());
                    self.check_route(prefix);
                    prefix.pop();
                }
            }
            syn::UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.check_route(prefix);
                if prefix.as_slice() == ["std", "self"] || prefix.len() == 1 && prefix[0] == "std" {
                    self.std_aliases.insert(rename.rename.to_string());
                    self.violations.push(format!("std as {}", rename.rename));
                }
                prefix.pop();
            }
            syn::UseTree::Glob(_) => self.check_route(prefix),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.visit_use_tree(prefix, item);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for CapabilityVisitor {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if attribute.path().is_ident("path") {
            self.violations.push("#[path] can import source outside src".to_owned());
        } else if attribute.path().is_ident("cfg_attr") {
            match attribute.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) {
                Ok(arguments) if arguments.iter().any(Self::meta_contains_path) => {
                    self.violations
                        .push("cfg_attr(path) can import source outside src".to_owned());
                }
                Ok(_) => {}
                Err(_) => self.violations.push("cfg_attr could not be inspected".to_owned()),
            }
        }
        visit::visit_attribute(self, attribute);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if item.ident == "std" {
            if let Some((_, alias)) = &item.rename {
                self.std_aliases.insert(alias.to_string());
            }
            self.violations.push("extern crate std".to_owned());
        }
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.visit_use_tree(&mut Vec::new(), &item.tree);
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let route = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.check_route(&route);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        let tokens = invocation.tokens.to_string().split_whitespace().collect::<String>();
        let macro_name = invocation
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if macro_name.trim_start_matches("r#") == "macro_rules" {
            self.violations
                .push("local macro definitions are outside the AST capability proof".to_owned());
        }
        if macro_name.trim_start_matches("r#") == "include" || tokens.contains("include!") {
            self.violations.push("include! can import source outside src".to_owned());
        }
        for forbidden in ["std::fs", "std::{fs", "std::process", "std::{process"] {
            if tokens.contains(forbidden) {
                self.violations.push(format!("macro tokens contain {forbidden}"));
            }
        }
        visit::visit_macro(self, invocation);
    }
}

fn rust_source_files(source_dir: &Path) -> Vec<PathBuf> {
    let mut pending = vec![source_dir.to_owned()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("read spike source directory") {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

fn dependency_package_name(
    alias: &str,
    specification: &toml::Value,
    workspace_dependencies: Option<&toml::map::Map<String, toml::Value>>,
) -> Result<String, String> {
    let Some(table) = specification.as_table() else {
        return specification
            .as_str()
            .map(|_| alias.to_owned())
            .ok_or_else(|| format!("dependency {alias} has an unsupported specification"));
    };
    if table.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
        let inherited = workspace_dependencies
            .and_then(|dependencies| dependencies.get(alias))
            .ok_or_else(|| format!("dependency {alias} is missing from workspace.dependencies"))?;
        return dependency_package_name(alias, inherited, None);
    }
    Ok(table.get("package").and_then(toml::Value::as_str).unwrap_or(alias).to_owned())
}

fn collect_runtime_dependency_tables(manifest: &toml::Value) -> Vec<&toml::map::Map<String, toml::Value>> {
    let mut tables = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        tables.extend(
            targets
                .values()
                .filter_map(toml::Value::as_table)
                .filter_map(|target| target.get("dependencies"))
                .filter_map(toml::Value::as_table),
        );
    }
    tables
}

fn assert_codec_has_no_filesystem_or_process_capability() {
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_source_files(&source_dir);

    let mut violations = Vec::new();
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read spike source");
        let syntax = syn::parse_file(&source).expect("spike source parses as Rust");
        let mut visitor = CapabilityVisitor::default();
        visitor.visit_file(&syntax);
        violations.extend(
            visitor
                .violations
                .into_iter()
                .map(|violation| format!("{}: {violation}", path.display())),
        );
    }
    assert!(
        violations.is_empty(),
        "codec source gained filesystem or process capability: {violations:?}"
    );

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_text = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("read spike manifest");
    let manifest = toml::from_str::<toml::Value>(&manifest_text).expect("parse spike manifest as TOML");
    let workspace_text = std::fs::read_to_string(manifest_dir.join("../../Cargo.toml")).expect("read workspace manifest");
    let workspace = toml::from_str::<toml::Value>(&workspace_text).expect("parse workspace manifest as TOML");
    let workspace_dependencies = workspace
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .expect("workspace.dependencies is a TOML table");
    let runtime_packages = collect_runtime_dependency_tables(&manifest)
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .map(|(alias, specification)| dependency_package_name(alias, specification, Some(workspace_dependencies)))
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("runtime dependency specifications resolve");
    assert_eq!(
        runtime_packages,
        BTreeSet::from(["quick-xml".to_owned()]),
        "runtime dependency packages must stay capability-free"
    );
}

#[test]
fn c_ext_n005_depth_limit_rejects_sixty_levels() {
    let mut input = String::from("<Rule>");
    input.push_str(&"<Unknown>".repeat(60));
    input.push_str("ignored");
    input.push_str(&"</Unknown>".repeat(60));
    input.push_str("<Status>Enabled</Status></Rule>");

    let error = LifecycleRule::decode_xml(input.as_bytes(), &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect_err("depth beyond 50 must fail");
    assert!(matches!(error, XmlError::LimitExceeded(LimitKind::Depth)));
}

#[test]
fn c_ext_n006_doctype_is_rejected() {
    let input = b"<!DOCTYPE Rule><Rule><Status>Enabled</Status></Rule>";
    let error = LifecycleRule::decode_xml(input, &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect_err("DOCTYPE must be rejected explicitly");

    assert!(matches!(error, XmlError::Doctype));
}

#[test]
fn c_ext_n007_billion_laughs_is_rejected_without_expansion() {
    let input = br#"<!DOCTYPE Rule [
        <!ENTITY lol "lol">
        <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]><Rule><Status>&lol2;</Status></Rule>"#;
    let error = LifecycleRule::decode_xml(input, &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect_err("DOCTYPE is rejected before entity expansion");

    assert!(matches!(error, XmlError::Doctype));
}

#[test]
fn c_ext_n008_xxe_is_rejected_with_no_filesystem_capability() {
    let secret = format!("ext-field-secret-{}", std::process::id());
    let path = std::env::temp_dir().join(format!("ext-field-spike-xxe-{}", std::process::id()));
    let external_file = TestSecret::create(path, &secret);
    assert_eq!(std::fs::read_to_string(external_file.path()).expect("secret exists"), secret);
    let input = format!(
        "<!DOCTYPE Rule [<!ENTITY xxe SYSTEM \"file://{}\">]><Rule><Status>&xxe;</Status></Rule>",
        external_file.path().display()
    );

    let error = LifecycleRule::decode_xml(input.as_bytes(), &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect_err("external entity declaration is rejected");
    assert!(matches!(error, XmlError::Doctype));

    assert_codec_has_no_filesystem_or_process_capability();
}

#[test]
fn c_ext_n009_element_count_limit_rejects_twenty_thousand() {
    let mut input = String::from("<Rule>");
    input.push_str(&"<Unknown/>".repeat(20_000));
    input.push_str("<Status>Enabled</Status></Rule>");

    let error = LifecycleRule::decode_xml(input.as_bytes(), &CodecPolicy::new(UnknownPolicy::Lenient))
        .expect_err("element count beyond 10,000 must fail");
    assert!(matches!(error, XmlError::LimitExceeded(LimitKind::Elements)));
}

#[test]
fn c_ext_n010_byte_limit_reads_only_limit_plus_one() {
    let mut input = String::from("<Rule><Unknown>");
    input.push_str(&"x".repeat(3 << 20));
    input.push_str("</Unknown><Status>Enabled</Status></Rule>");
    let limits = XmlLimits::default();
    let policy = CodecPolicy::with_limits(UnknownPolicy::Lenient, limits);
    let bytes_read = Cell::new(0);
    let reader = CountingReader {
        input: input.as_bytes(),
        position: 0,
        bytes_read: &bytes_read,
    };

    let error = LifecycleRule::decode_reader(reader, &policy).expect_err("body beyond 2 MiB must fail");
    assert!(matches!(error, XmlError::LimitExceeded(LimitKind::Bytes)));
    assert_eq!(
        bytes_read.get(),
        limits.max_bytes + 1,
        "the transport read must stop after the oversize probe byte"
    );
}
