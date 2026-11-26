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

//! Workspace-wide trybuild deferral contracts for bounded crate verification.
//!
//! Responsible for: discovering default-feature `trybuild` tests across workspace crates and
//! proving that no crate's 30-second verification loop executes an unskipped `trybuild` harness
//! (rustfs/gateway#1557). NOT responsible for: choosing crate verification scopes or running Cargo.
//! Upstream: `xtask::verify::tests`. Downstream: the xtask unit-test runner.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

use crate::codegen;

use super::crate_step_batches;

fn skipped_after_separator(step: &[String]) -> (Vec<&str>, bool) {
    let mut args = step.iter().skip_while(|argument| *argument != "--");
    if args.next().is_none() {
        return (Vec::new(), false);
    }
    let mut skips = Vec::new();
    let mut exact = false;
    while let Some(argument) = args.next() {
        if argument == "--skip" {
            if let Some(pattern) = args.next() {
                skips.push(pattern.as_str());
            }
        } else if argument == "--exact" {
            exact = true;
        }
    }
    (skips, exact)
}

fn step_runs_test_target(step: &[String], target: &str) -> bool {
    if step.first().map(String::as_str) != Some("test") {
        return false;
    }
    let before_sep: Vec<&str> = step
        .iter()
        .skip(1)
        .take_while(|argument| *argument != "--")
        .map(String::as_str)
        .collect();
    let mut has_target_filter = false;
    let mut index = 0;
    while index < before_sep.len() {
        match before_sep[index] {
            "--test" => {
                has_target_filter = true;
                if before_sep.get(index + 1).copied() == Some(target) {
                    return true;
                }
                index += 2;
            }
            "--bin" | "--example" | "--bench" => {
                has_target_filter = true;
                index += 2;
            }
            "--lib" | "--bins" | "--examples" | "--benches" | "--doc" => {
                has_target_filter = true;
                index += 1;
            }
            "--tests" | "--all-targets" => return true,
            _ => index += 1,
        }
    }
    !has_target_filter
}

fn unskipped_trybuild_tests(step_batches: &[Vec<Vec<String>>], trybuild_tests: &[(String, String)]) -> Vec<String> {
    let mut leaked = Vec::new();
    for step in step_batches.iter().flatten() {
        if step.first().map(String::as_str) != Some("test") {
            continue;
        }
        let (skips, exact) = skipped_after_separator(step);
        for (target, test_name) in trybuild_tests {
            if !step_runs_test_target(step, target) {
                continue;
            }
            let skipped = if exact {
                skips.iter().any(|pattern| *pattern == test_name)
            } else {
                skips.iter().any(|pattern| test_name.contains(*pattern))
            };
            if !skipped {
                leaked.push(format!("{target}::{test_name}"));
            }
        }
    }
    leaked
}

fn tokens_mention_feature(stream: proc_macro2::TokenStream) -> bool {
    stream.into_iter().any(|tree| match tree {
        proc_macro2::TokenTree::Ident(ident) => ident == "feature",
        proc_macro2::TokenTree::Group(group) => tokens_mention_feature(group.stream()),
        _ => false,
    })
}

fn has_feature_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && matches!(&attr.meta, syn::Meta::List(list) if tokens_mention_feature(list.tokens.clone()))
    })
}

fn is_test_attr(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("test") || attr.path().segments.last().is_some_and(|segment| segment.ident == "test")
}

fn path_attribute(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        if let syn::Meta::NameValue(name_value) = &attr.meta
            && let syn::Expr::Lit(expr_lit) = &name_value.value
            && let syn::Lit::Str(literal) = &expr_lit.lit
        {
            return Some(literal.value());
        }
        None
    })
}

fn use_tree_mentions_trybuild(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => path.ident == "trybuild" || use_tree_mentions_trybuild(&path.tree),
        syn::UseTree::Name(name) => name.ident == "trybuild",
        syn::UseTree::Rename(rename) => rename.ident == "trybuild",
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_mentions_trybuild),
    }
}

struct TrybuildFinder {
    imports_trybuild: bool,
    found: bool,
}

impl<'ast> Visit<'ast> for TrybuildFinder {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if use_tree_mentions_trybuild(&node.tree) {
            self.imports_trybuild = true;
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.iter().any(|segment| segment.ident == "trybuild")
            || (self.imports_trybuild && node.segments.iter().any(|segment| segment.ident == "TestCases"))
        {
            self.found = true;
        }
        syn::visit::visit_path(self, node);
    }
}

fn collect_trybuild_tests_in_items(items: &[syn::Item], base_dir: Option<&Path>, prefix: &str, out: &mut Vec<String>) {
    let imports_trybuild = items
        .iter()
        .any(|item| matches!(item, syn::Item::Use(use_item) if use_tree_mentions_trybuild(&use_item.tree)));
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                if !function.attrs.iter().any(is_test_attr) || has_feature_cfg(&function.attrs) {
                    continue;
                }
                let mut finder = TrybuildFinder {
                    imports_trybuild,
                    found: false,
                };
                finder.visit_block(&function.block);
                if finder.found {
                    out.push(format!("{prefix}{}", function.sig.ident));
                }
            }
            syn::Item::Mod(module) => {
                if has_feature_cfg(&module.attrs) {
                    continue;
                }
                let next_prefix = format!("{prefix}{}::", module.ident);
                if let Some((_, inline_items)) = &module.content {
                    collect_trybuild_tests_in_items(inline_items, base_dir, &next_prefix, out);
                    continue;
                }
                let Some(dir) = base_dir else { continue };
                let candidate = if let Some(explicit) = path_attribute(&module.attrs) {
                    dir.join(explicit)
                } else {
                    let sibling = dir.join(format!("{}.rs", module.ident));
                    if sibling.is_file() {
                        sibling
                    } else {
                        dir.join(module.ident.to_string()).join("mod.rs")
                    }
                };
                if candidate.is_file() {
                    let source = fs::read_to_string(&candidate)
                        .unwrap_or_else(|error| panic!("could not read {}: {error}", candidate.display()));
                    let parsed = syn::parse_file(&source)
                        .unwrap_or_else(|error| panic!("could not parse {}: {error}", candidate.display()));
                    collect_trybuild_tests_in_items(&parsed.items, candidate.parent(), &next_prefix, out);
                }
            }
            _ => {}
        }
    }
}

fn default_trybuild_tests_in_source(source: &str) -> Vec<String> {
    let parsed = syn::parse_file(source).expect("synthetic test source must parse");
    let mut out = Vec::new();
    collect_trybuild_tests_in_items(&parsed.items, None, "", &mut out);
    out
}

fn quoted_toml_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?.trim();
    let value = rest.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_owned())
}

fn parse_crate_test_targets(crate_dir: &Path) -> Option<(String, Vec<(String, PathBuf)>)> {
    let manifest = fs::read_to_string(crate_dir.join("Cargo.toml")).ok()?;
    let mut section = String::new();
    let mut package_name = None;
    let mut autotests = true;
    let mut explicit_tests: Vec<(Option<String>, Option<String>)> = Vec::new();

    for raw_line in manifest.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_owned();
            if section == "[[test]]" {
                explicit_tests.push((None, None));
            }
            continue;
        }
        match section.as_str() {
            "[package]" => {
                if let Some(name) = quoted_toml_value(line, "name") {
                    package_name = Some(name);
                } else if line.starts_with("autotests") && line.contains("false") {
                    autotests = false;
                }
            }
            "[[test]]" => {
                if let Some((name, path)) = explicit_tests.last_mut() {
                    if let Some(value) = quoted_toml_value(line, "name") {
                        *name = Some(value);
                    } else if let Some(value) = quoted_toml_value(line, "path") {
                        *path = Some(value);
                    }
                }
            }
            _ => {}
        }
    }

    let package_name = package_name?;
    let mut targets = Vec::new();
    for (name, path) in explicit_tests {
        if let Some(name) = name {
            let relative = path.unwrap_or_else(|| format!("tests/{name}.rs"));
            targets.push((name, crate_dir.join(relative)));
        }
    }
    if autotests {
        let tests_dir = crate_dir.join("tests");
        if let Ok(entries) = fs::read_dir(&tests_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if !targets.iter().any(|(name, _)| name == stem) {
                    targets.push((stem.to_owned(), path));
                }
            }
        }
    }
    Some((package_name, targets))
}

fn discover_workspace_trybuild_tests(root: &Path) -> BTreeMap<String, Vec<(String, String)>> {
    let mut discovered = BTreeMap::new();
    let entries = fs::read_dir(root.join("crates")).expect("workspace crates directory must exist");
    for entry in entries.flatten() {
        let crate_dir = entry.path();
        if !crate_dir.is_dir() {
            continue;
        }
        let Some((package, targets)) = parse_crate_test_targets(&crate_dir) else {
            continue;
        };
        let mut tests = Vec::new();
        for (target_name, path) in targets {
            if !path.is_file() {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
            let parsed = syn::parse_file(&source).unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()));
            let mut found = Vec::new();
            collect_trybuild_tests_in_items(&parsed.items, path.parent(), "", &mut found);
            for test_name in found {
                tests.push((target_name.clone(), test_name));
            }
        }
        discovered.insert(package, tests);
    }
    discovered
}

fn owned(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|argument| (*argument).to_owned()).collect()
}

/// Every `trybuild` harness compiles a synthetic crate in `target/tests/trybuild` and cleans it on
/// every run, so running one inside `verify --crate` always compiles inside the 30-second budget
/// (rustfs/gateway#1557). Every workspace crate must defer all default-feature `trybuild` tests to
/// `cargo test --workspace`.
#[test]
fn every_workspace_crate_defers_all_default_trybuild_tests_from_its_fast_loop() {
    let discovered = discover_workspace_trybuild_tests(&codegen::repo_root());

    assert_eq!(
        discovered.get("rustfs-gateway").map(Vec::len),
        Some(1),
        "scanner must observe the gateway trybuild contract: {:?}",
        discovered.get("rustfs-gateway")
    );
    assert_eq!(
        discovered.get("rustfs-gateway-core").map(Vec::len),
        Some(2),
        "scanner must observe both core trybuild contracts: {:?}",
        discovered.get("rustfs-gateway-core")
    );
    assert_eq!(
        discovered.get("rustfs-gateway-sig").map(Vec::len),
        Some(5),
        "scanner must observe all five default-feature sig trybuild contracts: {:?}",
        discovered.get("rustfs-gateway-sig")
    );

    for (package, trybuild_tests) in &discovered {
        let leaked = unskipped_trybuild_tests(&crate_step_batches(package), trybuild_tests);
        assert!(
            leaked.is_empty(),
            "{package} fast loop leaves trybuild tests unskipped inside the 30s budget: {leaked:?}"
        );
    }
}

#[test]
fn trybuild_skip_matcher_accepts_exact_and_substring_skips() {
    let exact_batches = vec![vec![owned(&[
        "test",
        "-p",
        "rustfs-gateway-sig",
        "--",
        "--skip",
        "compile_fail::p2_01_compile_time_boundaries_are_not_openable",
        "--exact",
    ])]];
    let substring_batches = vec![vec![owned(&[
        "test",
        "-p",
        "rustfs-gateway-core",
        "--lib",
        "--test",
        "integration",
        "--",
        "--skip",
        "operation_spec_semver::c_dto_n008_operation_spec_requires_its_builder_across_a_crate_boundary",
    ])]];

    assert!(
        unskipped_trybuild_tests(
            &exact_batches,
            &[(
                "integration".to_owned(),
                "compile_fail::p2_01_compile_time_boundaries_are_not_openable".to_owned(),
            )],
        )
        .is_empty()
    );
    assert!(
        unskipped_trybuild_tests(
            &substring_batches,
            &[(
                "integration".to_owned(),
                "operation_spec_semver::c_dto_n008_operation_spec_requires_its_builder_across_a_crate_boundary".to_owned(),
            )],
        )
        .is_empty()
    );
}

#[test]
fn n_unskipped_trybuild_test_is_rejected() {
    let batches = vec![vec![owned(&[
        "test",
        "-p",
        "rustfs-gateway-core",
        "--lib",
        "--test",
        "integration",
        "--",
        "--skip",
        "compile_fail::compile_time_contracts_are_not_openable",
    ])]];

    let leaked = unskipped_trybuild_tests(
        &batches,
        &[(
            "integration".to_owned(),
            "operation_spec_semver::c_dto_n008_operation_spec_requires_its_builder_across_a_crate_boundary".to_owned(),
        )],
    );

    assert_eq!(
        leaked,
        vec!["integration::operation_spec_semver::c_dto_n008_operation_spec_requires_its_builder_across_a_crate_boundary"]
    );
}

#[test]
fn n_exact_mode_rejects_partial_prefix_skip_for_trybuild() {
    let batches = vec![vec![owned(&[
        "test",
        "-p",
        "rustfs-gateway-sig",
        "--",
        "--skip",
        "compile_fail::",
        "--exact",
    ])]];

    let leaked = unskipped_trybuild_tests(
        &batches,
        &[(
            "integration".to_owned(),
            "compile_fail::p2_01_compile_time_boundaries_are_not_openable".to_owned(),
        )],
    );

    assert_eq!(leaked, vec!["integration::compile_fail::p2_01_compile_time_boundaries_are_not_openable"]);
}

#[test]
fn n_trybuild_skip_before_separator_is_not_treated_as_a_libtest_filter() {
    let batches = vec![vec![owned(&[
        "test",
        "-p",
        "rustfs-gateway-sig",
        "--skip",
        "compile_fail::p2_01_compile_time_boundaries_are_not_openable",
    ])]];

    let leaked = unskipped_trybuild_tests(
        &batches,
        &[(
            "integration".to_owned(),
            "compile_fail::p2_01_compile_time_boundaries_are_not_openable".to_owned(),
        )],
    );

    assert_eq!(leaked, vec!["integration::compile_fail::p2_01_compile_time_boundaries_are_not_openable"]);
}

#[test]
fn n_trybuild_in_second_batch_without_skip_is_rejected() {
    let batches = vec![
        vec![owned(&[
            "test",
            "-p",
            "rustfs-gateway",
            "--lib",
            "--test",
            "integration",
            "--",
            "--skip",
            "compile_fail::gateway_compile_fail_contracts_are_enforced",
        ])],
        vec![owned(&["test", "-p", "rustfs-gateway", "--test", "integration"])],
    ];

    let leaked = unskipped_trybuild_tests(
        &batches,
        &[(
            "integration".to_owned(),
            "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
        )],
    );

    assert_eq!(leaked, vec!["integration::compile_fail::gateway_compile_fail_contracts_are_enforced"]);
}

#[test]
fn n_unrelated_test_target_does_not_mask_an_integration_trybuild_leak() {
    let isolated_batches = vec![vec![owned(&["test", "-p", "rustfs-gateway", "--test", "socket_timing"])]];
    let all_targets_batches = vec![vec![owned(&["test", "-p", "rustfs-gateway", "--all-targets"])]];
    let tests = [(
        "integration".to_owned(),
        "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
    )];

    assert!(unskipped_trybuild_tests(&isolated_batches, &tests).is_empty());
    assert_eq!(
        unskipped_trybuild_tests(&all_targets_batches, &tests),
        vec!["integration::compile_fail::gateway_compile_fail_contracts_are_enforced"]
    );
}

#[test]
fn n_trybuild_scanner_detects_direct_and_imported_uses_while_ignoring_comments_and_feature_gates() {
    let source = r#"
        use trybuild::TestCases;

        #[test]
        fn direct_trybuild() {
            let cases = trybuild::TestCases::new();
            cases.compile_fail("tests/a.rs");
        }

        #[test]
        fn imported_trybuild() {
            let cases = TestCases::new();
            cases.pass("tests/b.rs");
        }

        #[cfg(feature = "extra")]
        #[test]
        fn feature_gated_trybuild() {
            let _ = trybuild::TestCases::new();
        }

        #[test]
        fn commented_only() {
            // trybuild::TestCases::new();
            let _ = "trybuild::TestCases";
        }
    "#;

    assert_eq!(
        default_trybuild_tests_in_source(source),
        vec!["direct_trybuild".to_owned(), "imported_trybuild".to_owned()]
    );
}
