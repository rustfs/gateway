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

//! Rust-aware enforcement of ADR-0004's `OperationSpec` builder policy.
//!
//! Responsible for: finding direct or syntactically aliased `OperationSpec` struct expressions in
//! tracked or new Rust source. NOT responsible for: full Rust name resolution, macro expansion,
//! type-checking, or registry validation. Upstream: Git and `syn`. Downstream:
//! `scripts/check_operation_spec_builder.sh`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{Type, UseTree};

const ALLOWED_LITERAL: &str = "crates/core/tests/compile_fail/operation_spec_literal.rs";
const DEFINITION_FILE: &str = "crates/core/src/registry/mod.rs";

pub(crate) fn check(args: &[String]) -> ExitCode {
    let [root] = args else {
        eprintln!("usage: cargo xtask check-operation-spec-builder <repository-root>");
        return ExitCode::from(2);
    };
    let root = Path::new(root);
    let output = match Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.rs"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            eprintln!("check_operation_spec_builder: git source enumeration failed: {}", output.status);
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("check_operation_spec_builder: cannot run git: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut violations = 0_usize;
    for raw in output.stdout.split(|byte| *byte == 0).filter(|raw| !raw.is_empty()) {
        let relative = PathBuf::from(String::from_utf8_lossy(raw).as_ref());
        if excluded(&relative) {
            continue;
        }
        let path = root.join(&relative);
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("check_operation_spec_builder: cannot read {}: {error}", relative.display());
                return ExitCode::FAILURE;
            }
        };
        if !source.contains("OperationSpec") {
            continue;
        }
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("check_operation_spec_builder: cannot parse {}: {error}", relative.display());
                return ExitCode::FAILURE;
            }
        };
        let aliases = match operation_spec_aliases(&relative, &file) {
            Ok(aliases) => aliases,
            Err(error) => {
                eprintln!("check_operation_spec_builder: {}:{error}", relative.display());
                return ExitCode::FAILURE;
            }
        };
        let mut finder = LiteralFinder {
            relative: &relative,
            aliases: &aliases,
            violations: &mut violations,
        };
        finder.visit_file(&file);
    }

    if violations != 0 {
        eprintln!("ADR-0004 P9: construct OperationSpec with OperationSpec::builder(...).");
        ExitCode::FAILURE
    } else {
        println!("OK: every OperationSpec construction uses the additive builder");
        ExitCode::SUCCESS
    }
}

fn excluded(path: &Path) -> bool {
    path == Path::new(ALLOWED_LITERAL) || path.starts_with("generated") || path.starts_with(Path::new("crates/types/generated"))
}

#[derive(Debug)]
struct Binding {
    source: Vec<String>,
    local: String,
}

#[derive(Default)]
struct AliasCollector {
    use_bindings: Vec<Binding>,
    type_bindings: Vec<Binding>,
    globs: Vec<(Vec<String>, usize)>,
}

impl<'ast> Visit<'ast> for AliasCollector {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_tree(Vec::new(), &item.tree, self);
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let Some(path) = simple_type_path(&item.ty) {
            self.type_bindings.push(Binding {
                source: path.segments.iter().map(|segment| segment.ident.to_string()).collect(),
                local: item.ident.to_string(),
            });
        }
        visit::visit_item_type(self, item);
    }
}

fn collect_use_tree(mut prefix: Vec<String>, tree: &UseTree, collector: &mut AliasCollector) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(prefix, &path.tree, collector);
        }
        UseTree::Name(name) => {
            let source_name = name.ident.to_string();
            prefix.push(source_name.clone());
            collector.use_bindings.push(Binding {
                source: prefix,
                local: source_name,
            });
        }
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            collector.use_bindings.push(Binding {
                source: prefix,
                local: rename.rename.to_string(),
            });
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(prefix.clone(), item, collector);
            }
        }
        UseTree::Glob(glob) => collector.globs.push((prefix, glob.span().start().line)),
    }
}

fn simple_type_path(ty: &Type) -> Option<&syn::Path> {
    match ty {
        Type::Path(path) if path.qself.is_none() => Some(&path.path),
        Type::Group(group) => simple_type_path(&group.elem),
        Type::Paren(paren) => simple_type_path(&paren.elem),
        _ => None,
    }
}

#[derive(Default)]
struct ResolvedAliases {
    type_names: HashSet<String>,
    module_names: HashSet<String>,
}

fn operation_spec_aliases(relative: &Path, file: &syn::File) -> Result<ResolvedAliases, String> {
    let mut collector = AliasCollector::default();
    collector.visit_file(file);

    let mut aliases = ResolvedAliases::default();
    if relative == Path::new(DEFINITION_FILE) {
        aliases.type_names.insert(String::from("OperationSpec"));
    }

    loop {
        let mut changed = false;
        for binding in &collector.use_bindings {
            if module_path_resolves(relative, &binding.source, &aliases.module_names) {
                changed |= aliases.module_names.insert(binding.local.clone());
            }
        }
        for binding in &collector.use_bindings {
            if type_path_resolves(relative, &binding.source, &aliases) {
                changed |= aliases.type_names.insert(binding.local.clone());
            }
        }
        for binding in &collector.type_bindings {
            if type_path_resolves(relative, &binding.source, &aliases) {
                changed |= aliases.type_names.insert(binding.local.clone());
            }
        }
        if !changed {
            break;
        }
    }

    for (prefix, line) in &collector.globs {
        if module_path_resolves(relative, prefix, &aliases.module_names) {
            return Err(format!(
                "{line}: wildcard import from the OperationSpec namespace cannot be resolved safely"
            ));
        }
    }

    Ok(aliases)
}

fn type_path_resolves(relative: &Path, source: &[String], aliases: &ResolvedAliases) -> bool {
    canonical_path(relative, source)
        || source.split_last().is_some_and(|(name, prefix)| {
            (aliases.type_names.contains(name) && prefix.iter().all(|segment| segment == "self" || segment == "super"))
                || (name == "OperationSpec" && module_path_resolves(relative, prefix, &aliases.module_names))
        })
}

fn module_path_resolves(relative: &Path, source: &[String], module_names: &HashSet<String>) -> bool {
    canonical_namespace(relative, source)
        || source.split_last().is_some_and(|(name, prefix)| {
            module_names.contains(name) && prefix.iter().all(|segment| segment == "self" || segment == "super")
        })
}

fn canonical_path(relative: &Path, segments: &[String]) -> bool {
    match segments {
        [root, name] if root == "rustfs_gateway_core" && name == "OperationSpec" => true,
        [root, name] if root == "rustfs_gateway" && name == "OperationSpec" => true,
        [root, name] if root == "crate" && name == "OperationSpec" => {
            relative.starts_with(Path::new("crates/core")) || relative.starts_with(Path::new("crates/gateway"))
        }
        [root, module, name] if root == "crate" && module == "registry" && name == "OperationSpec" => {
            relative.starts_with(Path::new("crates/core"))
        }
        _ => false,
    }
}

fn canonical_namespace(relative: &Path, segments: &[String]) -> bool {
    matches!(segments, [root] if root == "rustfs_gateway_core" || root == "rustfs_gateway")
        || matches!(segments, [root] if root == "crate" && (relative.starts_with(Path::new("crates/core")) || relative.starts_with(Path::new("crates/gateway"))))
        || matches!(segments, [root, module] if root == "crate" && module == "registry" && relative.starts_with(Path::new("crates/core")))
}

struct LiteralFinder<'a> {
    relative: &'a Path,
    aliases: &'a ResolvedAliases,
    violations: &'a mut usize,
}

impl<'ast> Visit<'ast> for LiteralFinder<'_> {
    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        let path: Vec<String> = expression
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if type_path_resolves(self.relative, &path, self.aliases) {
            let line = expression.path.span().start().line;
            eprintln!("{}:{line}: OperationSpec struct literal bypasses its builder", self.relative.display());
            *self.violations += 1;
        }
        visit::visit_expr_struct(self, expression);
    }
}
