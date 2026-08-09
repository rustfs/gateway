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

//! Intentionally-red operation scaffold creation.
//!
//! Responsible for: validating names, writing the operation/case/registry scaffold, and proving
//! the generated handler fails at its `todo!()`. NOT responsible for: operation semantics.
//! Upstream: the `new-op` command. Downstream: core operations, conformance cases, and verify.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::catalog;
use crate::codegen::repo_root;

const OPERATION: &str = include_str!("../templates/operation.rs.tmpl");
const TEST: &str = include_str!("../templates/operation_test.rs.tmpl");
const CASE: &str = include_str!("../templates/conformance.toml.tmpl");
const MANIFEST: &str = include_str!("../templates/manifest.toml.tmpl");
const MARKER: &str = "SCAFFOLD: implement before merge";

pub(crate) fn new_op(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let json = args.iter().position(|argument| argument == "--json");
    if let Some(index) = json {
        args.remove(index);
    }
    let [name] = args.as_slice() else {
        eprintln!("usage: cargo xtask new-op <UpperCamelOperation>");
        return ExitCode::from(2);
    };
    if !valid_name(name) {
        eprintln!("InvalidOperationName: expected ASCII UpperCamelCase, got `{name}`");
        return ExitCode::from(2);
    }
    let operations = match catalog::operations() {
        Ok(operations) => operations,
        Err(error) => return failure("operation catalog could not be loaded", "model and overlays", &error),
    };
    if operations.iter().any(|operation| operation.operation == *name) {
        eprintln!("NameCollision: `{name}` is already a standard operation");
        return ExitCode::from(2);
    }
    let snake = snake_case(name);
    let root = repo_root();
    let paths = ScaffoldPaths::new(&root, &snake);
    if let Some(path) = paths.created.iter().find(|path| path.exists()) {
        eprintln!("NameCollision: {} already exists", path.display());
        return ExitCode::from(2);
    }
    let old_modules = match fs::read_to_string(&paths.modules) {
        Ok(body) => body,
        Err(error) => return failure("operation registry could not be read", &paths.modules.display().to_string(), &error),
    };
    let module_line = format!("pub mod {snake}; // {MARKER}");
    if old_modules.contains(&format!("pub mod {snake};")) {
        eprintln!("NameCollision: module `{snake}` is already registered");
        return ExitCode::from(2);
    }
    let rendered = [
        (&paths.operation, render(OPERATION, name, &snake)),
        (&paths.test, render(TEST, name, &snake)),
        (&paths.case, render(CASE, name, &snake)),
        (&paths.manifest, render(MANIFEST, name, &snake)),
    ];
    if let Err(error) = write_scaffold(&rendered, &paths.modules, &old_modules, &module_line) {
        rollback(&paths, &old_modules);
        return failure("scaffold files could not be written", &root.display().to_string(), &error);
    }
    match must_fail_at_todo(&snake) {
        Ok(()) => {
            if let Err(error) = must_verify_red(name) {
                rollback(&paths, &old_modules);
                return failure(
                    "generated operation did not make verify --op red",
                    &format!("xtask/scaffolds/{snake}.toml"),
                    &error,
                );
            }
            if json.is_some() {
                println!("{{\"command\":\"new-op\",\"operation\":\"{name}\",\"ok\":true,\"verify_red\":true}}");
            } else {
                println!("new-op: `{name}` generated and verified red at its todo!() handler");
                for path in &paths.created {
                    println!("  {}", relative(&root, path));
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            rollback(&paths, &old_modules);
            failure(
                "new operation scaffold did not fail at its todo!() handler",
                &format!("crates/core/tests/scaffold_{snake}.rs"),
                &error,
            )
        }
    }
}

fn must_verify_red(name: &str) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| format!("xtask executable is unavailable: {error}"))?;
    let output = Command::new(executable)
        .args(["verify", "--op", name])
        .output()
        .map_err(|error| format!("verify could not start: {error}"))?;
    if output.status.code() != Some(1) {
        return Err(format!("expected verify exit 1, observed {}", output.status));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("intentionally unimplemented") {
        return Err("verify was red for a reason other than the scaffold todo!()".to_owned());
    }
    Ok(())
}

fn write_scaffold(rendered: &[(&PathBuf, String)], modules: &Path, old_modules: &str, module_line: &str) -> Result<(), String> {
    for (path, body) in rendered {
        let parent = path.parent().ok_or_else(|| format!("{} has no parent", path.display()))?;
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        fs::write(path, body).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    let mut body = old_modules.trim_end().to_owned();
    body.push('\n');
    body.push_str(module_line);
    body.push('\n');
    fs::write(modules, body).map_err(|error| format!("{}: {error}", modules.display()))
}

fn must_fail_at_todo(snake: &str) -> Result<(), String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "rustfs-gateway-core",
            "--test",
            &format!("scaffold_{snake}"),
            "scaffold_must_be_red",
            "--",
            "--exact",
        ])
        .output()
        .map_err(|error| format!("cargo could not start: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        return Err("the must-red test passed; refusing a fake-green scaffold".to_owned());
    }
    if !stderr.contains("SCAFFOLD handler is not implemented") && !stdout.contains("SCAFFOLD handler is not implemented") {
        return Err(format!("the test failed for the wrong reason: {}", concise(&stderr)));
    }
    Ok(())
}

fn rollback(paths: &ScaffoldPaths, old_modules: &str) {
    for path in &paths.created {
        let _ = fs::remove_file(path);
    }
    let _ = fs::write(&paths.modules, old_modules);
}

struct ScaffoldPaths {
    operation: PathBuf,
    test: PathBuf,
    case: PathBuf,
    manifest: PathBuf,
    modules: PathBuf,
    created: [PathBuf; 4],
}

impl ScaffoldPaths {
    fn new(root: &Path, snake: &str) -> Self {
        let operation = root.join(format!("crates/core/src/ops/{snake}.rs"));
        let test = root.join(format!("crates/core/tests/scaffold_{snake}.rs"));
        let case = root.join(format!("conformance/cases/scaffold/{snake}_smoke.toml"));
        let manifest = root.join(format!("xtask/scaffolds/{snake}.toml"));
        let created = [operation.clone(), test.clone(), case.clone(), manifest.clone()];
        Self {
            operation,
            test,
            case,
            manifest,
            modules: root.join("crates/core/src/ops/mod.rs"),
            created,
        }
    }
}

fn render(template: &str, name: &str, snake: &str) -> String {
    template.replace("{{NAME}}", name).replace("{{SNAKE}}", snake)
}

fn valid_name(name: &str) -> bool {
    name.len() >= 2
        && name.bytes().next().is_some_and(|byte| byte.is_ascii_uppercase())
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && name.bytes().any(|byte| byte.is_ascii_lowercase())
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (index, byte) in name.bytes().enumerate() {
        if index != 0 && byte.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(char::from(byte.to_ascii_lowercase()));
    }
    out
}

fn concise(value: &str) -> String {
    value
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no diagnostic")
        .to_owned()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).display().to_string()
}

fn failure(what: &str, where_: &str, rule: &impl std::fmt::Display) -> ExitCode {
    eprintln!("what: {what}");
    eprintln!("where: {where_}");
    eprintln!("rule: a-xt-0010 must-red scaffold; {rule}");
    ExitCode::FAILURE
}
