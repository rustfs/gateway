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

//! Fresh-checkout bootstrap with stable failure classes.
//!
//! Responsible for: fetching pinned dependencies, checking generated output, and warming test
//! compilation within five minutes. NOT responsible for: installing a Rust toolchain.
//! Upstream: the `bootstrap` command. Downstream: Cargo and codegen.

use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use crate::codegen;

pub(crate) fn bootstrap(args: &[String]) -> ExitCode {
    let json = matches!(args, [flag] if flag == "--json");
    if !args.is_empty() && !json {
        eprintln!("usage: cargo xtask bootstrap");
        return ExitCode::from(2);
    }
    let started = Instant::now();
    let stage = Stage::start("toolchain check");
    for tool in [["--version"].as_slice(), ["rustc", "--version"].as_slice()] {
        let (program, arguments) = if tool.len() == 1 {
            (env!("CARGO"), tool)
        } else {
            (tool[0], &tool[1..])
        };
        match Command::new(program).args(arguments).output() {
            Ok(output) if output.status.success() => {}
            Ok(_) | Err(_) => {
                eprintln!("bootstrap: required Rust tool `{program}` is unavailable; install the pinned toolchain");
                return ExitCode::from(3);
            }
        }
    }
    drop(stage);
    let stage = Stage::start("dependency fetch");
    match Command::new(env!("CARGO")).args(["fetch", "--locked"]).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!("bootstrap: dependency fetch failed ({}); check network access and retry", output.status);
            return ExitCode::from(3);
        }
        Err(error) => {
            eprintln!("bootstrap: dependency fetch could not start: {error}");
            return ExitCode::from(3);
        }
    }
    drop(stage);
    let root = codegen::repo_root();
    let stage = Stage::start("pinned model verification");
    match Command::new("python3")
        .arg(root.join("model/tools/verify.py"))
        .current_dir(&root)
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(_) => {
            eprintln!("bootstrap: pinned model SHA or checksum disagrees with model/PROVENANCE.md");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("bootstrap: python3 is required to verify the pinned model: {error}");
            return ExitCode::from(3);
        }
    }
    drop(stage);
    let stage = Stage::start("generated artifact verification");
    match codegen::verify_generated() {
        Ok(count) if !json => println!("bootstrap: verified {count} generated artifacts"),
        Ok(_) => {}
        Err(error) => {
            eprintln!("bootstrap: generated artifacts drifted; run `cargo xtask codegen` and inspect the diff: {error}");
            return ExitCode::FAILURE;
        }
    }
    drop(stage);
    let stage = Stage::start("workspace test compilation");
    let compile = Command::new(env!("CARGO"))
        .args(["test", "--workspace", "--no-run"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match compile {
        Ok(status) if !status.success() => return ExitCode::FAILURE,
        Err(error) => {
            eprintln!("bootstrap: cargo test could not start: {error}");
            return ExitCode::FAILURE;
        }
        Ok(_) => {}
    }
    drop(stage);
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(300) {
        eprintln!("bootstrap: exceeded the five-minute budget ({:.2}s)", elapsed.as_secs_f64());
        return ExitCode::FAILURE;
    }
    if json {
        println!(
            "{{\"command\":\"bootstrap\",\"ok\":true,\"elapsed_seconds\":{:.3}}}",
            elapsed.as_secs_f64()
        );
    } else {
        println!("bootstrap: ready in {:.2}s", elapsed.as_secs_f64());
    }
    ExitCode::SUCCESS
}

/// Reports each entered stage even when an early failure returns from bootstrap.
struct Stage {
    name: &'static str,
    started: Instant,
}

impl Stage {
    fn start(name: &'static str) -> Self {
        eprintln!("bootstrap: {name} started");
        Self {
            name,
            started: Instant::now(),
        }
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        eprintln!("bootstrap: {} finished in {:.2}s", self.name, self.started.elapsed().as_secs_f64());
    }
}
