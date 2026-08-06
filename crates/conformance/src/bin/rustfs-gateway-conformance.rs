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

//! The conformance suite as a standalone command, runnable against any S3 implementation.
//!
//! Responsible for: handing the process arguments to `rustfs_gateway_conformance::cli` and
//! returning its exit code unchanged. This binary is the product surface — it is what a foreign
//! implementation runs against its own server, and it is what `cargo xtask conformance` shells
//! out to, because the layer matrix gives `xtask` no dependency on this crate.
//! NOT responsible for: anything else. Every decision lives in the library.
//! Upstream: `rustfs_gateway_conformance::cli`. Downstream: the shell.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    rustfs_gateway_conformance::cli::main(&args)
}
