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

//! The `decode-diff` runner: the decode diff over the recorded corpus or the built-in matrix.
//!
//! Responsible for: nothing but calling the shared runner and exiting with its status.
//! NOT responsible for: the command line, the run or the report (`runner.rs`).
//! Upstream: `rustfs_gateway_difftest::runner`. Downstream: CI and operators.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(rustfs_gateway_difftest::runner::main(
        "decode-diff",
        rustfs_gateway_difftest::runner::decode,
    ))
}
