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

//! `fuzz-to-case <artifact> [--write]`: a decode_diff fuzz artifact as a conformance case draft.
//!
//! Responsible for: the command line. Prints the draft; with `--write`, writes it under
//! `conformance/cases/_from_fuzz/` (run from the repository root). Exits 0 with a draft, 1 when the
//! artifact no longer reproduces or cannot be converted, 2 on a usage or environment error.
//! NOT responsible for: the conversion (`rustfs_gateway_difftest::fuzz_case`).
//! Upstream: a file `cargo fuzz` wrote. Downstream: a draft a person completes.

use std::path::Path;
use std::process::ExitCode;

use rustfs_gateway_difftest::fuzz_case::{DRAFT_DIR, draft};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (artifact, write) = match arguments.as_slice() {
        [artifact] => (artifact, false),
        [artifact, flag] if flag == "--write" => (artifact, true),
        _ => {
            eprintln!("usage: fuzz-to-case <artifact> [--write]");
            return ExitCode::from(2);
        }
    };
    let input = match std::fs::read(artifact) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("fuzz-to-case: {artifact}: {error}");
            return ExitCode::from(2);
        }
    };
    let (path, text) = match draft(&input, Path::new(DRAFT_DIR)) {
        Ok(draft) => draft,
        Err(error) => {
            eprintln!("fuzz-to-case: {error}");
            return ExitCode::from(1);
        }
    };
    if write {
        if let Err(error) = std::fs::create_dir_all(DRAFT_DIR).and_then(|()| std::fs::write(&path, &text)) {
            eprintln!("fuzz-to-case: {}: {error}", path.display());
            return ExitCode::from(2);
        }
        println!("wrote {}", path.display());
    } else {
        print!("{text}");
    }
    ExitCode::SUCCESS
}
