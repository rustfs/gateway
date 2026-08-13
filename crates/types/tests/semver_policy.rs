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

//! Cross-crate compiler evidence for ADR-0004's functional-update policy.
//!
//! Responsible for: proving `#[non_exhaustive]` rejects DTO functional update syntax with E0639.
//! NOT responsible for: inspecting generated source text; repository guards own that. Upstream:
//! rustc. Downstream: DTO SemVer policy.

use std::path::PathBuf;
use std::process::Command;

struct ProbeDir(PathBuf);

impl Drop for ProbeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn c_dto_n002_non_exhaustive_blocks_fru_across_a_crate_boundary() {
    let root = ProbeDir(std::env::temp_dir().join(format!("gateway-e0639-{}", std::process::id())));
    std::fs::create_dir_all(&root.0).expect("create compiler probe directory");
    let upstream = root.0.join("upstream.rs");
    let downstream = root.0.join("downstream.rs");
    let library = root.0.join("libdto_semver_probe.rlib");

    std::fs::write(
        &upstream,
        r#"
#[non_exhaustive]
#[derive(Default)]
pub struct Input {
    pub value: Option<String>,
    pub added_later: Option<String>,
}
"#,
    )
    .expect("write upstream probe");
    std::fs::write(
        &downstream,
        r#"
use dto_semver_probe::Input;

fn main() {
    let _ = Input {
        value: Some(String::from("kept")),
        ..Default::default()
    };
}
"#,
    )
    .expect("write downstream probe");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let upstream_output = Command::new(&rustc)
        .args(["--edition=2024", "--crate-name", "dto_semver_probe", "--crate-type", "lib"])
        .arg(&upstream)
        .arg("-o")
        .arg(&library)
        .output()
        .expect("run rustc for upstream probe");
    assert!(
        upstream_output.status.success(),
        "upstream probe failed: {}",
        String::from_utf8_lossy(&upstream_output.stderr)
    );

    let downstream_output = Command::new(&rustc)
        .args(["--edition=2024", "--extern"])
        .arg(format!("dto_semver_probe={}", library.display()))
        .arg(&downstream)
        .arg("-o")
        .arg(root.0.join("downstream"))
        .output()
        .expect("run rustc for downstream probe");
    let stderr = String::from_utf8_lossy(&downstream_output.stderr);
    assert!(!downstream_output.status.success(), "non-exhaustive FRU unexpectedly compiled");
    assert!(stderr.contains("E0639"), "expected E0639, got: {stderr}");
    assert!(
        stderr.contains("cannot create non-exhaustive struct using struct expression"),
        "compiler diagnostic no longer describes the FRU prohibition: {stderr}"
    );
}
