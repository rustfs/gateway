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

//! Responsible for: proving parent parity wiring uses independent metadata and both child results.
//! NOT responsible for: HTTP transport observations; these child processes emit explicit fixtures.
//! Upstream: the parity CLI orchestration; downstream: census and exit-code boundary controls.

use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    directory: PathBuf,
    executable: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn fixture(hyper: &str, conn: &str, hyper_exit: u8, conn_exit: u8, write_conn: bool) -> Fixture {
    let directory = parity_directory().expect("temporary fixture directory");
    let executable = directory.join("child.sh");
    let script = format!(
        r#"#!/bin/sh
transport=
report=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --transport) transport="$2"; shift ;;
    --json) report="$2"; shift ;;
  esac
  shift
done
if [ "$transport" = hyper ]; then
  cat > "$report" <<'HYPER_REPORT'
{hyper}
HYPER_REPORT
  exit {hyper_exit}
fi
if [ "{write_conn}" = true ]; then
  cat > "$report" <<'CONN_REPORT'
{conn}
CONN_REPORT
fi
exit {conn_exit}
"#
    );
    std::fs::write(&executable, script).expect("write child fixture");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).expect("executable child fixture");
    Fixture { directory, executable }
}

fn report(id: &str, verdict: &str, reason: &str) -> String {
    format!(r#"{{"cases":[{{"id":"{id}","verdict":"{verdict}","phase":"execute","reason":"{reason}","failures":[]}}]}}"#)
}
const REASON: &str = "environment: the production self-held driver speaks HTTP/1.1 only; authored HTTP/2 frames run on the production Hyper driver";

fn drive(id: &str, fixture: &Fixture) -> ExitCode {
    let args = ["diff-transports", "--filter", id].map(str::to_owned);
    let options = Options::parse(&args).expect("CLI options").expect("not help");
    let root = crate::corpus::Corpus::discover_root().expect("real corpus metadata");
    execute_transport_diff_with_executable(&options, root, &fixture.executable)
}

#[test]
fn parent_accepts_a_complete_capability_pair_after_loading_the_selected_case() {
    let id = "c-h2-0001";
    let fixture = fixture(&report(id, "passed", ""), &report(id, "skipped", REASON), 0, 3, true);
    assert_eq!(drive(id, &fixture), ExitCode::SUCCESS);
}

#[test]
fn parent_rejects_both_children_omitting_the_selected_case() {
    let fixture = fixture(r#"{"cases":[]}"#, r#"{"cases":[]}"#, 0, 0, true);
    assert_ne!(drive("c-h2-0001", &fixture), ExitCode::SUCCESS);
}

#[test]
fn parent_does_not_infer_capability_from_child_refusal_text() {
    let id = "c-cors-0043";
    let fixture = fixture(&report(id, "passed", ""), &report(id, "skipped", REASON), 0, 3, true);
    assert_ne!(drive(id, &fixture), ExitCode::SUCCESS);
}

#[test]
fn parent_rejects_hyper_environment_exit_even_with_plausible_reports() {
    let id = "c-h2-0001";
    let fixture = fixture(&report(id, "passed", ""), &report(id, "skipped", REASON), 3, 3, true);
    assert_ne!(drive(id, &fixture), ExitCode::SUCCESS);
}

#[test]
fn parent_rejects_a_missing_report_instead_of_accepting_exit_three() {
    let id = "c-h2-0001";
    let fixture = fixture(&report(id, "passed", ""), &report(id, "skipped", REASON), 0, 3, false);
    assert_ne!(drive(id, &fixture), ExitCode::SUCCESS);
}

#[test]
fn parent_rejects_wrong_refusal_and_failed_hyper_observations() {
    let id = "c-h2-0001";
    for (hyper, conn) in [
        (report(id, "passed", ""), report(id, "skipped", "environment: connect failed")),
        (report(id, "failed", ""), report(id, "skipped", REASON)),
    ] {
        let fixture = fixture(&hyper, &conn, 0, 3, true);
        assert_ne!(drive(id, &fixture), ExitCode::SUCCESS);
    }
}
