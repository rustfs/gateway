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

//! Profile-specific golden selection contracts through the real corpus and runner.
//!
//! Responsible for: exact profile bytes, strict index validation and confined override reads.
//! NOT responsible for: proving a live backend's behavior or changing the XML emitter.
//! Upstream: corpus loading, runner and the public reference capture in issue #1436.
//! Downstream: the unit-test harness.

use super::*;
use crate::observation::{ConnectionState, Observation};
use crate::sut::Scripted;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT: &str = "goldens/c-acl-0001.xml";
const OVERRIDE: &str = "goldens/rustfs/c-acl-0001.xml";
// Public reference capture: https://github.com/rustfs/gateway/issues/1436#issuecomment-6117268048
// The reference backend emitted these complete bytes; native parity is not asserted here.
const RUSTFS: &[u8] = include_bytes!("profile_golden_tests/acl-rustfs.xml");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "gateway-profile-golden-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("unique fixture directory");
        let fixture = Self(root);
        let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
        for relative in ["case.schema.json", "cases/acl/c-acl-0001.toml", DEFAULT] {
            fixture.write(relative, &std::fs::read(original.join(relative)).expect("repository fixture"));
        }
        fixture.write(OVERRIDE, RUSTFS);
        fixture.index(&format!("[rustfs]\n\"{DEFAULT}\" = \"{OVERRIDE}\"\n"));
        fixture
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directories");
        std::fs::write(path, bytes).expect("fixture write");
    }

    fn index(&self, text: &str) {
        self.write("profile-goldens.toml", text.as_bytes());
    }

    fn default_body(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(self.0.join(DEFAULT)).expect("default golden");
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        bytes
    }

    fn outcome(&self, profile: Profile, body: Vec<u8>) -> CaseOutcome {
        let corpus = Corpus::load(&self.0).expect("valid fixture corpus");
        let mut observation = Observation::response(200, vec![("content-type".into(), "application/xml".into())], body);
        observation.connection_after = Some(ConnectionState::Open);
        let mut sut = Scripted::new().with("c-acl-0001", 0, observation);
        let report = run(
            &corpus,
            &mut sut,
            &RunOptions {
                profile,
                ..RunOptions::default()
            },
        );
        report.outcomes.into_iter().next().expect("the ACL case ran")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned fixture");
    }
}

fn rejects_body(fixture: &Fixture, profile: Profile, body: Vec<u8>) {
    let outcome = fixture.outcome(profile, body);
    assert!(
        outcome.verdict == Verdict::Failed && outcome.diagnostics.iter().any(|d| d.rule == "expect/body.golden"),
        "expected an exact-body rejection: {outcome:?}"
    );
}

fn rejects_index(fixture: &Fixture, text: &str, reason: &[&str]) {
    // First prove the unchanged corpus and valid mapping are usable. Only the index changes below.
    let healthy = Corpus::load(&fixture.0).expect("valid index control before corruption");
    assert_eq!(healthy.cases().len(), 1, "the ACL control case must exist");
    assert!(healthy.cases()[0].diagnostics.is_empty(), "the control case must validate");
    fixture.index(text);
    let error = match Corpus::load(&fixture.0) {
        Err(error) => error,
        Ok(_) => panic!("invalid index must fail corpus loading"),
    };
    assert!(
        error.message.contains("profile-goldens.toml") && reason.iter().all(|fragment| error.message.contains(fragment)),
        "expected index rejection identifying {reason:?}: {error}"
    );
}

#[test]
fn a_default_run_keeps_the_complete_default_golden() {
    let fixture = Fixture::new();
    assert_eq!(fixture.outcome(Profile::Aws, fixture.default_body()).verdict, Verdict::Passed);
}

#[test]
fn a_rustfs_run_uses_only_its_declared_golden() {
    let fixture = Fixture::new();
    assert_eq!(fixture.outcome(Profile::Rustfs, RUSTFS.to_vec()).verdict, Verdict::Passed);
}

#[test]
fn an_absent_optional_index_keeps_default_behavior() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.0.join("profile-goldens.toml")).expect("remove optional index");
    assert_eq!(fixture.outcome(Profile::Rustfs, fixture.default_body()).verdict, Verdict::Passed);
}

#[test]
fn an_unmapped_profile_does_not_inherit_rustfs() {
    let fixture = Fixture::new();
    rejects_body(&fixture, Profile::Minio, RUSTFS.to_vec());
}

#[test]
fn default_rejects_the_rustfs_body() {
    rejects_body(&Fixture::new(), Profile::Aws, RUSTFS.to_vec());
}

#[test]
fn rustfs_rejects_the_default_body() {
    let fixture = Fixture::new();
    rejects_body(&fixture, Profile::Rustfs, fixture.default_body());
}

#[test]
fn a_missing_declared_override_cannot_fall_back() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.0.join(OVERRIDE)).expect("remove declared target");
    let outcome = fixture.outcome(Profile::Rustfs, fixture.default_body());
    assert!(
        outcome.verdict == Verdict::Failed
            && outcome
                .diagnostics
                .iter()
                .any(|d| d.rule == "expect/body.golden" && d.message.contains(OVERRIDE)),
        "{outcome:?}"
    );
}

fn rejects_damage(profile: Profile, removed: &str) {
    let fixture = Fixture::new();
    let body = if profile == Profile::Rustfs {
        RUSTFS.to_vec()
    } else {
        fixture.default_body()
    };
    assert_eq!(fixture.outcome(profile, body.clone()).verdict, Verdict::Passed);
    let text = String::from_utf8(body).expect("XML fixture");
    let damaged = if removed.is_empty() {
        format!("{text} ")
    } else {
        text.replace(removed, "")
    };
    rejects_body(&fixture, profile, damaged.into_bytes());
}

#[test]
fn default_rejects_root_namespace_damage() {
    rejects_damage(Profile::Aws, r#" xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#);
}

#[test]
fn default_rejects_discriminator_damage() {
    rejects_damage(Profile::Aws, r#" xsi:type="CanonicalUser""#);
}

#[test]
fn default_rejects_grantee_namespace_damage() {
    rejects_damage(Profile::Aws, r#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#);
}

#[test]
fn default_rejects_extra_byte_damage() {
    rejects_damage(Profile::Aws, r#""#);
}

#[test]
fn rustfs_rejects_root_namespace_damage() {
    rejects_damage(Profile::Rustfs, r#" xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#);
}

#[test]
fn rustfs_rejects_discriminator_damage() {
    rejects_damage(Profile::Rustfs, r#" xsi:type="CanonicalUser""#);
}

#[test]
fn rustfs_rejects_grantee_namespace_damage() {
    rejects_damage(Profile::Rustfs, r#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#);
}

#[test]
fn rustfs_rejects_extra_byte_damage() {
    rejects_damage(Profile::Rustfs, r#""#);
}

#[test]
fn rejects_malformed_index() {
    rejects_index(&Fixture::new(), r#"[rustfs"#, &["table header"]);
}

#[test]
fn rejects_duplicate_index() {
    rejects_index(
        &Fixture::new(),
        r#"[rustfs]
"goldens/c-acl-0001.xml" = "goldens/rustfs/c-acl-0001.xml"
"goldens/c-acl-0001.xml" = "goldens/rustfs/c-acl-0001.xml""#,
        &["duplicate", "goldens/c-acl-0001.xml"],
    );
}

#[test]
fn rejects_unknown_profile_index() {
    rejects_index(
        &Fixture::new(),
        r#"[unknown]
"goldens/c-acl-0001.xml" = "goldens/rustfs/c-acl-0001.xml""#,
        &["unknown profile", "unknown"],
    );
}

#[test]
fn rejects_unknown_reference_index() {
    let fixture = Fixture::new();
    // Both files exist: absence from case expectations, not missing file I/O, is the defect.
    fixture.write("goldens/unknown.xml", RUSTFS);
    rejects_index(
        &fixture,
        r#"[rustfs]
"goldens/unknown.xml" = "goldens/rustfs/c-acl-0001.xml""#,
        &["not referenced", "goldens/unknown.xml"],
    );
}

#[test]
fn rejects_non_string_index() {
    rejects_index(
        &Fixture::new(),
        r#"[rustfs]
"goldens/c-acl-0001.xml" = 1"#,
        &["goldens/c-acl-0001.xml", "string"],
    );
}

#[test]
fn rejects_non_table_index() {
    rejects_index(&Fixture::new(), r#"rustfs = 1"#, &["rustfs", "table"]);
}

#[test]
fn rejects_absolute_index() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    let target = outside.0.join(DEFAULT);
    assert!(target.is_file(), "absolute target exists before path validation");
    rejects_index(&fixture, &format!("[rustfs]\n\"{DEFAULT}\" = \"{}\"", target.display()), &["relative"]);
}

#[test]
fn rejects_parent_index() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    let sibling = outside
        .0
        .file_name()
        .expect("sibling fixture name")
        .to_str()
        .expect("ASCII fixture name");
    let target = format!("../{sibling}/{DEFAULT}");
    assert!(fixture.0.join(&target).is_file(), "parent target exists before path validation");
    rejects_index(&fixture, &format!("[rustfs]\n\"{DEFAULT}\" = \"{target}\""), &["parent"]);
}

#[cfg(unix)]
#[test]
fn an_override_symlink_cannot_leave_the_corpus() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    std::fs::remove_file(fixture.0.join(OVERRIDE)).expect("remove local override");
    std::os::unix::fs::symlink(outside.0.join(DEFAULT), fixture.0.join(OVERRIDE)).expect("outside symlink");
    rejects_body(&fixture, Profile::Rustfs, outside.default_body());
}

#[test]
fn an_event_only_golden_mapping_loads() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.0.join("cases/acl/c-acl-0001.toml")).expect("remove ordinary reference");
    let original =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases/select-restore/c-select-restore-0046.toml");
    let text = std::fs::read_to_string(original).expect("existing event case");
    assert_eq!(text.matches("exact_utf8 = \"789\"").count(), 1, "event fixture marker moved");
    let text = text.replace("exact_utf8 = \"789\"", "golden = \"goldens/event.txt\"");
    fixture.write("cases/select-restore/c-select-restore-0046.toml", text.as_bytes());
    fixture.write("goldens/event.txt", b"789");
    fixture.write("goldens/rustfs/event.txt", b"789");
    fixture.index("[rustfs]\n\"goldens/event.txt\" = \"goldens/rustfs/event.txt\"\n");
    let corpus = Corpus::load(&fixture.0).expect("event-only reference is a valid mapping key");
    assert_eq!(corpus.cases().len(), 1, "the fixture must load exactly one case");
    let case = &corpus.cases()[0];
    assert_eq!(case.id, "c-select-restore-0046", "event fixture identity");
    let exchanges = case.exchanges();
    let events = exchanges[0]
        .expect
        .expect("event expectation")
        .read("expect.events")
        .and_then(Value::as_array)
        .expect("event expectations");
    let reference = events[0]
        .read("expect.events[].payload")
        .and_then(|payload| payload.read("bodyExpectation.golden"))
        .and_then(Value::as_str);
    assert_eq!(reference, Some("goldens/event.txt"), "event-only golden is present");
    assert!(
        corpus.cases().iter().all(|case| case.diagnostics.is_empty()),
        "schema-valid event fixture required"
    );
}
