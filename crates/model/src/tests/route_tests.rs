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

//! Tests for `overlays/route.toml`: what a shadowing declaration must carry, and what it may not.
//!
//! Responsible for: the refusals in [`crate::overlay`]'s route reader — the missing field, the
//! dangling reference, the dead reference, the duplicate pair, the paragraph written twice.
//! NOT responsible for: whether the two selectors really overlap. That is decided in
//! `rustfs-gateway-core` at table-build time against the compiled table, and no amount of TOML
//! can answer it.
//! Upstream: the reader under test. Downstream: the repository verification gate.
//!
//! Almost every case here is a negative, because the file is hand-written data whose whole risk is
//! a rule that is present, wrong, and ignored. The one positive is the real overlay: a fixture
//! that parses proves the grammar, and only the checked-in file proves the grammar is the one the
//! repository actually writes in.

use std::path::{Path, PathBuf};

use crate::overlay::{Overlay, ROUTE_FILE};

/// A throwaway overlay directory holding one route file. Removed on drop.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str, route: &str) -> Self {
        let root = std::env::temp_dir().join(format!("gateway-route-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ops")).expect("test sandbox is creatable");
        std::fs::create_dir_all(root.join("quirks")).expect("test sandbox is creatable");
        std::fs::write(root.join("scalars.toml"), "[scalar]\nETag = \"ETag\"\n").expect("test sandbox is writable");
        std::fs::write(
            root.join("ops/family.toml"),
            "include = [\"Alpha\", \"Beta\"]\n\n[op.Alpha]\nprecedence = 1\n\n[op.Beta]\nprecedence = 2\n",
        )
        .expect("test sandbox is writable");
        std::fs::write(
            root.join("quirks/family.toml"),
            "[[quirk]]\nid = \"q-base-0001\"\nkind = \"note\"\nclassification = \"contract\"\n\
             target = \"Alpha\"\nsummary = \"a placeholder record so the directory is not empty\"\n\
             cases = [\"c-base-0001\"]\n\n  [[quirk.evidence]]\n  kind = \"observed\"\n  ref = \"local\"\n\
             \x20 summary = \"a placeholder record so the directory is not empty\"\n",
        )
        .expect("test sandbox is writable");
        std::fs::write(root.join(ROUTE_FILE), route).expect("test sandbox is writable");
        Self { root }
    }

    fn load(&self) -> Result<Overlay, String> {
        Overlay::load(&self.root).map_err(|error| error.to_string())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const EVIDENCE: &str = "\
[evidence.alpha]
url = \"https://docs.aws.amazon.com/AmazonS3/latest/API/API_Alpha.html\"
summary = \"Alpha is selected by the ?alpha subresource alone.\"

[evidence.beta]
url = \"https://docs.aws.amazon.com/AmazonS3/latest/API/API_Beta.html\"
summary = \"Beta is selected by the ?beta subresource alone.\"
";

const REASON: &str = "Alpha and Beta name two subresources of one bucket, and the earlier row answers.";

fn one(fields: &str) -> String {
    format!("{EVIDENCE}\n[[shadowing]]\n{fields}")
}

fn refuses(name: &str, route: String, fragment: &str) {
    let sandbox = Sandbox::new(name, &route);
    let error = sandbox.load().expect_err("the route overlay is refused");
    assert!(error.contains(fragment), "expected {fragment:?} in: {error}");
}

#[test]
fn reads_a_complete_declaration() {
    let sandbox = Sandbox::new(
        "complete",
        &one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\", \"beta\"]\n"
        )),
    );
    let overlay = sandbox.load().expect("a complete declaration loads");
    assert_eq!(overlay.shadowing.len(), 1);
    let decl = &overlay.shadowing[0];
    assert_eq!(decl.winner, "Alpha");
    assert_eq!(decl.shadowed, "Beta");
    assert_eq!(decl.reason, REASON);
    assert_eq!(
        decl.evidence,
        vec![
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Alpha.html — Alpha is selected by the ?alpha subresource alone."
                .to_owned(),
            "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Beta.html — Beta is selected by the ?beta subresource alone."
                .to_owned(),
        ]
    );
}

#[test]
fn resolves_a_shared_reason_through_its_id() {
    let route = format!(
        "{EVIDENCE}\n[reason.two-keys]\ntext = \"{REASON}\"\n\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason_ref = \"two-keys\"\nevidence = [\"alpha\", \"beta\"]\n"
    );
    let sandbox = Sandbox::new("shared-reason", &route);
    let overlay = sandbox.load().expect("a shared reason resolves");
    assert_eq!(overlay.shadowing[0].reason, REASON);
}

#[test]
fn n_refuses_a_missing_route_file() {
    let sandbox = Sandbox::new("missing", "");
    std::fs::remove_file(sandbox.root.join(ROUTE_FILE)).expect("the fixture file is removable");
    let error = sandbox.load().expect_err("a missing authority is a failure");
    assert!(error.contains("route.toml"), "expected the path in: {error}");
}

#[test]
fn n_refuses_a_declaration_with_no_reason() {
    refuses(
        "no-reason",
        one("winner = \"Alpha\"\nshadowed = \"Beta\"\nevidence = [\"alpha\"]\n"),
        "carries neither `reason` nor `reason_ref`",
    );
}

#[test]
fn n_refuses_a_declaration_with_no_evidence_key() {
    refuses(
        "no-evidence",
        one(&format!("winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\n")),
        "carries no `evidence`",
    );
}

#[test]
fn n_refuses_a_declaration_with_an_empty_evidence_list() {
    refuses(
        "empty-evidence",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = []\n"
        )),
        "empty `evidence` list",
    );
}

#[test]
fn n_refuses_a_declaration_carrying_both_a_reason_and_a_reference() {
    let route = format!(
        "{EVIDENCE}\n[reason.two-keys]\ntext = \"{REASON}\"\n\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\n\
         reason_ref = \"two-keys\"\nevidence = [\"alpha\", \"beta\"]\n"
    );
    refuses("both-reasons", route, "carries both `reason` and `reason_ref`");
}

#[test]
fn n_refuses_the_same_paragraph_written_inline_twice() {
    let route = format!(
        "{EVIDENCE}\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\"]\n\n\
         [[shadowing]]\nwinner = \"Beta\"\nshadowed = \"Alpha\"\nreason = \"{REASON}\"\nevidence = [\"beta\"]\n"
    );
    refuses("duplicate-reason", route, "carry the same inline `reason`");
}

#[test]
fn n_refuses_a_reason_too_short_to_have_been_written() {
    refuses(
        "short-reason",
        one("winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"because\"\nevidence = [\"alpha\"]\n"),
        "`reason`; at least",
    );
}

#[test]
fn n_refuses_a_reference_to_an_undeclared_reason() {
    refuses(
        "dangling-reason",
        one("winner = \"Alpha\"\nshadowed = \"Beta\"\nreason_ref = \"nowhere\"\nevidence = [\"alpha\"]\n"),
        "which no `[reason.nowhere]` declares",
    );
}

#[test]
fn n_refuses_a_reference_to_undeclared_evidence() {
    refuses(
        "dangling-evidence",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"gamma\"]\n"
        )),
        "which no `[evidence.gamma]` declares",
    );
}

#[test]
fn n_refuses_evidence_nothing_cites() {
    refuses(
        "dead-evidence",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\"]\n"
        )),
        "`[evidence.beta]` is cited by no shadowing declaration",
    );
}

#[test]
fn n_refuses_a_shared_reason_nothing_names() {
    let route = format!(
        "{EVIDENCE}\n[reason.two-keys]\ntext = \"{REASON}\"\n\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON} It differs here.\"\n\
         evidence = [\"alpha\", \"beta\"]\n"
    );
    refuses("dead-reason", route, "`[reason.two-keys]` is named by no shadowing declaration");
}

#[test]
fn n_refuses_one_pair_declared_twice() {
    let route = format!(
        "{EVIDENCE}\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\"]\n\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON} And again.\"\nevidence = [\"beta\"]\n"
    );
    refuses("duplicate-pair", route, "is declared twice");
}

#[test]
fn n_refuses_a_route_that_shadows_itself() {
    refuses(
        "self-shadow",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Alpha\"\nreason = \"{REASON}\"\nevidence = [\"alpha\", \"beta\"]\n"
        )),
        "names itself as shadowed",
    );
}

#[test]
fn n_refuses_a_pair_naming_an_operation_no_family_includes() {
    refuses(
        "unknown-operation",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Gamma\"\nreason = \"{REASON}\"\nevidence = [\"alpha\", \"beta\"]\n"
        )),
        "and no family `include`s it",
    );
}

#[test]
fn n_refuses_an_unknown_key_on_a_declaration() {
    refuses(
        "unknown-key",
        one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\", \"beta\"]\n\
             precedence = 3\n"
        )),
        "unknown key `precedence`",
    );
}

#[test]
fn n_refuses_an_unknown_top_level_table() {
    let route = format!("{EVIDENCE}\n[op.Alpha]\nprecedence = 4\n");
    refuses("unknown-table", route, "carries `op`");
}

#[test]
fn n_refuses_a_family_file_carrying_a_shadowing_pair() {
    let sandbox = Sandbox::new(
        "family-shadowing",
        &one(&format!(
            "winner = \"Alpha\"\nshadowed = \"Beta\"\nreason = \"{REASON}\"\nevidence = [\"alpha\", \"beta\"]\n"
        )),
    );
    std::fs::write(
        sandbox.root.join("ops/family.toml"),
        "include = [\"Alpha\", \"Beta\"]\n\n[op.Alpha]\nprecedence = 1\n\n[op.Beta]\nprecedence = 2\n\n\
         [[shadowing]]\nwinner = \"Alpha\"\nshadowed = \"Beta\"\n",
    )
    .expect("test sandbox is writable");
    let error = sandbox.load().expect_err("a family file may not declare a shadowing pair");
    assert!(error.contains("lives in `route.toml` alone"), "unexpected: {error}");
}

#[test]
fn n_refuses_evidence_that_is_not_an_https_reference() {
    let route = "\
[evidence.alpha]
url = \"API_Alpha.html\"
summary = \"Alpha is selected by the ?alpha subresource alone.\"
"
    .to_owned();
    refuses("evidence-not-a-url", route, "is not an https reference");
}

#[test]
fn n_refuses_an_evidence_summary_too_short_to_have_been_written() {
    let route = "\
[evidence.alpha]
url = \"https://docs.aws.amazon.com/AmazonS3/latest/API/API_Alpha.html\"
summary = \"see above\"
"
    .to_owned();
    refuses("evidence-short-summary", route, "`summary`; at least");
}

#[test]
fn the_checked_in_overlay_loads_and_every_declaration_is_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../model/overlays");
    let overlay = Overlay::load(&root).expect("the checked-in overlay loads");
    assert!(
        overlay.shadowing.len() > 100,
        "the checked-in record is the whole reviewed table, not a sample: {}",
        overlay.shadowing.len()
    );
    for decl in &overlay.shadowing {
        assert!(decl.reason.len() >= 40, "{} over {} has no reason", decl.winner, decl.shadowed);
        assert!(!decl.evidence.is_empty(), "{} over {} has no evidence", decl.winner, decl.shadowed);
        for citation in &decl.evidence {
            assert!(citation.starts_with("https://"), "evidence is a reference: {citation}");
            assert!(citation.contains(" — "), "evidence carries a written summary: {citation}");
        }
    }
}
