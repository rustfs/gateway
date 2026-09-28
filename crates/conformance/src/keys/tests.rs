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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! The guard's own controls.
//!
//! [`super::audit`] is pure, so every way it is meant to go red is exercised here without running a
//! corpus. A guard whose failure path is untested is a green tick nobody has earned — which is the
//! same defect this module exists to catch, one level up.

use super::*;
use crate::corpus::Corpus;
use crate::toml;

fn schema_source() -> String {
    let root = Corpus::discover_root().expect("the repository corpus");
    std::fs::read_to_string(root.join("case.schema.json")).expect("the frozen schema")
}

fn inventory() -> Inventory {
    Inventory::compile(&schema_source()).expect("the frozen schema compiles")
}

fn ledger_of(entries: &[(&'static str, Site)]) -> Ledger {
    let mut ledger = Ledger::new();
    for (key, site) in entries {
        ledger.entry(key).or_default().insert(*site);
    }
    ledger
}

fn at(line: u32) -> Site {
    Site { file: "probe.rs", line }
}

fn keys_of(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// No case writes anything, unless a test says otherwise.
fn nothing() -> BTreeSet<String> {
    BTreeSet::new()
}

#[test]
fn a_schema_location_names_the_toml_key_it_fetches() {
    assert_eq!(leaf("setup.buckets[].object_lock"), "object_lock");
    assert_eq!(leaf("expect.capture.*.header"), "header");
    assert_eq!(leaf("case"), "case");
}

/// Recording is fused to reading: the field fetched is derived from the name recorded, so a call
/// cannot claim one key while looking at another.
#[test]
fn read_fetches_the_field_the_recorded_location_names() {
    let value = Value::Table(vec![("object_lock".to_owned(), Value::Bool(true))]);
    assert_eq!(value.read("setup.buckets[].object_lock").and_then(Value::as_bool), Some(true));
    assert!(recorded().contains_key("setup.buckets[].object_lock"));
}

/// Recorded on the attempt, not on the hit. The fact worth recording is that the harness looks —
/// otherwise a corpus that stopped writing an optional key would make the harness look honest
/// about a key it had quietly stopped reading.
#[test]
fn read_records_a_key_the_document_does_not_carry() {
    let empty = Value::empty_table();
    assert!(empty.read("setup.buckets[].versioning").is_none());
    assert!(recorded().contains_key("setup.buckets[].versioning"));
}

#[test]
fn a_key_nothing_reads_and_nothing_declares_is_reported() {
    let findings = audit(&keys_of(&["expect.status"]), &Ledger::new(), &[], &nothing());
    assert_eq!(findings, vec![Finding::Silent("expect.status".to_owned())]);
}

#[test]
fn a_declared_key_is_not_reported_as_silent() {
    let declarations = [("expect.status", Disposition::Inert, "because")];
    assert!(audit(&keys_of(&["expect.status"]), &Ledger::new(), &declarations, &nothing()).is_empty());
}

#[test]
fn a_recorded_name_the_schema_does_not_declare_is_reported() {
    let ledger = ledger_of(&[("expect.stuts", at(1))]);
    let findings = audit(&keys_of(&["expect.status"]), &ledger, &[], &nothing());
    assert!(findings.contains(&Finding::Invented("expect.stuts".to_owned())), "{findings:?}");
}

#[test]
fn a_declaration_for_a_field_the_schema_dropped_is_reported() {
    let declarations = [("expect.gone", Disposition::Inert, "because")];
    let findings = audit(
        &keys_of(&["expect.status"]),
        &ledger_of(&[("expect.status", at(1))]),
        &declarations,
        &nothing(),
    );
    assert!(findings.contains(&Finding::Stale("expect.gone".to_owned())), "{findings:?}");
}

#[test]
fn a_declaration_the_ledger_contradicts_is_reported() {
    let declarations = [("expect.status", Disposition::Unhonoured, "because")];
    let findings = audit(
        &keys_of(&["expect.status"]),
        &ledger_of(&[("expect.status", at(1))]),
        &declarations,
        &nothing(),
    );
    assert!(findings.contains(&Finding::Contradicted("expect.status".to_owned())), "{findings:?}");
}

/// The cheapest way to make this audit vacuous is one loop over a list of every key. It is one
/// source location claiming many keys, and that is exactly what this rejects.
#[test]
fn one_source_location_may_not_claim_two_keys() {
    let ledger = ledger_of(&[("expect.status", at(7)), ("expect.kind", at(7))]);
    let findings = audit(&keys_of(&["expect.status", "expect.kind"]), &ledger, &[], &nothing());
    assert!(
        findings
            .iter()
            .any(|finding| matches!(finding, Finding::Blanket(site, keys) if site.line == 7 && keys.len() == 2)),
        "{findings:?}"
    );
}

#[test]
fn the_same_key_read_from_two_places_is_not_a_blanket_claim() {
    let ledger = ledger_of(&[("expect.status", at(7))]);
    let mut ledger = ledger;
    ledger.entry("expect.status").or_default().insert(at(9));
    assert!(audit(&keys_of(&["expect.status"]), &ledger, &[], &nothing()).is_empty());
}

/// "Unreachable behind a refusal" is only true while something performs the refusal.
#[test]
fn an_unreachable_claim_whose_ancestor_is_also_unread_is_reported() {
    let declarations = [
        ("h2Frame.type", Disposition::BehindRefusal("requestSpec.h2_frames"), "because"),
        ("requestSpec.h2_frames", Disposition::Inert, "also unread"),
    ];
    let inventory = keys_of(&["h2Frame.type", "requestSpec.h2_frames"]);
    let findings = audit(&inventory, &Ledger::new(), &declarations, &nothing());
    assert!(
        findings.contains(&Finding::Ungrounded {
            key: "h2Frame.type".to_owned(),
            ancestor: "requestSpec.h2_frames".to_owned(),
        }),
        "{findings:?}"
    );
}

#[test]
fn the_inventory_names_declarations_by_their_schema_location() {
    let inventory = inventory();
    for key in [
        "setup.buckets[].object_lock",
        "connection.pipeline",
        "requestSpec.method",
        "signSpec.tamper.component",
        "bodyExpectation.contains_utf8",
        "expect.capture.*.xml_text",
        "dataChunk.raw_hex",
    ] {
        assert!(inventory.keys().contains(key), "missing `{key}`");
    }
    // The two spellings of a request are one declaration each, and the fields underneath them are
    // one set: a runner that read `request.method` would otherwise look as if it had never read
    // `exchanges[].request.method`.
    assert!(inventory.keys().contains("request"));
    assert!(inventory.keys().contains("exchange.request"));
    assert!(!inventory.keys().contains("exchanges[].request.method"));
}

/// `region` is why this guard is not a grep: the identical name is declared twice, and one of the
/// two was read by nothing while the other was read everywhere.
#[test]
fn two_declarations_sharing_a_name_are_two_keys() {
    let inventory = inventory();
    assert!(inventory.keys().contains("signSpec.region"));
    assert!(inventory.keys().contains("setup.buckets[].region"));
}

#[test]
fn a_document_declares_only_the_branch_it_satisfies() {
    let document = toml::parse(
        "[[request.chunks]]\nutf8 = \"a\"\ndelay_ms = 5\n\n[[request.chunks]]\naction = \"stall\"\nduration_ms = 3\n",
    )
    .expect("valid TOML");
    let declared = inventory().declared_in(&document);
    assert!(declared.contains_key("dataChunk.delay_ms"), "{declared:?}");
    assert!(declared.contains_key("controlChunk.duration_ms"), "{declared:?}");
    // A data chunk carries no `action`, so nothing about it is a control chunk.
    assert!(!declared.contains_key("controlChunk.delay_ms"), "{declared:?}");
}

#[test]
fn a_document_reports_where_it_declared_each_key() {
    let document = toml::parse("[[setup.buckets]]\nname = \"b\"\nobject_lock = true\n").expect("valid TOML");
    let declared = inventory().declared_in(&document);
    assert_eq!(
        declared.get("setup.buckets[].object_lock").map(Vec::as_slice),
        Some(["/setup/buckets/0/object_lock".to_owned()].as_slice())
    );
}

/// An exemption for a container no case writes deletes itself the moment a case writes it.
#[test]
fn an_unexercised_claim_the_corpus_now_writes_is_reported() {
    let declarations = [("expect.events[].type", Disposition::Unexercised("expect.events"), "because")];
    let inventory = keys_of(&["expect.events[].type", "expect.events"]);
    let exercised = keys_of(&["expect.events"]);
    let findings = audit(&inventory, &ledger_of(&[("expect.events", at(1))]), &declarations, &exercised);
    assert!(
        findings.contains(&Finding::Exercised {
            key: "expect.events[].type".to_owned(),
            container: "expect.events".to_owned(),
        }),
        "{findings:?}"
    );
}

/// Every disposition names a key the frozen schema really declares, whatever the ledger says.
#[test]
fn every_declaration_names_a_field_of_the_frozen_schema() {
    let inventory = inventory();
    for (key, _, reason) in DECLARED {
        assert!(inventory.keys().contains(*key), "keys::DECLARED names `{key}`, which the schema does not");
        assert!(reason.len() > 30, "`{key}` needs a reason a maintainer can act on");
    }
}

/// Real execution, in a fresh process: other tests must not donate reads to this ledger.
#[test]
fn h2_key_declarations_match_the_selected_transport_in_an_isolated_process() {
    const CHILD: &str = "GATEWAY_H2_KEY_AUDIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "keys::tests::h2_key_declarations_match_the_selected_transport_in_an_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run the isolated ledger control");
        assert!(
            output.status.success(),
            "isolated H2 key audit failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let root = Corpus::discover_root().expect("the repository corpus");
    let corpus = crate::runner::prepare_corpus(&root).expect("the authored corpus loads");
    #[cfg(feature = "production-transports")]
    let mut target = crate::conn::Conn::production(root, crate::production::ProductionDriver::Hyper);
    #[cfg(not(feature = "production-transports"))]
    let mut target = crate::inprocess::InProcess::new(root);
    assert!(
        recorded()
            .keys()
            .all(|key| !key.starts_with("h2Frame.") && !key.starts_with("h2ControlFrame."))
    );
    let options = crate::runner::RunOptions {
        filter: Some("c-h2-*".to_owned()),
        ..crate::runner::RunOptions::default()
    };
    let report = crate::runner::run(&corpus, &mut target, &options);
    let ids: Vec<_> = report.outcomes.iter().map(|outcome| outcome.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "c-h2-0001",
            "c-h2-0002",
            "c-h2-0003",
            "c-h2-0004",
            "c-h2-0005",
            "c-h2-0006",
            "c-h2-0007",
            "c-h2-0008",
            "c-h2-0009",
            "c-h2-0010",
            "c-h2-0011",
            "c-h2-0012",
            "c-h2-0013",
            "c-h2-0014",
            "c-h2-0015",
            "c-h2-0016"
        ]
    );
    #[cfg(not(feature = "production-transports"))]
    for outcome in &report.outcomes {
        assert_eq!(outcome.verdict, crate::report::Verdict::Skipped);
        assert!(
            outcome
                .skip_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("h2_frames"))
        );
    }
    #[cfg(feature = "production-transports")]
    for outcome in &report.outcomes {
        // Protocol verdicts remain the separate corpus test's responsibility, including #873.
        assert_ne!(outcome.verdict, crate::report::Verdict::Skipped);
        assert_ne!(outcome.verdict, crate::report::Verdict::Validated);
    }
    let relevant =
        |key: &str| key.starts_with("h2Frame.") || key.starts_with("h2ControlFrame.") || key == "requestSpec.h2_frames";
    let inventory: BTreeSet<_> = corpus
        .inventory()
        .keys()
        .iter()
        .filter(|key| relevant(key))
        .cloned()
        .collect();
    let ledger: Ledger = recorded().into_iter().filter(|(key, _)| relevant(key)).collect();
    let declarations: Vec<_> = DECLARED.iter().copied().filter(|(key, _, _)| relevant(key)).collect();
    let exercised: BTreeSet<_> = corpus
        .cases()
        .iter()
        .filter_map(|case| case.document.as_ref())
        .flat_map(|document| corpus.inventory().declared_in(document).into_keys())
        .collect();
    assert!(ledger.contains_key("requestSpec.h2_frames"), "the refusal gate itself must be read");
    for field in [
        "type",
        "stream_id",
        "flags",
        "payload_hex",
        "error_code",
        "increment",
        "delay_ms",
    ] {
        assert!(
            ledger.contains_key(format!("h2Frame.{field}").as_str()),
            "the real authored-frame parser must read {field}"
        );
    }
    let findings = audit(&inventory, &ledger, &declarations, &exercised);
    assert!(findings.is_empty(), "{findings:?}");
}
