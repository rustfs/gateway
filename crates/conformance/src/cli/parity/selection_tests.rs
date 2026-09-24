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

//! Responsible for: independent parity census selection and capability metadata boundaries.
//! NOT responsible for: interpreting child reports or executing HTTP/2 frames.
//! Upstream: the corpus and runner selection contract. Downstream: parity child validation.

use super::*;
use crate::corpus::Case;
use crate::parity::ExpectedCapability::{HyperScriptedH2, Shared};
use crate::runner::{RunOptions, Shard};

const FRAMES: &str = "[request]\nhttp_version = \"h2\"\n[[request.h2_frames]]\ntype = \"settings\"\n";

fn case(id: &str, text: &str) -> Case {
    Case {
        id: id.to_owned(),
        domain: "h2".to_owned(),
        path: PathBuf::from(id),
        relative: format!("cases/misc/{id}.toml"),
        document: Some(crate::toml::parse(text).expect("test document")),
        diagnostics: Vec::new(),
    }
}

#[test]
fn root_and_exchange_scripts_derive_capability_without_report_or_id_labels() {
    let cases = [
        case("c-wire-0001", FRAMES),
        case(
            "c-wire-0002",
            "[[exchanges]]\n[exchanges.request]\nhttp_version = \"h2\"\n[[exchanges.request.h2_frames]]\ntype = \"settings\"\n",
        ),
    ];
    let census = selected_capabilities(&cases, &RunOptions::default()).expect("independent selection");
    assert_eq!(census.len(), 2);
    assert_eq!(census.get("c-wire-0001"), Some(&HyperScriptedH2));
    assert_eq!(census.get("c-wire-0002"), Some(&HyperScriptedH2));
}

#[test]
fn h2_name_domain_and_version_without_frames_do_not_authorize_a_difference() {
    let census = selected_capabilities(&[case("c-h2-0001", "[request]\nhttp_version = \"h2\"\n")], &RunOptions::default())
        .expect("shared case");
    assert_eq!(census.get("c-h2-0001"), Some(&Shared));
}

#[test]
fn load_or_deny_diagnostics_do_not_authorize_unexecuted_h2() {
    let mut absent = case("absent", FRAMES);
    absent.document = None;
    let mut denied = case("denied", FRAMES);
    denied
        .diagnostics
        .push(crate::diagnostic::Diagnostic::deny("schema/test", "", "invalid case"));
    let census = selected_capabilities(&[absent, denied], &RunOptions::default()).expect("failed cases retained");
    assert_eq!(census.get("absent"), Some(&Shared));
    assert_eq!(census.get("denied"), Some(&Shared));
}

#[test]
fn profile_tls_and_version_inapplicability_remain_shared_skips() {
    for gate in [
        "profiles = [\"minio\"]",
        "tls = \"required\"",
        "http_versions = [\"http/1.1\"]",
    ] {
        let text = format!("[case.applies_to]\n{gate}\n{FRAMES}");
        let census = selected_capabilities(&[case("gated", &text)], &RunOptions::default()).expect("gated case retained");
        assert_eq!(census.get("gated"), Some(&Shared), "{gate}");
    }
}

#[test]
fn filter_and_slow_exclusion_precede_shard_ordinals() {
    let cases = [
        case("other", FRAMES),
        case("keep-slow", &format!("[case]\ntags=[\"slow\"]\n{FRAMES}")),
        case("keep-a", FRAMES),
        case("keep-b", FRAMES),
        case("keep-c", FRAMES),
    ];
    let options = RunOptions {
        filter: Some("keep*".to_owned()),
        include_slow: false,
        shard: Some(Shard { index: 1, count: 2 }),
        ..RunOptions::default()
    };
    let census = selected_capabilities(&cases, &options).expect("same selection as execution");
    assert_eq!(census.keys().map(String::as_str).collect::<Vec<_>>(), ["keep-b"]);
}

#[test]
fn duplicate_selected_ids_are_not_silently_overwritten() {
    assert!(selected_capabilities(&[case("duplicate", FRAMES), case("duplicate", FRAMES)], &RunOptions::default()).is_err());
}

#[test]
fn validation_only_cases_cannot_authorize_a_transport_capability_difference() {
    let options = RunOptions {
        validate_only: true,
        ..RunOptions::default()
    };
    let census = selected_capabilities(&[case("scripted", FRAMES)], &options).expect("validation-only case retained");
    assert_eq!(census.get("scripted"), Some(&Shared));
}
