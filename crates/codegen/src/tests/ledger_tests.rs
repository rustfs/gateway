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

//! Protected quirk-ledger regression tests.
//!
//! Responsible for: pinning generated typed-rule, source, dimension and capability-exclusion counts.
//! NOT responsible for: source-to-consumer and bilateral-case scans, which live in `check_quirk_ledger.sh`.
//! Upstream: canonical overlays. Downstream: generated protected quirk and contract tables.

use std::collections::BTreeSet;

use super::codegen_tests::{artifacts, root};

#[test]
fn only_proven_mutable_quirks_and_typed_contracts_have_generated_tables() {
    let artifacts = artifacts();
    let overlay = rustfs_gateway_model::Overlay::load(&root().join("model/overlays")).expect("the canonical overlay loads");
    let mutable = artifacts
        .files
        .iter()
        .filter(|(path, _)| path.to_string_lossy().contains("spec/quirks/"))
        .count();
    let contracts = artifacts
        .files
        .iter()
        .filter(|(path, _)| path.to_string_lossy().contains("spec/contracts/"))
        .count();
    let mutable_contracts = overlay
        .contract_rules
        .keys()
        .filter(|id| overlay.classifications.get(*id) == Some(&rustfs_gateway_model::overlay::RuleClassification::Mutable))
        .count();

    assert_eq!(mutable, artifacts.codec_rules.len() + artifacts.source_rules.len() + mutable_contracts);
    assert_eq!(mutable, 103, "the mutable side of the protected ledger drifted");
    assert_eq!(
        artifacts.contract_rules.len(),
        165,
        "the typed-contract side of the protected ledger drifted"
    );
    assert_eq!(contracts, 160, "only typed contracts belong in the protected contract table");
    assert_eq!(mutable + contracts, 263, "only proven typed sources belong in generated rule tables");

    let mut typed_sources = BTreeSet::new();
    let mut dimensions = BTreeSet::new();
    for (id, rule) in &overlay.codec_rules {
        assert!(typed_sources.insert(id.as_str()), "{id} has more than one typed source");
        dimensions.insert(rule.mutation_dimension.as_str());
    }
    for (id, rule) in &overlay.source_rules {
        assert!(typed_sources.insert(id.as_str()), "{id} has more than one typed source");
        dimensions.insert(rule.mutation_dimension.as_str());
    }
    for (id, rule) in &overlay.contract_rules {
        assert!(typed_sources.insert(id.as_str()), "{id} has more than one typed source");
        dimensions.insert(rule.mutation_dimension.as_str());
    }
    assert_eq!(typed_sources.len(), 263, "the typed source union drifted");
    assert_eq!(dimensions.len(), 179, "the protected mutation-dimension ledger drifted");

    let capability_blocks = BTreeSet::from(["q-cors-0006", "q-cors-0047"]);
    assert!(capability_blocks.is_subset(&typed_sources), "capability blocks must remain typed sources");
    let wired = typed_sources.difference(&capability_blocks).copied().collect::<BTreeSet<_>>();
    assert_eq!(wired.len(), 261, "the production-wired ledger drifted");
    assert_eq!(typed_sources.difference(&wired).copied().collect::<BTreeSet<_>>(), capability_blocks);
    assert!(
        artifacts
            .files
            .iter()
            .any(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-order-0014.toml")),
        "a typed codegen source belongs in the mutation table"
    );
}
