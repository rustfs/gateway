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

//! Exhaustive loading and classification of hand-written protocol records.
//!
//! Responsible for: requiring exactly one typed mutable input or a contract classification for
//! every quirk record. NOT responsible for: parsing typed values. Upstream: quirk family TOML.
//! Downstream: [`super::Overlay`].

use std::path::Path;

use crate::error::{Error, Result};
use crate::ir::{Evidence, Quirk};
use crate::toml_lite;

use super::codec::contract_rule;
use super::codec_inputs::{codec_rule, source_rule};
use super::{Origins, Overlay, RuleClassification, array_of_tables, claim, label, read, required_str};

impl Overlay {
    pub(super) fn read_quirks(&mut self, path: &Path, quirk_origin: &mut Origins) -> Result<()> {
        let file = label(path);
        let text = read(path)?;
        let doc = toml_lite::parse(&path.display().to_string(), &text)?;
        for entry in array_of_tables(&doc, "quirk") {
            let id = required_str(entry, "id", "quirk")?;
            let kind = required_str(entry, "kind", &format!("quirk `{id}`"))?;
            let codec_rule = codec_rule(entry, &id)?;
            let source_rule = source_rule(entry, &id)?;
            let contract_rule = contract_rule(entry, &id)?;
            let classification = match required_str(entry, "classification", &format!("quirk `{id}`"))?.as_str() {
                "mutable" => RuleClassification::Mutable,
                "contract" => RuleClassification::Contract,
                spelling => {
                    return Err(Error::Overlay(format!(
                        "quirk `{id}`: unknown classification `{spelling}`; expected `mutable` or `contract`"
                    )));
                }
            };
            let mutable_rule_count = usize::from(codec_rule.is_some()) + usize::from(source_rule.is_some());
            match (classification, mutable_rule_count, contract_rule.is_some()) {
                (RuleClassification::Mutable, 0, _) => {
                    return Err(Error::Overlay(format!("quirk `{id}` is mutable but has no typed rule")));
                }
                (RuleClassification::Mutable, 1, false) | (RuleClassification::Contract, 0, _) => {}
                (RuleClassification::Contract, _, _) => {
                    return Err(Error::Overlay(format!("quirk `{id}` is a contract but carries mutable input")));
                }
                (RuleClassification::Mutable, _, _) => {
                    return Err(Error::Overlay(format!("quirk `{id}` has more than one mutable input")));
                }
            }
            let mut evidence = Vec::new();
            for item in array_of_tables(entry, "evidence") {
                evidence.push(Evidence {
                    kind: required_str(item, "kind", &format!("quirk `{id}` evidence"))?,
                    reference: required_str(item, "ref", &format!("quirk `{id}` evidence"))?,
                    summary: required_str(item, "summary", &format!("quirk `{id}` evidence"))?,
                });
            }
            let quirk = Quirk {
                id: id.clone(),
                kind,
                target: required_str(entry, "target", &format!("quirk `{id}`"))?,
                summary: required_str(entry, "summary", &format!("quirk `{id}`"))?,
                evidence,
                cases: entry
                    .get("cases")
                    .ok_or_else(|| Error::Overlay(format!("quirk `{id}` has no `cases`")))?
                    .string_array(&format!("quirk `{id}` cases"))?,
            };
            claim(quirk_origin, &id, &file, "declared as `[[quirk]]`")?;
            if let Some(rule) = codec_rule {
                self.codec_rules.insert(id.clone(), rule);
            }
            if let Some(rule) = source_rule {
                self.source_rules.insert(id.clone(), rule);
            }
            if let Some(rule) = contract_rule {
                self.contract_rules.insert(id.clone(), rule);
            }
            self.classifications.insert(id.clone(), classification);
            self.quirks.insert(id, quirk);
        }
        Ok(())
    }
}
