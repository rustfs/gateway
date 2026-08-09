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

//! The pinned Smithy 2.0 JSON AST, with the documentation traits removed on the way in.
//!
//! Responsible for: loading `model/s3.json`, deleting the trait families that carry no wire
//! meaning, and answering shape questions (members, targets, enum values, http bindings).
//! NOT responsible for: deciding what any of it means for S3 (that is [`mod@crate::lower`]).
//! Upstream: [`crate::json`]. Downstream: [`mod@crate::lower`].
//!
//! The stripping happens in [`Model::load`], before any other code sees a shape, so a leaked
//! documentation string cannot reach the IR by any route. See ADR-0001 and `model/PROVENANCE.md`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::json::{self, Value};

/// Trait ids deleted from every shape and member as the model is loaded.
///
/// The first three are pure documentation: Smithy defines them as having no effect on the wire, so
/// keeping them would only enlarge the artefact and widen the attribution surface. The three
/// `smithy.rules#` entries are *client* endpoint resolution rules — a server does not resolve its
/// own endpoint.
pub const STRIPPED_TRAITS: &[&str] = &[
    "smithy.api#documentation",
    "smithy.api#examples",
    "smithy.api#externalDocumentation",
    "smithy.rules#endpointBdd",
    "smithy.rules#endpointRuleSet",
    "smithy.rules#endpointTests",
];

/// The loaded model.
#[derive(Debug)]
pub struct Model {
    shapes: BTreeMap<String, Value>,
    service: String,
    stripped: usize,
}

impl Model {
    /// Reads and strips a Smithy 2.0 JSON AST from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))?;
        Self::from_json(&text)
    }

    /// Parses and strips a Smithy 2.0 JSON AST held in memory.
    pub fn from_json(text: &str) -> Result<Self> {
        let root = json::parse(text)?;
        let version = root
            .get("smithy")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Model("missing `smithy` version".into()))?;
        if version != "2.0" {
            return Err(Error::Model(format!("unsupported smithy version `{version}`")));
        }
        let shapes = root
            .get("shapes")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::Model("missing `shapes`".into()))?;

        let mut stripped = 0usize;
        let mut map = BTreeMap::new();
        for (id, shape) in shapes {
            let mut shape = shape.clone();
            strip(&mut shape, &mut stripped);
            map.insert(id.clone(), shape);
        }
        let service = map
            .iter()
            .find(|(_, v)| v.get("type").and_then(Value::as_str) == Some("service"))
            .map(|(k, _)| k.clone())
            .ok_or_else(|| Error::Model("no service shape".into()))?;
        Ok(Model {
            shapes: map,
            service,
            stripped,
        })
    }

    /// The namespaced id of the service shape.
    pub fn service_id(&self) -> &str {
        &self.service
    }

    /// How many trait occurrences were removed while loading. Reported by `xtask codegen` so the
    /// stripping stays visible instead of becoming folklore.
    pub fn stripped_trait_count(&self) -> usize {
        self.stripped
    }

    /// Total shape count.
    pub fn shape_count(&self) -> usize {
        self.shapes.len()
    }

    /// Every operation's local (unqualified) name, sorted.
    pub fn operation_names(&self) -> Vec<String> {
        self.shapes
            .iter()
            .filter(|(_, v)| v.get("type").and_then(Value::as_str) == Some("operation"))
            .map(|(k, _)| local_name(k).to_owned())
            .collect()
    }

    /// Looks a shape up by its namespaced id.
    pub fn shape(&self, id: &str) -> Option<&Value> {
        self.shapes.get(id)
    }

    /// Looks a shape up by its local name inside the service namespace.
    pub fn shape_local(&self, name: &str) -> Option<&Value> {
        let namespace = self.service.split('#').next().unwrap_or("");
        self.shapes.get(&format!("{namespace}#{name}"))
    }

    /// The `type` discriminator of a shape referenced by id.
    pub fn kind_of(&self, id: &str) -> &str {
        self.shape(id)
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// The declared members of a structure, union or enum shape, in model order.
    pub fn members<'a>(&'a self, shape: &'a Value) -> Vec<(&'a str, &'a Value)> {
        shape
            .get("members")
            .and_then(Value::as_object)
            .map(|pairs| pairs.iter().map(|(k, v)| (k.as_str(), v)).collect())
            .unwrap_or_default()
    }

    /// The enum values of an `enum` shape, in model order.
    pub fn enum_values(&self, id: &str) -> Option<Vec<String>> {
        let shape = self.shape(id)?;
        if shape.get("type").and_then(Value::as_str) != Some("enum") {
            return None;
        }
        Some(
            self.members(shape)
                .into_iter()
                .filter_map(|(name, m)| {
                    trait_of(m, "smithy.api#enumValue")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| Some(name.to_owned()))
                })
                .collect(),
        )
    }
}

/// The part of a shape id after the `#`.
pub fn local_name(id: &str) -> &str {
    id.rsplit('#').next().unwrap_or(id)
}

/// Reads one trait off a shape or member.
pub fn trait_of<'a>(node: &'a Value, id: &str) -> Option<&'a Value> {
    node.get("traits")?.get(id)
}

/// Whether a shape or member carries a trait.
pub fn has_trait(node: &Value, id: &str) -> bool {
    trait_of(node, id).is_some()
}

/// The target shape id of a member.
pub fn target_of(member: &Value) -> Option<&str> {
    member.get("target").and_then(Value::as_str)
}

fn strip(node: &mut Value, count: &mut usize) {
    match node {
        Value::Object(pairs) => {
            for (key, value) in pairs.iter_mut() {
                if key == "traits" {
                    if let Value::Object(traits) = value {
                        let before = traits.len();
                        traits.retain(|(id, _)| !STRIPPED_TRAITS.contains(&id.as_str()));
                        *count += before - traits.len();
                    }
                } else {
                    strip(value, count);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                strip(item, count);
            }
        }
        _ => {}
    }
}
