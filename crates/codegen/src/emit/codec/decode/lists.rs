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

//! How a request decoder reads a list member.
//!
//! Responsible for: [`list_source`], the node iterator a list's entries are read from, and
//! [`Presence`], which reads a list whose presence is carried (`emit::dto::presence`,
//! rustfs/gateway#1078) into a list of its own that becomes the member only when the list's
//! wrapper is there: an empty wrapper is an empty list, and no wrapper is no list.
//! NOT responsible for: reading one entry (the parent's `xml_member`), or laying a line out
//! (`super::layout`).
//! Upstream: the parent. Downstream: the parent's `xml_member`.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::Field;

use super::super::ListElements;
use super::layout::assign;
use crate::emit::dto::naming;

/// The node iterator one list-typed member reads its entries from.
/// A flattened list repeats its entry element directly under the parent; a wrapped one sits inside
/// an enclosing element. Which name is which comes from [`super::super::list_elements`] rather
/// than from here, so the reader and the writer cannot disagree about it — they did, and the
/// disagreement was invisible because both spellings compile.
///
/// Returned as the links of a method chain rather than as one string, because rustfmt breaks a
/// chain that is too long link by link and this emitter has to produce what rustfmt would.
pub(super) fn list_source(flattened: bool, member_name: Option<&str>, wire: &str) -> Result<Vec<String>, String> {
    let names = super::super::list_elements(flattened, member_name, wire)?;
    Ok(match &names.wrapper {
        None => vec![format!("children_named(\"{}\")", names.entry)],
        Some(wrapper) => vec![
            format!("child(\"{wrapper}\")"),
            "into_iter()".to_owned(),
            format!("flat_map(|w| w.children_named(\"{}\"))", names.entry),
        ],
    })
}

/// How one list member is filled: its entries pushed into the member itself, or — for a list
/// whose presence is carried — into a list of its own that becomes the member when its wrapper is
/// there.
pub(super) struct Presence<'a> {
    target: &'a str,
    local: Option<String>,
}

impl<'a> Presence<'a> {
    /// The filling of `owner`'s member `field`, held at `target`.
    pub(super) fn of(owner: &str, field: &Field, target: &'a str) -> Self {
        let carried = crate::emit::dto::presence::carries_presence(owner, field);
        Self {
            target,
            local: carried.then(|| naming::field_name(&field.name)),
        }
    }

    /// The statement declaring the list of its own, at `pad`; nothing for any other list.
    pub(super) fn prelude(&self, pad: &str) -> String {
        let mut out = String::new();
        if let Some(local) = &self.local {
            let _ = writeln!(out, "{pad}let mut {local} = Vec::new();");
        }
        out
    }

    /// Where the entries are pushed.
    pub(super) fn entries(&self) -> &str {
        self.local.as_deref().unwrap_or(self.target)
    }

    /// The assignment making the list of its own the member when `names`' wrapper is in `node`,
    /// at `indent`; nothing for any other list.
    ///
    /// # Errors
    ///
    /// A list whose presence is carried has no wrapper.
    pub(super) fn assign(&self, indent: usize, node: &str, names: ListElements) -> Result<String, String> {
        let Some(local) = &self.local else {
            return Ok(String::new());
        };
        let wrapper = names
            .wrapper
            .ok_or_else(|| format!("codec: `{}` carries its presence and has no wrapper", self.target))?;
        Ok(assign(indent, self.target, &format!("{node}.child(\"{wrapper}\").map(|_| {local})")))
    }
}
