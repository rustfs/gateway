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

//! Why this request went to that operation, and what it did not go to.
//!
//! Responsible for: [`Explanation`] and [`RouteTable::explain`] — the answer a `route explain`
//! command renders.
//! NOT responsible for: any request-time decision. Nothing on the serving path calls this; it
//! allocates freely because it runs when a human asks a question.
//! Upstream: `table`, `shadowing`. Downstream: the xtask that prints it (P4-01's CLI half, outside
//! this crate).
//!
//! An explanation without the shadowed entries is not an explanation. "This is `GetBucketLocation`"
//! answers nothing for somebody who expected a listing; "this is `GetBucketLocation` at precedence
//! 300, and it hides `ListObjectsV2` at 600, for this reason, with this evidence" does.

use std::fmt;

use super::selector::{RouteEntry, RouteRequestParts};
use super::table::RouteTable;

/// One entry an explanation names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explained {
    /// The operation.
    pub op_name: &'static str,
    /// Its precedence.
    pub precedence: u16,
    /// Its selector, rendered.
    pub selector: String,
    /// Why it loses to the winner, when a declaration says so.
    pub reason: Option<&'static str>,
    /// Where that reason comes from.
    pub evidence: &'static [&'static str],
}

impl Explained {
    fn of(entry: &RouteEntry) -> Self {
        Self {
            op_name: entry.op_name,
            precedence: entry.precedence,
            selector: entry.selector.to_string(),
            reason: None,
            evidence: &[],
        }
    }
}

/// What the table did with one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Explanation {
    /// The entry that won, if any.
    pub matched: Option<Explained>,
    /// Every later entry that would also have accepted this request.
    pub shadowed: Vec<Explained>,
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.matched {
            Some(matched) => writeln!(f, "matched: {} (precedence={})", matched.op_name, matched.precedence)?,
            None => writeln!(f, "matched: nothing — this request shape has no route")?,
        }
        for entry in &self.shadowed {
            writeln!(f, "shadows: {} (precedence={})", entry.op_name, entry.precedence)?;
            if let Some(reason) = entry.reason {
                writeln!(f, "  reason: {reason}")?;
            }
            if !entry.evidence.is_empty() {
                writeln!(f, "  evidence: {}", entry.evidence.join(", "))?;
            }
        }
        Ok(())
    }
}

impl RouteTable {
    /// Everything the table has to say about one request.
    ///
    /// Not on the serving path. See the module docs.
    #[must_use]
    pub fn explain(&self, request: &RouteRequestParts<'_>) -> Explanation {
        let mut matching = self.entries().iter().filter(|entry| entry.selector.matches(request));
        let Some(winner) = matching.next() else {
            return Explanation::default();
        };
        let shadowed = matching
            .map(|entry| {
                let mut explained = Explained::of(entry);
                if let Some(decl) = self.shadowing().find(winner.op_name, entry.op_name) {
                    explained.reason = Some(decl.reason);
                    explained.evidence = decl.evidence;
                }
                explained
            })
            .collect();
        Explanation {
            matched: Some(Explained::of(winner)),
            shadowed,
        }
    }
}
