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

//! Rustfmt-equivalent layout primitives for generated request decoders.
//!
//! Responsible for: line and chain wrapping shared by decoder assignments, list loops and pushes.
//! NOT responsible for: deciding which wire binding is decoded or which expression reads it.
//! Upstream: the repository rustfmt width contract. Downstream: the request codec emitter.

/// rustfmt's `max_width` for this repository.
pub(super) const MAX_WIDTH: usize = 130;

/// rustfmt's default `chain_width`: sixty per cent of `max_width`.
const CHAIN_WIDTH: usize = MAX_WIDTH * 6 / 10;

/// The `for item in <chain> {` header, laid out the way rustfmt lays it out.
pub(super) fn for_header(indent: usize, receiver: &str, links: &[String]) -> String {
    let pad = " ".repeat(indent);
    let chain: String = links.iter().map(|link| format!(".{link}")).collect();
    let single = format!("{pad}for item in {receiver}{chain} {{\n");
    if single.len().saturating_sub(1) <= MAX_WIDTH && chain.len() <= CHAIN_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    let mut out = format!("{pad}for item in {receiver}\n");
    for link in links {
        out.push_str(&format!("{continuation}.{link}\n"));
    }
    out.push_str(&format!("{pad}{{\n"));
    out
}

/// One assignment, laid out the way rustfmt lays it out.
pub(super) fn assign(indent: usize, target: &str, expression: &str) -> String {
    let pad = " ".repeat(indent);
    let single = format!("{pad}{target} = {expression};\n");
    if single.len().saturating_sub(1) <= MAX_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    format!("{pad}{target} =\n{continuation}{expression};\n")
}

/// One `target.push(expression)` inside a list loop, with rustfmt-equivalent wrapping.
pub(super) fn push_stmt(indent: usize, target: &str, expression: &str) -> String {
    let pad = " ".repeat(indent);
    let single = format!("{pad}{target}.push({expression});\n");
    let receiver_len = target.split('.').next().map_or(0, str::len);
    let chain_len = target.len().saturating_sub(receiver_len) + ".push()".len() + expression.len();
    if single.len().saturating_sub(1) <= MAX_WIDTH && chain_len <= CHAIN_WIDTH {
        return single;
    }
    let continuation = " ".repeat(indent.saturating_add(4));
    let (receiver, links) = target.split_once('.').unwrap_or((target, ""));
    format!("{pad}{receiver}\n{continuation}.{links}\n{continuation}.push({expression});\n")
}
