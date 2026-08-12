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

//! Edit-distance support for reverse-trace target suggestions.
//!
//! Responsible for: computing the character edit distance used to rank nearby targets.
//! NOT responsible for: resolving targets or rendering suggestions.
//! Upstream: the reverse-trace index. Downstream: unknown-target diagnostics.

pub(super) fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (row, left) in a.iter().enumerate() {
        let mut current = vec![row + 1];
        for (column, right) in b.iter().enumerate() {
            let insert = current[column] + 1;
            let delete = previous[column + 1] + 1;
            let replace = previous[column] + usize::from(left != right);
            current.push(insert.min(delete).min(replace));
        }
        previous = current;
    }
    previous.last().copied().unwrap_or(a.len())
}
