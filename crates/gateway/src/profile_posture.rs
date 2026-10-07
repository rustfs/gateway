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

//! The `PROFILE_POSTURE` start-up line: every legacy RustFS reading an assembly turned on, named
//! by the builder method that turned it on (rustfs/backlog#2751).
//!
//! Responsible for: rendering the line from the switch names the builder derived from its own
//! state, and writing it to the start-up log.
//! NOT responsible for: deriving that set (`crate::builder::rustfs_profile`, from the assembled
//! state and never from whether the preset was called), the switches themselves, or the other
//! start-up lines (`crate::posture`, `crate::dialect_posture`, `crate::naming_posture`,
//! `crate::presigned_expiry_posture`).
//! Upstream: `crate::startup_report`. Downstream: startup logs, operators, and the posture golden
//! in `tests/golden/rustfs-profile-posture.txt`.

use std::collections::BTreeSet;

use crate::logging;
use crate::posture::format_names;

/// The line naming every legacy reading in `switches`, sorted, as `PROFILE_POSTURE switches=[…]`.
///
/// An assembly running none renders an empty list rather than no line: an operator reading the
/// start-up log learns that the assembly is the AWS-model one, not that the line was forgotten.
pub(crate) fn render_profile_posture(switches: &BTreeSet<&'static str>) -> String {
    format!("PROFILE_POSTURE switches=[{}]", format_names(switches))
}

/// Writes [`render_profile_posture`] to the start-up log.
pub(crate) fn log_profile_posture(switches: &BTreeSet<&'static str>) {
    tracing::info!(
        target: logging::TARGET,
        event = logging::EVENT_PROFILE_POSTURE,
        component = logging::COMPONENT,
        subsystem = logging::SUBSYSTEM_POSTURE,
        "{}",
        render_profile_posture(switches)
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::render_profile_posture;

    /// Negative — an assembly running no legacy reading still writes the line, with an empty list.
    #[test]
    fn n_no_switch_renders_an_empty_list_and_not_no_line() {
        assert_eq!(render_profile_posture(&BTreeSet::new()), "PROFILE_POSTURE switches=[]");
    }

    /// Positive — every name is listed once, sorted, comma-separated, whatever order it arrived in.
    #[test]
    fn every_switch_is_named_once_in_sorted_order() {
        let switches: BTreeSet<&'static str> = [
            "write_responses_as_rustfs",
            "answer_heads_as_legacy_rustfs",
            "clamp_oversized_max_keys",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            render_profile_posture(&switches),
            "PROFILE_POSTURE switches=[answer_heads_as_legacy_rustfs,clamp_oversized_max_keys,write_responses_as_rustfs]"
        );
    }

    /// Negative — two assemblies that differ in one switch render differently: the line is a
    /// distinguishing observation, not a label.
    #[test]
    fn n_one_switch_more_renders_differently() {
        let fewer: BTreeSet<&'static str> = ["clamp_oversized_max_keys"].into_iter().collect();
        let more: BTreeSet<&'static str> = ["clamp_oversized_max_keys", "answer_heads_as_legacy_rustfs"]
            .into_iter()
            .collect();
        assert_ne!(render_profile_posture(&fewer), render_profile_posture(&more));
        assert!(render_profile_posture(&fewer).ends_with("switches=[clamp_oversized_max_keys]"));
    }
}
