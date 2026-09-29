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

//! The `NAMING_POSTURE` start-up line: the slash rule and the key floor an assembly names keys
//! under (rustfs/gateway#1107).
//!
//! Responsible for: rendering and logging the two naming choices that decide which key an object
//! is stored under and which keys reach the backend at all.
//! NOT responsible for: the `SECURITY_POSTURE` and `DIALECT_POSTURE` lines, whose exact shapes
//! `crate::posture` and `crate::dialect_posture` pin, or applying either choice.
//! Upstream: `crate::builder`. Downstream: startup logs and operators.

use rustfs_gateway_types::NamePolicy;

/// The naming half of the start-up report: the slash rule (persistence-affecting when it rewrites
/// keys) and the key floor (security-relevant when it lowers the default).
///
/// A line of its own, as `DIALECT_POSTURE` is, so that neither of the existing lines changes shape.
pub(crate) fn render_naming_posture(names: &NamePolicy) -> String {
    let slash = names.slash_policy();
    let floor = names.key_floor();
    format!(
        "NAMING_POSTURE slash_policy={} slash_rewrites_keys={} key_floor={} key_floor_lowered={}",
        slash.as_str(),
        slash.rewrites_keys(),
        floor.as_str(),
        floor.lowers_the_default(),
    )
}

/// Writes [`render_naming_posture`] to the start-up log.
pub(crate) fn log_naming_posture(names: &NamePolicy) {
    eprintln!("{}", render_naming_posture(names));
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test names the field it could not find")]
mod tests {
    use rustfs_gateway_types::{NamePolicy, SlashPolicy};

    use super::render_naming_posture;

    /// The value of one `name=value` field of the line, and that it appears exactly once.
    fn field<'a>(line: &'a str, name: &str) -> &'a str {
        let prefix = format!("{name}=");
        let mut values = line.split(' ').filter_map(|field| field.strip_prefix(prefix.as_str()));
        let value = values.next().unwrap_or_else(|| panic!("{name} is missing from {line}"));
        assert!(values.next().is_none(), "{name} appears twice in {line}");
        value
    }

    /// Negative — the default names nothing lowered and nothing rewritten, so a report that always
    /// printed the RustFS values would fail here.
    #[test]
    fn the_default_reports_the_aws_rules() {
        let line = render_naming_posture(&NamePolicy::default());
        assert!(line.starts_with("NAMING_POSTURE "), "{line}");
        assert_eq!(field(&line, "slash_policy"), "aws-preserve");
        assert_eq!(field(&line, "slash_rewrites_keys"), "false");
        assert_eq!(field(&line, "key_floor"), "unconditional");
        assert_eq!(field(&line, "key_floor_lowered"), "false");
    }

    /// Positive — the RustFS profile reports both of its choices, the lowered floor by name.
    #[test]
    fn the_rustfs_profile_reports_the_legacy_rules() {
        let rustfs = NamePolicy::default()
            .with_slash_policy(SlashPolicy::RustfsLegacy)
            .with_legacy_rustfs_key_floor();
        let line = render_naming_posture(&rustfs);
        assert_eq!(field(&line, "slash_policy"), "rustfs-legacy");
        assert_eq!(field(&line, "slash_rewrites_keys"), "true");
        assert_eq!(field(&line, "key_floor"), "rustfs-legacy");
        assert_eq!(field(&line, "key_floor_lowered"), "true");
    }

    /// Negative — the two choices are reported independently: the slash rule alone lowers nothing.
    #[test]
    fn the_slash_rule_alone_reports_the_unconditional_floor() {
        let line = render_naming_posture(&NamePolicy::default().with_slash_policy(SlashPolicy::RustfsLegacy));
        assert_eq!(field(&line, "slash_policy"), "rustfs-legacy");
        assert_eq!(field(&line, "key_floor"), "unconditional");
        assert_eq!(field(&line, "key_floor_lowered"), "false");
    }
}
