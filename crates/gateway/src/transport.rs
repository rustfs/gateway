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

//! Which assembly path a request travelled.
//!
//! Responsible for: [`Transport`], the two ways a request reaches the same [`crate::S3Service`].
//! NOT responsible for: implementing either path. The hyper adapter is `crate::adapt`, and the
//! connection-level path is P7-03's.
//! Upstream: none. Downstream: `crate::service`, and the conformance runner, which injects one of
//! these per run and requires both to agree.
//!
//! # Why this is a value and not two services
//!
//! The two paths exist so that a defect in one of them is visible: a case that passes over hyper
//! and fails on the self-hosted connection path has found a framing difference, which is exactly
//! the class of defect a single-path suite cannot see. That only works if both paths drive **one**
//! `S3Service` instance, so the choice cannot be expressed as two types.

/// The assembly path a request reaches the service through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Through hyper, as a `hyper::service::Service`.
    Hyper,
    /// Through the connection-level path, which owns its own framing.
    ///
    /// The path itself is P7-03's. Naming it here means a case corpus written today already
    /// declares which runs it expects, rather than being retrofitted when the path lands.
    Conn,
}

impl Transport {
    /// Every variant, so a runner can enumerate the paths without a hand-written list.
    pub const ALL: [Self; 2] = [Self::Hyper, Self::Conn];

    /// The command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hyper => "hyper",
            Self::Conn => "conn",
        }
    }

    /// Parses the command-line spelling.
    ///
    /// Byte-exact and lowercase-only. A tolerant parser here would accept `HYPER` from one script
    /// and reject it from another the moment the spelling reached a case file.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|transport| transport.as_str() == text)
    }
}

impl core::fmt::Display for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — an unknown spelling is `None` rather than a default, or a typo in a runner
    /// invocation would silently measure the wrong path.
    #[test]
    fn an_unknown_spelling_does_not_default() {
        assert_eq!(Transport::parse("h3"), None);
        assert_eq!(Transport::parse(""), None);
    }

    /// Negative — the parser is case-sensitive, so one spelling means one path everywhere.
    #[test]
    fn the_parser_is_case_sensitive() {
        assert_eq!(Transport::parse("HYPER"), None);
        assert_eq!(Transport::parse("Conn"), None);
    }

    /// Positive — every variant round-trips, which is what lets a report name the path it ran.
    #[test]
    fn every_variant_round_trips() {
        for transport in Transport::ALL {
            assert_eq!(Transport::parse(transport.as_str()), Some(transport));
        }
    }
}
