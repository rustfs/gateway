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

//! Why a service refused to be assembled, and the rule reference every refusal carries.
//!
//! Responsible for: [`RuleRef`] — the `asm-*` identifier a refusal cites — and [`AssemblyError`],
//! the single answer to "why did this service refuse to start".
//! NOT responsible for: performing any of the checks. Registration rules are
//! `rustfs_gateway_core::RouterBuilder::build`'s and are surfaced here unchanged; the extension
//! point rules are [`crate::ServiceBuilder::build`]'s.
//! Upstream: `rustfs-gateway-core`. Downstream: [`crate::ServiceBuilder`].
//!
//! # Why every variant carries a rule reference
//!
//! An assembly refusal is read once, by whoever is holding a service that will not start, and the
//! useful question is always "which rule is this and where is it written down". A message alone
//! sends them grepping. The identifier is a `&'static str` in a closed namespace so that a
//! reference cannot be invented at a call site and so that a future `cargo xtask why` has a set to
//! resolve against.
//!
//! # Why nothing here degrades to a warning
//!
//! Every refusal below is decidable at assembly time and every one of them changes which handler a
//! request reaches. A service that started anyway with the conflict logged is the shape that turns
//! a configuration mistake into a silent authorisation hole, so [`crate::ServiceBuilder::build`]
//! returns nothing at all when it refuses.

use core::fmt;

use rustfs_gateway_core::BuildError;

/// The identifier of one assembly-time rule.
///
/// Opaque and constructible only from the constants below, so a refusal cannot cite a rule that
/// does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleRef {
    id: &'static str,
    explanation: &'static str,
    acceptance: &'static str,
}

impl RuleRef {
    /// The rule's identifier, in the `asm-*` namespace.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.id
    }

    /// What the rule means, in one sentence. This is what a `why` lookup prints.
    ///
    /// Carried on the value rather than looked up from the identifier: a lookup keyed on a string
    /// has a fallback arm, and the fallback is where a rule with no explanation hides.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        self.explanation
    }

    /// The acceptance checks that exercise the rule.
    #[must_use]
    pub const fn acceptance(self) -> &'static str {
        self.acceptance
    }

    /// A registration this build refused: a duplicate, an un-namespaced third-party name, a name
    /// that collides with an AWS one, or an operation with no authorisation action.
    pub const REGISTRATION: Self = Self {
        id: "asm-registration-refused",
        explanation: "a handler registration was refused: a duplicate operation, a third-party name that is not namespaced or \
                      that collides with an AWS one, or an operation with no authorisation action",
        acceptance: "a-asm-0012, a-asm-0013, a-asm-0014",
    };

    /// A route table that will not build: an overlap at one precedence, or a third-party entry
    /// standing in front of a standard operation.
    pub const ROUTE: Self = Self {
        id: "asm-route-refused",
        explanation: "the route table refused to build: two entries overlap at one precedence, or a third-party entry stands \
                      in front of a standard operation",
        acceptance: "a-asm-0011, a-asm-0015",
    };

    /// No operation was registered at all.
    pub const EMPTY_REGISTRY: Self = Self {
        id: "asm-empty-registry",
        explanation: "no operation was registered; a service that answers every request with 501 is a configuration mistake \
                      rather than a deployment, and starting it hides the mistake until traffic arrives",
        acceptance: "a-asm-0016",
    };

    /// No [`crate::Authorizer`] was installed.
    pub const MISSING_AUTHORIZER: Self = Self {
        id: "asm-missing-authorizer",
        explanation: "no Authorizer was installed; there is no default allow and no default deny, because a default either \
                      fails open or makes every deployment look broken in the same way",
        acceptance: "a-asm-0009, a-asm-0010",
    };

    /// No [`crate::Authenticator`] was installed.
    pub const MISSING_AUTHENTICATOR: Self = Self {
        id: "asm-missing-authenticator",
        explanation: "no Authenticator was installed; without one an AWS-signed request has nothing to verify it, and the only \
                      two ways out of that are to reject everything or to accept everything",
        acceptance: "a-asm-0017",
    };

    /// An operation was registered with the core router but has no wire codec bound to it.
    pub const MISSING_CODEC: Self = Self {
        id: "asm-missing-codec",
        explanation: "an operation reached the router without a wire codec; the request would route and then have nothing able \
                      to read it",
        acceptance: "a-asm-0017",
    };

    /// An [`crate::OpLayer`] was registered for an operation that has no handler.
    pub const OP_LAYER_UNATTACHED: Self = Self {
        id: "asm-op-layer-unattached",
        explanation: "an operation layer was registered for an operation with no handler; ignoring it would leave the \
                      deployment believing a rewrite is in force while nothing ever runs it",
        acceptance: "a-asm-0017",
    };

    /// Two operation types claimed one name, so a layer could not be matched to its operation.
    pub const OP_LAYER_TYPE: Self = Self {
        id: "asm-op-layer-type",
        explanation: "an operation layer could not be matched to the operation it was registered under; two operation types \
                      are claiming one name, and running the layer would apply it to the wrong input",
        acceptance: "a-asm-0017",
    };

    /// A custom wall clock was too far from the system clock without an explicit acknowledgement.
    pub const CLOCK_SKEW: Self = Self {
        id: "asm-clock-skew",
        explanation: "a custom wall clock differs from the system clock by more than the allowed window; a frozen or skewed \
                      clock can keep captured signatures valid, so assembly requires an explicit acknowledgement",
        acceptance: "a-asm-0017",
    };

    /// Every rule this crate can cite, for a reverse lookup and for the assertion that the set is
    /// closed.
    pub const ALL: [Self; 9] = [
        Self::REGISTRATION,
        Self::ROUTE,
        Self::EMPTY_REGISTRY,
        Self::MISSING_AUTHORIZER,
        Self::MISSING_AUTHENTICATOR,
        Self::MISSING_CODEC,
        Self::OP_LAYER_UNATTACHED,
        Self::OP_LAYER_TYPE,
        Self::CLOCK_SKEW,
    ];
}

impl fmt::Display for RuleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id)
    }
}

/// Why a service could not be assembled.
///
/// `#[non_exhaustive]` because the assembly-time rule set grows as extension points land, and a
/// downstream `match` that stopped compiling on every addition would be a reason not to add one.
#[non_exhaustive]
#[derive(Debug)]
pub enum AssemblyError {
    /// The core router refused: registrations, route names, or the table itself.
    Router {
        /// What the router said, verbatim. It already names every refused registration.
        ///
        /// Boxed: `BuildError` carries a `Vec` of refusals and is an order of magnitude wider than
        /// every other variant, so an unboxed one would make `build`'s `Result` pay for the
        /// failure shape on the success path too.
        source: Box<BuildError>,
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// Nothing was registered.
    EmptyRegistry {
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// No authorizer was installed.
    MissingAuthorizer {
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// No authenticator was installed.
    MissingAuthenticator {
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// An operation registered with the router has no wire codec.
    MissingCodec {
        /// The operation that would route and then be unreadable.
        operation: &'static str,
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// An [`crate::OpLayer`] was registered for an operation nobody handles.
    UnattachedOpLayer {
        /// The operation the layer named.
        operation: &'static str,
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// A layer could not be matched back to the operation it was registered under.
    OpLayerTypeMismatch {
        /// The operation name both types claimed.
        operation: &'static str,
        /// Which assembly rule this is.
        rule: RuleRef,
    },
    /// A custom clock exceeded the assembly-time skew bound.
    ClockSkew {
        /// The observed absolute difference in seconds.
        skew_seconds: u64,
        /// Which assembly rule this is.
        rule: RuleRef,
    },
}

impl AssemblyError {
    /// The rule this refusal cites. Every variant has one; that is the point of the type.
    #[must_use]
    pub const fn rule(&self) -> RuleRef {
        match self {
            Self::Router { rule, .. }
            | Self::EmptyRegistry { rule }
            | Self::MissingAuthorizer { rule }
            | Self::MissingAuthenticator { rule }
            | Self::MissingCodec { rule, .. }
            | Self::UnattachedOpLayer { rule, .. }
            | Self::OpLayerTypeMismatch { rule, .. }
            | Self::ClockSkew { rule, .. } => *rule,
        }
    }
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = self.rule();
        match self {
            Self::Router { source, .. } => write!(f, "[{rule}] {source}"),
            Self::MissingCodec { operation, .. } => {
                write!(f, "[{rule}] the operation {operation} has no wire codec: {}", rule.explanation())
            }
            Self::UnattachedOpLayer { operation, .. } | Self::OpLayerTypeMismatch { operation, .. } => {
                write!(f, "[{rule}] the operation {operation}: {}", rule.explanation())
            }
            Self::ClockSkew { skew_seconds, .. } => {
                write!(f, "[{rule}] custom clock skew is {skew_seconds}s: {}", rule.explanation())
            }
            _ => write!(f, "[{rule}] {}", rule.explanation()),
        }
    }
}

impl std::error::Error for AssemblyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Router { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<BuildError> for AssemblyError {
    fn from(source: BuildError) -> Self {
        let rule = match source {
            BuildError::Registration(_) => RuleRef::REGISTRATION,
            BuildError::RouteClaimsStandardName { .. } | BuildError::Route(_) => RuleRef::ROUTE,
        };
        Self::Router {
            source: Box::new(source),
            rule,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — no rule may be spelled outside the `asm-` namespace, or a refusal could cite a
    /// reference no lookup resolves.
    #[test]
    fn every_rule_is_in_the_asm_namespace() {
        for rule in RuleRef::ALL {
            assert!(rule.as_str().starts_with("asm-"), "{rule}");
        }
    }

    /// Negative — a rule with no explanation is a rule a reader cannot act on.
    #[test]
    fn every_rule_explains_itself() {
        for rule in RuleRef::ALL {
            assert!(rule.explanation().len() > 40, "{rule}");
        }
    }

    /// Negative — two rules sharing an identifier would make the reverse lookup ambiguous.
    #[test]
    fn rule_identifiers_are_unique() {
        let mut seen: Vec<&str> = RuleRef::ALL.iter().map(|rule| rule.as_str()).collect();
        seen.sort_unstable();
        let count = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), count);
    }

    /// Positive — the displayed refusal leads with its rule, which is what makes it greppable.
    #[test]
    fn a_refusal_leads_with_its_rule() {
        let error = AssemblyError::MissingAuthorizer {
            rule: RuleRef::MISSING_AUTHORIZER,
        };
        assert!(error.to_string().starts_with("[asm-missing-authorizer]"), "{error}");
    }
}
