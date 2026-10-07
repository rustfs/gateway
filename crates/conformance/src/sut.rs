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

//! The seam between the runner and the system under test.
//!
//! Responsible for: the one trait a target implements to be measured — establish the fixtures,
//! run one exchange, report what was observed — plus the two implementations that need no target
//! at all: [`Unwired`], which reports precisely why nothing can run, and [`Scripted`], which
//! replays canned observations so the runner itself is testable.
//! NOT responsible for: judging an observation (`crate::expect`), or how bytes reach a server. A
//! real transport writes raw bytes on a socket — never through an SDK, because an SDK normalises
//! away the malformed framing a negative case exists to send.
//! Upstream: `crate::observation`. Downstream: `crate::runner`.

use crate::interpolate::Captures;
use crate::observation::Observation;
use crate::value::Value;
pub use rustfs_gateway::Transport;
use std::collections::BTreeMap;

/// How long a target here lets a committed continuation go without producing its outcome.
///
/// Two seconds, and deliberately not the shipped `rustfs_gateway::DEFAULT_COMMIT_PROGRESS_DEADLINE`,
/// which is a minute. What `c-mpu-0040` asserts is *that* a stalled completion is ended and with
/// which document; a real minute of waiting to say so would be a tenth of the whole gate's clock
/// spent watching a timer. Far above every other case's entire runtime, so nothing that answers is
/// bounded by it — which is the property `c-mpu-0040`'s slow-continuation control turns on.
///
/// Read by `crate::inprocess`, which assembles the service both transports run against.
pub const COMMIT_PROGRESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// Which implementation profile the target claims, gating `case.applies_to.profiles`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// AWS S3 behaviour.
    Aws,
    /// MinIO behaviour.
    Minio,
    /// The strictest reading, where implementations legitimately diverge.
    Strict,
    /// Legacy RustFS behaviour: the readings `ServiceBuilder::rustfs_profile` applies
    /// (`docs/rustfs-profile.md`, rustfs/backlog#2751), measured on an external candidate.
    ///
    /// Never inherits another profile's expectations: a case that names `minio` is skipped under
    /// it exactly as under `aws`. The bundled reference target does not run the preset, so the
    /// claim is only accepted with `--endpoint` (rustfs/backlog#2757).
    Rustfs,
}

impl Profile {
    /// The command-line spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Aws => "aws",
            Profile::Minio => "minio",
            Profile::Strict => "strict",
            Profile::Rustfs => "rustfs",
        }
    }

    /// Parses the command-line spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Profile> {
        match text {
            "aws" => Some(Profile::Aws),
            "minio" => Some(Profile::Minio),
            "strict" => Some(Profile::Strict),
            "rustfs" => Some(Profile::Rustfs),
            _ => None,
        }
    }
}

/// What a target reports about itself when asked, beyond [`Sut::describe`].
///
/// Both fields are observations or absent. The endpoint is the URL the run was pointed at; the
/// build is the `Server` header the target sent on an unsigned `HEAD /`, verbatim. A target that
/// sends no such header has no build here — the report says `null`, never a product name the probe
/// did not see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetIdentity {
    /// The URL the run was pointed at, when it was pointed at one.
    pub endpoint: Option<String>,
    /// The target's `Server` header, when it sent one.
    pub build: Option<String>,
}

/// Everything a target needs to perform one exchange.
#[derive(Debug, Clone)]
pub struct ExchangePlan<'a> {
    /// The case this exchange belongs to.
    pub case_id: &'a str,
    /// Zero-based index within the case.
    pub index: usize,
    /// The request specification with every `${capture.*}` already substituted, so an
    /// interpolated value is covered by the signature the target computes.
    pub request: Value,
    /// The case's `[clock]` block, when it has one.
    pub clock: Option<&'a Value>,
    /// The case's `[connection]` block, when it has one.
    pub connection: Option<&'a Value>,
    /// Remaining target budget for this exchange, excluding measured harness waits.
    pub timeout_ms: Option<i64>,
    /// Absolute case deadline supplied by the runner. Direct callers may leave it absent.
    /// Transports must not restart this clock after listener setup or request preparation.
    pub deadline: Option<std::time::Instant>,
    /// The assembly path this run uses.
    pub transport: Transport,
    /// The profile the target claims.
    pub profile: Profile,
}

/// Why an exchange could not be attempted.
///
/// Kept distinct from a failed assertion on purpose: a connection refused is an environment
/// problem, and recording it as a red case poisons the baseline with a result that says nothing
/// about the implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SutError {
    /// No target is wired up. Carries the capabilities that are missing.
    NotWired {
        /// A one-line description of what is missing.
        reason: String,
        /// The public items a target would need, in the order they are needed.
        missing: Vec<String>,
    },
    /// The target exists but could not be reached or driven.
    Environment(String),
    /// The case needs something of the wire this target's transport cannot do — a socket, TLS,
    /// HTTP/2 frames, connection control, concurrent dispatch — which a socket transport can.
    /// Kept apart from [`SutError::Environment`] because the reference evaluation re-judges exactly
    /// these on a socket, and nothing else (rustfs/gateway#985).
    TransportLimit(String),
}

impl core::fmt::Display for SutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SutError::NotWired { reason, .. } => f.write_str(reason),
            SutError::Environment(reason) | SutError::TransportLimit(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for SutError {}

/// A system under test.
pub trait Sut {
    /// A one-line description for the report header.
    fn describe(&self) -> String;

    /// Whether this authored exchange is configured to use TLS, for applicability gates.
    ///
    /// This reports configuration, not transport support or an observed handshake. A matching
    /// gate must still reach the transport's normal capability checks. The default is cleartext.
    /// Called before fixture preparation with the authored request and case connection block;
    /// implementations must not derive this from a session left by an earlier case.
    fn configured_tls(&self, _request: &Value, _connection: Option<&Value>) -> bool {
        false
    }

    /// Establishes the fixtures a case declares, returning any captures the setup minted.
    ///
    /// Setup traffic is not under test: a target may use normalised, correctly signed requests
    /// for it.
    ///
    /// # Errors
    ///
    /// Returns [`SutError`] when the fixtures cannot be established.
    fn prepare(&mut self, case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError>;

    /// Performs one exchange and reports what was observed.
    ///
    /// # Errors
    ///
    /// Returns [`SutError`] when the exchange could not be attempted at all. A response that
    /// merely fails the case's assertions is a successful call returning an [`Observation`].
    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError>;

    /// Performs every plan as one concurrent batch and returns observations in plan order.
    ///
    /// A target must not implement this by calling [`Sut::exchange`] in a loop: all requests must
    /// be dispatched before any response is awaited. Targets without that capability fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`SutError`] when independent concurrent dispatch is unavailable.
    fn exchange_concurrent(&mut self, _plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        Err(SutError::TransportLimit(
            "this target cannot dispatch a concurrent exchange batch".to_owned(),
        ))
    }

    /// Releases anything the case allocated. The default does nothing.
    ///
    /// # Errors
    ///
    /// Returns [`SutError`] when cleanup fails in a way that would affect the next case.
    fn finish(&mut self, case_id: &str) -> Result<(), SutError> {
        let _ = case_id;
        Ok(())
    }

    /// Asks the target what it is, for the report header: its endpoint and its `Server` header.
    ///
    /// The default reports nothing, which is the truth for every target that was not pointed at
    /// a URL. An external target probes once, before the run, and reports what it observed.
    ///
    /// # Errors
    ///
    /// Returns [`SutError`] when the target could not be reached for the probe.
    fn identity(&mut self) -> Result<TargetIdentity, SutError> {
        Ok(TargetIdentity::default())
    }
}

/// The public items the `rustfs-gateway` facade must expose before a target can be wired.
///
/// The conformance suite may only use the facade's public API — it is a product other S3
/// implementations run against themselves, so reaching into `-core`, `-http` or `-sig` would make
/// it untestable anywhere else. Until these exist, every case is reported as skipped with this
/// list attached, which is deliberately louder than a green run that asserted nothing.
pub const REQUIRED_FACADE_EXPORTS: &[&str] = &[
    "rustfs_gateway::ServiceBuilder — assemble a service from a Router and run it in-process",
    "rustfs_gateway::Transport (hyper | conn) — select the assembly path the runner injects",
    "rustfs_gateway::WireRequest / WireResponse — submit a request built from raw bytes and read \
     the response head, body, trailers and wire header order back",
    "rustfs_gateway::Body / ByteStream — feed a timed chunk sequence and observe how much of it \
     was consumed before the response head arrived",
    "rustfs_gateway::sig::Signer — compute a SigV4 header, streaming, streaming-trailer, \
     unsigned-payload or presigned signature client-side; the -sig crate today verifies \
     signatures and cannot produce one",
    "rustfs_gateway::Clock — inject `[clock] fixed`, `skew_ms` and `request_time` so a body \
     containing a timestamp can be compared byte for byte",
    "rustfs_gateway::Credentials — the fixture credentials a case names as valid, \
     unknown_access_key, expired_session or wrong_secret",
];

/// The default target: none.
///
/// Every exchange fails with [`SutError::NotWired`], which the runner turns into a skipped case
/// carrying the reason. A case that did not run and a case that ran and failed are different
/// facts, and this type exists so they never look the same in a report.
#[derive(Debug, Clone, Default)]
pub struct Unwired;

impl Sut for Unwired {
    fn describe(&self) -> String {
        "no system under test (the rustfs-gateway facade exposes no service entry point yet)".to_owned()
    }

    fn prepare(&mut self, _case_id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        Err(not_wired())
    }

    fn exchange(&mut self, _plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        Err(not_wired())
    }
}

fn not_wired() -> SutError {
    SutError::NotWired {
        reason: "no system under test is wired: the `rustfs-gateway` facade exposes no service \
                 entry point, and the conformance suite may only use the facade's public API"
            .to_owned(),
        missing: REQUIRED_FACADE_EXPORTS.iter().map(|item| (*item).to_owned()).collect(),
    }
}

/// A target that replays canned observations, keyed by `<case id>#<exchange index>`.
///
/// This is what makes the runner testable without a server. It is not a mock of an S3
/// implementation and must never be used to make a case look green.
#[derive(Debug, Clone, Default)]
pub struct Scripted {
    observations: BTreeMap<String, Observation>,
    setup_captures: Captures,
    /// Requests the runner handed over, in order, so a test can assert what was actually sent.
    pub seen: Vec<Value>,
}

impl Scripted {
    /// An empty script.
    #[must_use]
    pub fn new() -> Scripted {
        Scripted::default()
    }

    /// Binds an observation to one exchange of one case.
    #[must_use]
    pub fn with(mut self, case_id: &str, index: usize, observation: Observation) -> Scripted {
        self.observations.insert(format!("{case_id}#{index}"), observation);
        self
    }

    /// Binds a capture that setup would have minted.
    #[must_use]
    pub fn with_setup_capture(mut self, name: &str, value: &str) -> Scripted {
        self.setup_captures.insert(name.to_owned(), value.to_owned());
        self
    }
}

impl Sut for Scripted {
    fn describe(&self) -> String {
        format!("scripted target with {} canned observations", self.observations.len())
    }

    fn prepare(&mut self, _case_id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        Ok(self.setup_captures.clone())
    }

    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        self.seen.push(plan.request.clone());
        self.observations
            .get(&format!("{}#{}", plan.case_id, plan.index))
            .cloned()
            .ok_or_else(|| SutError::Environment(format!("no scripted observation for {}#{}", plan.case_id, plan.index)))
    }

    fn exchange_concurrent(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        plans.iter().map(|plan| self.exchange(plan)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unwired_target_never_reports_a_pass() {
        let mut sut = Unwired;
        let error = sut.prepare("c-etag-0001", None).expect_err("must not succeed");
        assert!(matches!(error, SutError::NotWired { .. }));
    }

    #[test]
    fn the_unwired_target_names_what_the_facade_must_expose() {
        let mut sut = Unwired;
        let plan = ExchangePlan {
            case_id: "c-etag-0001",
            index: 0,
            request: Value::empty_table(),
            clock: None,
            connection: None,
            timeout_ms: None,
            deadline: None,
            transport: Transport::Hyper,
            profile: Profile::Aws,
        };
        match sut.exchange(&plan) {
            Err(SutError::NotWired { missing, .. }) => {
                assert!(missing.iter().any(|item| item.contains("ServiceBuilder")), "{missing:?}");
                assert!(missing.iter().any(|item| item.contains("Signer")), "{missing:?}");
            }
            other => panic!("expected NotWired, got {other:?}"),
        }
    }

    #[test]
    fn transport_and_profile_spellings_round_trip() {
        assert_eq!(Transport::parse("conn"), Some(Transport::Conn));
        assert_eq!(Transport::parse("h3"), None);
        assert_eq!(Profile::parse("minio").map(Profile::as_str), Some("minio"));
        assert_eq!(Profile::parse("rustfs"), Some(Profile::Rustfs));
        assert_eq!(Profile::Rustfs.as_str(), "rustfs");
        assert_eq!(Profile::parse("RustFS"), None, "the spelling is the command line's, lower-case");
        assert_eq!(Profile::parse("nope"), None);
    }

    /// Negative — a target that was never asked reports nothing about itself: no endpoint, no
    /// build. The default must never invent either.
    #[test]
    fn a_target_without_an_endpoint_has_no_identity_to_report() {
        assert_eq!(Unwired.identity().expect("nothing to ask"), TargetIdentity::default());
        assert_eq!(Scripted::new().identity().expect("nothing to ask"), TargetIdentity::default());
        assert_eq!(
            TargetIdentity::default(),
            TargetIdentity {
                endpoint: None,
                build: None
            }
        );
    }

    #[test]
    fn a_scripted_target_without_a_binding_is_an_environment_error_not_a_failure() {
        let mut sut = Scripted::new();
        let plan = ExchangePlan {
            case_id: "c-etag-0001",
            index: 0,
            request: Value::empty_table(),
            clock: None,
            connection: None,
            timeout_ms: None,
            deadline: None,
            transport: Transport::Hyper,
            profile: Profile::Aws,
        };
        assert!(matches!(sut.exchange(&plan), Err(SutError::Environment(_))));
    }
}
