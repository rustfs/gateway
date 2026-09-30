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

//! The opt-in switches of the built-in SigV4 authenticator: handing the caller's secret to
//! handlers (ADR-0022), verifying any signing region (ADR-0023), the RustFS profile's reading of
//! signing regions — empty, outside the grammar, of any length (rustfs/backlog#1677) — and of
//! signing services (rustfs/gateway#1130), and its narrower raw-path fallback
//! (rustfs/rustfs#2593). All are off by default.
//!
//! Responsible for: the builder methods, their documented posture, and [`ScopePolicy`], which
//! turns the region and service switches into the parsers' credential rule, the scope expectation
//! and the service refusal legacy RustFS answers.
//! NOT responsible for: verification itself, or what a switch changes in it; they are read in
//! `super::authenticator` (and the secret hand-off also in `super::sigv2`).
//! Upstream: `super::authenticator::SigV4Authenticator`. Downstream: deployments assembling the
//! service, the RustFS ring-2 adapter first.

use super::authenticator::SigV4Authenticator;
use super::legacy_refusal::LegacyRefusal;
use rustfs_gateway_sig::{CredentialScope, EmptyRegion, ExpectedScope, RegionLength, RegionRule, RegionSet, ServiceReading};
use rustfs_gateway_types::ErrorCode;

/// The credential-scope services legacy RustFS verifies, on every route: the legacy stack's two
/// defaults and the table catalog's signing name, in the order its refusal lists them (rustfs/rustfs
/// `e870a6d25b` `rustfs/src/server/http.rs:166-172`, `rustfs_s3_config`).
const LEGACY_RUSTFS_SIGNING_SERVICES: [&str; 3] = ["s3", "sts", "s3tables"];

/// The opt-in credential-scope policies of [`SigV4Authenticator`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ScopePolicy {
    /// ADR-0023: any region in the configured-name grammar.
    pub(super) any_region: bool,
    /// The empty region, which legacy RustFS reads as no region.
    pub(super) empty_region: bool,
    /// Any region the parser reads, verified and then refused when outside the grammar
    /// (rustfs/gateway#1075).
    pub(super) any_spelling: bool,
    /// A region of any length, read by the parsers and held to the grammar without its ceiling.
    pub(super) any_length: bool,
    /// Every service legacy RustFS verifies, on every operation (rustfs/gateway#1130).
    pub(super) legacy_services: bool,
}

impl ScopePolicy {
    /// How the credential parsers read the region field: an empty one admitted only when the scope
    /// check admits it too, so a parse that succeeds is never refused by name for its region shape
    /// alone; one of any length only under the any-length policy. And the service field: any name
    /// under the legacy services, which [`Self::service_refusal`] then answers.
    pub(super) const fn region_rule(self) -> RegionRule {
        let empty = if self.empty_region {
            EmptyRegion::Admitted
        } else {
            EmptyRegion::Refused
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a scope region up to the next
        // `/` at any length and serves every one of the grammar, so a correctly signed region
        // longer than any real one is verified and served. No region is that long, and the
        // ceiling keeps request-chosen input small before any key is derived; the intended
        // future behaviour is the default's 64-byte ceiling.
        let length = if self.any_length {
            RegionLength::Unbounded
        } else {
            RegionLength::Bounded
        };
        let services = if self.legacy_services {
            ServiceReading::AnyName
        } else {
            ServiceReading::Known
        };
        RegionRule::STRICT
            .with_empty(empty)
            .with_length(length)
            .with_services(services)
    }

    /// `expected`, widened by exactly the policies this authenticator turned on.
    pub(super) const fn apply(self, expected: ExpectedScope<'_>) -> ExpectedScope<'_> {
        let expected = if self.any_region {
            expected.accepting_any_region()
        } else {
            expected
        };
        let expected = if self.empty_region {
            expected.accepting_empty_region()
        } else {
            expected
        };
        let expected = if self.any_spelling {
            expected.accepting_any_region_spelling()
        } else {
            expected
        };
        let expected = if self.any_length {
            expected.accepting_regions_of_any_length()
        } else {
            expected
        };
        if self.legacy_services {
            expected.accepting_services(&LEGACY_RUSTFS_SIGNING_SERVICES)
        } else {
            expected
        }
    }

    /// Legacy RustFS's answer to a scope naming a service it verifies on no route, under the legacy
    /// services: `501 NotImplemented`, naming the service and the ones it verifies.
    pub(super) fn service_refusal(self, scope: &CredentialScope) -> Option<LegacyRefusal> {
        let service = scope.service_name();
        if !self.legacy_services || LEGACY_RUSTFS_SIGNING_SERVICES.contains(&service) {
            return None;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS echoes the service the request named
        // into its refusal, where every other authentication refusal here is a constant sentence.
        // The name is the caller's own credential text and escaped in the document; the intended
        // future behaviour is a constant sentence.
        let expected = LEGACY_RUSTFS_SIGNING_SERVICES.join(", ");
        Some(LegacyRefusal::new(
            ErrorCode::NOT_IMPLEMENTED,
            format!("unknown service '{service}' in credential scope; expected one of: {expected}"),
        ))
    }

    /// Whether a region the signature was just verified under must now be refused: only under the
    /// any-spelling policy, and only a non-empty region outside the configured-name grammar. The
    /// grammar is checked without its ceiling: the parser already applied the ceiling unless the
    /// any-length policy lifted it, and legacy RustFS applies none.
    pub(super) fn refuses_after_verification(self, region: &str) -> bool {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS derives a key from any scope region,
        // so a client learns whether its signature was right before it learns that `US-EAST-1` is
        // not a region, and the answer is `InvalidRequest` rather than the
        // `AuthorizationHeaderMalformed` naming the region to use. The intended future behaviour is
        // ADR-0023's: refuse the spelling at the scope check, before any key is derived.
        self.any_spelling && !region.is_empty() && !RegionSet::is_region_name_of_any_length(region)
    }
}

impl SigV4Authenticator {
    /// Verifies a SigV4 signature whose credential scope names any region in the configured-name
    /// grammar, not only one this deployment serves: the RustFS profile of rd-loc-0004
    /// (ADR-0023). RustFS verifies every scope region today, and its clients sign with
    /// `us-east-1` or an operator's label whatever the server is set to.
    ///
    /// Off by default, and meant only for a single-endpoint deployment with no per-region
    /// credentials. It changes no key material and no comparison: the key is derived from the
    /// region the client named, and the date and service are still enforced. What it gives up is
    /// the AWS answer that tells a misconfigured client which region to use.
    #[must_use]
    pub fn accept_any_signing_region(mut self) -> Self {
        self.scope_policy.any_region = true;
        self
    }

    /// Verifies a SigV4 signature whose credential scope names an empty region
    /// (`AKID/20260929//s3/aws4_request`): the RustFS profile of the empty region
    /// (rustfs/backlog#1677, ruling R2).
    ///
    /// Legacy RustFS verifies such a signature and then reads the empty region as no region, and
    /// its own replication client signs with one: a bucket target's region, empty unless the
    /// operator set one, is the signing region of the remote client
    /// (rustfs/rustfs@1e7065101d `crates/ecstore/src/bucket/bucket_target_sys.rs:112`,
    /// `crates/ecstore/src/bucket/remote_s3_client.rs:299`). A RustFS deployment that refused it
    /// could not replicate to itself. It is separate from
    /// [`accept_any_signing_region`](Self::accept_any_signing_region) because the empty region is
    /// not a region name, and ADR-0023's grammar deliberately excludes it; the RustFS profile turns
    /// both on.
    ///
    /// Off by default: the default refuses an empty region as a region mismatch,
    /// `400 AuthorizationHeaderMalformed` naming the region to use. Like the any-region switch it
    /// changes no key material and no comparison: the key is derived from the empty region the
    /// client signed with, and the date and service are still enforced.
    #[must_use]
    pub fn accept_empty_signing_region(mut self) -> Self {
        self.scope_policy.empty_region = true;
        self
    }

    /// Verifies a SigV4 signature whose credential scope names a region outside the
    /// configured-name grammar (`US-EAST-1`, `rustfs_local`) and then refuses it with
    /// `400 InvalidRequest`, as legacy RustFS does (rustfs/gateway#1075); a wrong signature over
    /// such a region is `403 SignatureDoesNotMatch` first. The RustFS profile turns it on together
    /// with [`accept_any_signing_region`](Self::accept_any_signing_region) and
    /// [`accept_empty_signing_region`](Self::accept_empty_signing_region).
    ///
    /// Off by default: the default refuses such a region at the scope check, before any key is
    /// derived, with `400 AuthorizationHeaderMalformed` naming the region to use. It admits no
    /// request the default refuses: every region it lets through the scope check it refuses after
    /// the signature, so only the refusal's code and order change.
    #[must_use]
    pub fn refuse_unreadable_signing_regions_after_verification(mut self) -> Self {
        self.scope_policy.any_spelling = true;
        self
    }

    /// Reads a SigV4 credential scope region of any length, as legacy RustFS does: a region of the
    /// configured-name grammar longer than 64 bytes is verified and served under
    /// [`accept_any_signing_region`](Self::accept_any_signing_region), and one outside the grammar
    /// is refused after the signature under
    /// [`refuse_unreadable_signing_regions_after_verification`](Self::refuse_unreadable_signing_regions_after_verification).
    /// The RustFS profile turns it on together with both, and with
    /// [`accept_empty_signing_region`](Self::accept_empty_signing_region).
    ///
    /// Off by default: the default refuses a region over 64 bytes as a credential it cannot read,
    /// with `403 InvalidAccessKeyId`, before any key is derived. The region is still read up to
    /// the next `/`, every byte of it still ASCII-graphic, and the key is still derived from it.
    #[must_use]
    pub fn accept_signing_regions_of_any_length(mut self) -> Self {
        self.scope_policy.any_length = true;
        self
    }

    /// Verifies a SigV4 signature whose credential scope names `s3`, `sts` or `s3tables` on every
    /// operation, and answers a scope naming any other service with `501 NotImplemented` and the
    /// sentence legacy RustFS writes, as legacy RustFS does (rustfs/gateway#1130): the header,
    /// presigned and POST-form surfaces alike.
    ///
    /// RustFS verifies those three services wherever a request is routed — its table-catalog
    /// clients sign `s3tables`, and AWS STS clients sign `sts` — and refuses every other one before
    /// it looks the access key up. The key is derived from the service the client named, so a
    /// signature stays bound to it; the date and region checks are unchanged.
    ///
    /// Off by default: the default verifies only the routed operation's own service, answers an
    /// S3-family service that is not it with `400 AuthorizationHeaderMalformed`, and any other name
    /// as a credential it cannot read, `403 InvalidAccessKeyId`.
    #[must_use]
    pub fn accept_legacy_rustfs_signing_services(mut self) -> Self {
        self.scope_policy.legacy_services = true;
        self
    }

    /// Verifies the wire spelling of a request path, after its decoded spelling failed, only when
    /// the wire path carries a byte a percent-escape would have encoded (anything but
    /// `A-Z a-z 0-9 - _ . ~ / %`), as legacy RustFS does (rustfs/rustfs#2593): a client that signs
    /// a raw `=` or `+` in a key is verified, and a path that differs from its decoded spelling
    /// only in how its escapes are spelled (`%7E`, `%3d`) is verified in the decoded spelling
    /// alone, so a signature over the re-spelled escapes is `403 SignatureDoesNotMatch`.
    ///
    /// Off by default: the default also tries the wire spelling of a path whose escapes a proxy
    /// re-spelled in transit. The switch only removes a candidate; it adds none, changes no key
    /// material and no comparison, and every other check is unchanged.
    #[must_use]
    pub fn verify_raw_paths_only_with_unencoded_bytes(mut self) -> Self {
        self.raw_path = rustfs_gateway_sig::RawPathFallback::WithUnencodedBytes;
        self
    }

    /// Hands the secret this authenticator's own credential lookup returned for an authenticated
    /// principal to the handler, as `RequestPrincipal::secret_key_from_authenticator_lookup`
    /// (ADR-0022).
    ///
    /// Off by default, and meant for a backend that genuinely needs the secret: one that decrypts
    /// a payload the client encrypted with it, or an adapter filling s3s's
    /// `Credentials::secret_key`. The secret travels only after the signature matched and the
    /// credential was admitted; a rejected or anonymous request never carries one, and no lookup
    /// happens that verification did not already make.
    ///
    /// Which handlers receive it is the assembly's decision (ADR-0024): by default only the
    /// operations whose spec calls `OperationSpec::hand_caller_secret_to_handler`, and every one
    /// only after `ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report`.
    #[must_use]
    pub fn hand_caller_secret_to_handlers(mut self) -> Self {
        self.hand_secret = true;
        self
    }
}
