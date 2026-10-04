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
use super::legacy_credential::{
    LegacyScope, invalid_region_sentence, is_legacy_region, read_authorization, read_scope, signed_headers_refusal,
};
use super::legacy_refusal::LegacyRefusal;
use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AuthError, CredentialScope, EmptyRegion, ExpectedScope, RegionLength, RegionRule, RegionSet, SealedAws,
    ServiceReading, SigLocation, SignedHeaderSet, X_AMZ_DATE, X_AMZ_DATE_HEADER,
};
use rustfs_gateway_types::ErrorCode;

/// Legacy RustFS's sentence for a scope date other than the signed timestamp's day.
const SCOPE_DATE_SENTENCE: &str = "credential scope date does not match x-amz-date";

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
    /// Legacy RustFS's answers to a scope date and a region it refuses (rustfs/gateway#1130).
    pub(super) legacy_scope_refusals: bool,
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

    /// Legacy RustFS's words for a region refused after the signature, under the legacy scope
    /// refusals.
    pub(super) fn verified_region_refusal(self, region: &str) -> Option<LegacyRefusal> {
        self.legacy_scope_refusals
            .then(|| LegacyRefusal::new(ErrorCode::INVALID_REQUEST, invalid_region_sentence(region)))
    }

    /// Legacy RustFS's answer to a scope dated other than `signed_day`, under the legacy scope
    /// refusals.
    pub(super) fn scope_date_refusal(self, scope_date: &str, signed_day: &str) -> Option<(AuthError, LegacyRefusal)> {
        (self.legacy_scope_refusals && scope_date != signed_day).then(|| {
            (
                AuthError::SignatureDoesNotMatch,
                LegacyRefusal::new(ErrorCode::SIGNATURE_DOES_NOT_MATCH, SCOPE_DATE_SENTENCE),
            )
        })
    }

    /// Legacy RustFS's answer to a credential the gateway's parsers could not read, under the legacy
    /// scope refusals: legacy RustFS reads a region with a separator, a control byte or a non-ASCII
    /// byte, and a POST form whose scope date is not its `x-amz-date` day, and refuses both.
    pub(super) fn unreadable_scope_refusal(
        self,
        sealed: &SealedAws<'_>,
        location: SigLocation,
    ) -> Option<(AuthError, LegacyRefusal)> {
        if !self.legacy_scope_refusals {
            return None;
        }
        let view = sealed.view();
        let refused = |scope: LegacyScope<'_>, signed: Option<&str>| {
            if let Some(refusal) = signed.and_then(|stamp| self.scope_date_refusal(scope.date, stamp.get(..8)?)) {
                return Some(refusal);
            }
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a region with a separator,
            // a control byte or a non-ASCII byte, derives a key from it and refuses it only after
            // the signature, naming it. This refuses it before any key is derived, with legacy
            // RustFS's code and sentence; the intended future behaviour is the gateway's own
            // answer to a credential it cannot read.
            (!is_legacy_region(scope.region)).then(|| {
                (
                    AuthError::InvalidCredentialRegion,
                    LegacyRefusal::new(ErrorCode::INVALID_REQUEST, invalid_region_sentence(scope.region)),
                )
            })
        };
        match location {
            SigLocation::Header => {
                // Decoded as UTF-8, as legacy RustFS decodes a header value.
                let utf8 = |name| {
                    view.headers()
                        .get(name)
                        .and_then(|value: &http::HeaderValue| core::str::from_utf8(value.as_bytes()).ok())
                };
                refused(read_authorization(utf8(AUTHORIZATION_HEADER)?)?.scope, utf8(X_AMZ_DATE_HEADER))
            }
            SigLocation::Query => {
                let credential = view.query().decoded_value(rustfs_gateway_sig::X_AMZ_CREDENTIAL).ok()??;
                let signed = view.query().decoded_value(X_AMZ_DATE).ok().flatten();
                refused(read_scope(&credential)?, signed.as_deref())
            }
            SigLocation::FormField => {
                let credential = view.form_value("x-amz-credential")?;
                refused(read_scope(credential)?, view.form_value("x-amz-date"))
            }
            _ => None,
        }
    }
}

impl SigV4Authenticator {
    /// The request's `SignedHeaders` list, read and held to the completeness rules: verbatim, as
    /// legacy RustFS reads a list AWS would call malformed, under
    /// [`read_signed_headers_as_legacy_rustfs`](Self::read_signed_headers_as_legacy_rustfs).
    pub(super) fn read_signed_headers(
        &self,
        raw: &str,
        headers: &http::HeaderMap,
        wire_content_length: Option<u64>,
        location: SigLocation,
    ) -> Result<SignedHeaderSet, AuthError> {
        match (self.legacy_signed_headers, location) {
            (true, SigLocation::Header) => {
                SignedHeaderSet::parse_and_enforce_header_as_legacy_rustfs(raw, headers, wire_content_length)
            }
            (false, SigLocation::Header) => SignedHeaderSet::parse_and_enforce_header(raw, headers, wire_content_length),
            (true, _) => SignedHeaderSet::parse_and_enforce_as_legacy_rustfs(raw, headers, wire_content_length),
            (false, _) => SignedHeaderSet::parse_and_enforce(raw, headers, wire_content_length),
        }
    }

    /// Legacy RustFS's words for a `SignedHeaders` list refused with `error`, under the legacy
    /// reading: a name the request did not send, or sent unreadable, and an `x-amz-*` header the
    /// list leaves out. Header authentication covers `x-amz-content-sha256` in HashedPayload and
    /// may leave it out of the header list; a presigned request must still name a present header.
    pub(super) fn signed_headers_refusal(
        &self,
        raw: &str,
        headers: &http::HeaderMap,
        location: SigLocation,
        error: &AuthError,
    ) -> Option<LegacyRefusal> {
        if !self.legacy_signed_headers || *error != AuthError::SignatureDoesNotMatch {
            return None;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS names the header a signature
        // declared and the request lacks, and answers an unsigned `x-amz-*` header with
        // `AccessDenied` after it has looked the key up. Kept: the codes and sentences. The
        // intended future behaviour is the gateway's uniform `SignatureDoesNotMatch`, which names
        // nothing the request chose.
        let (code, sentence) = signed_headers_refusal(raw, headers, location == SigLocation::Header)?;
        Some(LegacyRefusal::new(code, sentence))
    }

    /// Reads `SignedHeaders` as legacy RustFS reads it, and answers its refusals in legacy RustFS's
    /// words, as RustFS does today (rustfs/gateway#1130): a list AWS would call malformed — a name
    /// in uppercase, out of order or repeated — is read verbatim (each name as written, in the
    /// order written, a name repeated in a row once, its values looked up case-insensitively)
    /// rather than refused `400 AuthorizationHeaderMalformed`, so a client that signed that same
    /// string is verified and one that signed another is `403 SignatureDoesNotMatch`; a name the
    /// request did not send is `403 SignatureDoesNotMatch` `missing signed header: <name>`; and an
    /// `x-amz-*` header the list leaves out is `403 AccessDenied` "There were headers present in
    /// the request which were not signed".
    ///
    /// Off by default. Host and every semantic `x-amz-*` header remain signed. Both readings
    /// permit header authentication to cover `x-amz-content-sha256` through HashedPayload;
    /// presigned requests retain full header coverage. Every named header is still hashed; this
    /// switch changes only the list spelling in the string to sign and the words of a refusal.
    #[must_use]
    pub fn read_signed_headers_as_legacy_rustfs(mut self) -> Self {
        self.legacy_signed_headers = true;
        self
    }

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
    /// An ordinary request reaching header verification with `sts` scope and no
    /// `x-amz-content-sha256` uses the body's SHA-256 after lookup, bounded at 8192 bytes; a
    /// longer body is `400 InvalidRequest` before comparison (rustfs/gateway#1230). The service
    /// retains those bytes for the operation's body handoff; browser forms keep their own path.
    ///
    /// Off by default: the default verifies only the routed operation's own service, answers an
    /// S3-family service that is not it with `400 AuthorizationHeaderMalformed`, and any other name
    /// as a credential it cannot read, `403 InvalidAccessKeyId`.
    #[must_use]
    pub fn accept_legacy_rustfs_signing_services(mut self) -> Self {
        self.scope_policy.legacy_services = true;
        self
    }

    /// Answers a credential scope legacy RustFS refuses with its code and sentence, as RustFS does
    /// today (rustfs/gateway#1130), on every signing surface: a scope date other than the signed
    /// timestamp's day is `403 SignatureDoesNotMatch` "credential scope date does not match
    /// x-amz-date", before the key is looked up and before the service is judged, as legacy RustFS
    /// refuses it; and a region outside `[a-z0-9-]+` is `400 InvalidRequest` naming it ("invalid
    /// credential region: invalid region: "US-EAST-1"") — one the gateway's parsers read after the
    /// signature, as
    /// [`refuse_unreadable_signing_regions_after_verification`](Self::refuse_unreadable_signing_regions_after_verification)
    /// refuses it and legacy RustFS does, and one they cannot read (a space, a comma in the
    /// `Authorization` header, a control or non-ASCII byte) before any key is looked up or derived,
    /// where legacy RustFS verifies it first (the kept order, rd-loc-0011).
    ///
    /// Off by default: the default answers a scope date or region the scope check refuses with
    /// `400 AuthorizationHeaderMalformed`, a region refused after the signature with the gateway's
    /// sentence, and a credential its parsers cannot read with `403 InvalidAccessKeyId`. The switch
    /// only changes those answers: it admits nothing, derives no key it did not before, and changes
    /// no comparison.
    #[must_use]
    pub fn answer_credential_scope_refusals_as_legacy_rustfs(mut self) -> Self {
        self.scope_policy.legacy_scope_refusals = true;
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
