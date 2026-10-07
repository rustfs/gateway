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

//! The RustFS profile as one reviewable entity (rustfs/backlog#2751): the preset that applies every
//! legacy RustFS reading the client-matrix launcher chained by hand, and the census that names
//! each reading an assembly runs for the `PROFILE_POSTURE` start-up line.
//!
//! Responsible for: [`ServiceBuilder::rustfs_profile`] and [`SigV4Authenticator::rustfs_profile`],
//! the two halves of the preset; and `ServiceBuilder::legacy_switches`, which reads the assembled
//! state — never whether a preset was called — and names each legacy reading by the builder method
//! that turns it on.
//! NOT responsible for: the readings themselves (each switch's own module), rendering the line
//! (`crate::profile_posture`), the one reading held by the router (`select_operations_as_legacy_rustfs`,
//! which `crate::startup_report` reads from the assembled router), or what stays the host's:
//! its credentials, authorizer, bucket-owner and CORS sources, host resolver, trace source, SSE
//! transport policy, limits and deadlines.
//! Upstream: `super::ServiceBuilder`, `crate::ext::SigV4Authenticator`. Downstream:
//! `crate::startup_report`, the RustFS bridge and the client-matrix launcher (`compat/sut`).
//!
//! # The switches, what each keeps, and where rustfs/backlog#2684 registers it
//!
//! `docs/rustfs-profile.md` carries the same table with each switch's exit condition. "Unregistered"
//! means rustfs/backlog#2684 has no entry for the reading yet; the register has no item numbers,
//! so an entry is named by its heading.
//!
//! Builder half, `ServiceBuilder::rustfs_profile`:
//!
//! | Switch | Legacy RustFS behaviour kept | #2684 entry |
//! | --- | --- | --- |
//! | `accept_all_checksum_omissions` | no integrity claim required on any request body | "no checksum required on any operation" (R5) |
//! | `accept_empty_uploads_without_content_length` | an upload the transport ended empty without `Content-Length` is an empty object | "empty upload without Content-Length stored" |
//! | `accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report` | every key up to 1024 bytes reaches storage, which judges it | "paths, keys and addressing as legacy" (`key_floor.rs`) |
//! | `accept_minio_body_literals` | a bare `Enabled` body on a versioning or object-lock write | "bare `Enabled` body" (R6) |
//! | `accept_mismatched_payload_digests_without_a_body` | a bodyless request's signed digest is not compared | "bodyless signed digest unchecked" |
//! | `address_paths_as_legacy_rustfs` | the path decoded whole before the bucket split, `GET //` as `GET /` | "paths, keys and addressing as legacy" (`addressing.rs`, `legacy_addressing.rs`) |
//! | `answer_body_refusals_with_legacy_rustfs_sentences` | body refusals worded by code, in the API layer's fixed sentences | "digest and short-body failures use one wording" |
//! | `answer_checksum_failures_with_bad_digest` | every checksum failure is `BadDigest` | "checksum failures answer `BadDigest`" |
//! | `answer_cors_as_legacy_rustfs` | CORS answered in front of the stack, every `OPTIONS` before routing, no fallback origins | unregistered (rustfs/gateway#1120) |
//! | `answer_credential_refusals_with_legacy_rustfs_sentences` | the two credential refusals in RustFS's words | unregistered (rustfs/gateway#1120) |
//! | `answer_denials_with_legacy_rustfs_sentence` | every denial is `Access Denied` | unregistered (rustfs/gateway#1349) |
//! | `answer_head_refusals_without_content_length` | a refused `HEAD` carries no `Content-Length` | unregistered (rustfs/gateway#1120) |
//! | `answer_header_signatures_as_legacy_rustfs` | header-signature refusals before the credential lookup, naming the field | "signature verification as legacy" (GW-SIG, item 4) |
//! | `answer_heads_as_legacy_rustfs` | `HeadBucket` without a region, policy write `204`, restore `200`, policy read untyped | "response heads and statuses as legacy" |
//! | `answer_not_modified_with_legacy_rustfs_headers` | a `304` with the object's `ETag` and `Last-Modified` on `GET`, none on `HEAD` | "RustFS errors answered as legacy" |
//! | `answer_presigned_urls_as_legacy_rustfs` | presigned refusals before the credential lookup, naming the parameter | "signature verification as legacy" (GW-SIG, item 5) |
//! | `authorize_header_permissions_as_legacy_rustfs` | tagging and ACL headers ask the base permission only | unregistered (GHSA-3ppv-adjacent) |
//! | `authorize_versions_as_legacy_rustfs` | `HEAD`, tag and ACL reads of a version ask the unversioned action | unregistered (GHSA-3ppv) |
//! | `bound_buffered_bodies_as_legacy_rustfs` | buffered bodies read up to 20 MiB with no XML bound below it | unregistered (rustfs/gateway#1173) |
//! | `bound_claimed_route_bodies_as_legacy_rustfs` | a claimed route's body over 1 MiB refused before its access check | unregistered (rustfs/gateway#1173) |
//! | `clamp_oversized_max_keys` | `max-keys` above 1000 lowered, not refused | "`max-keys` above 1000 silently lowered" |
//! | `drain_unread_request_bodies` (300 s idle) | an unread HTTP/1 body drained behind the answer, then the connection closed | unregistered (rustfs/gateway#1120) |
//! | `identify_requests_as_legacy_rustfs` | one UUID in `x-amz-request-id` and `x-request-id`, no `x-amz-id-2` | unregistered (ruling R10) |
//! | `ignore_unknown_checksum_algorithms` | an unknown checksum algorithm header ignored | "unknown-algorithm checksum headers ignored" |
//! | `leave_anonymous_streaming_payloads_undecoded` | an anonymous aws-chunked upload refused, not decoded | "anonymous aws-chunked upload not decoded" |
//! | `leave_bodies_of_bodyless_operations_unread` | a body on a bodyless operation never polled | unregistered (rustfs/gateway#1173) |
//! | `legacy_rustfs_post_forms` | browser forms read with the legacy grammar | "POST forms parsed with the legacy grammar" (GW-FORM) |
//! | `read_aws_chunks_as_legacy_rustfs` | aws-chunked framing with no chunk-count or share bound | unregistered (rustfs/gateway#1173) |
//! | `read_checksum_declarations_as_legacy_rustfs` | a doubled `x-amz-checksum-algorithm` and a two-checksum trailer refused with RustFS's codes | unregistered (rustfs/gateway#1349) |
//! | `read_checksums_as_legacy_rustfs` | claims read as the storage reader reads them; the SDK algorithm header not read | "trailer algorithm ignores `x-amz-sdk-checksum-algorithm`" |
//! | `read_empty_headers_as_absent` | an empty optional header claims nothing | "empty request headers read as absent" |
//! | `read_request_documents_as_rustfs` | request documents refused by shape with `MalformedXML` | unregistered (rustfs/gateway#1078) |
//! | `refuse_plaintext_customer_keys_before_routing` | a customer key over cleartext refused before routing, copy source included | "SSE-C TLS gate" (R11) |
//! | `refuse_unreadable_date_conditions` | a conditional date in one spelling, the rest refused | "conditional dates read strictly" (R14) |
//! | `refuse_unsigned_amz_headers_before_routing` | a swapped algorithm token, an unreadable header or an unsigned `x-amz-*` refused before routing | "signature verification as legacy" (GW-SIG) |
//! | `refuse_unsized_buffered_bodies_as_legacy_rustfs` | a buffered write RustFS cannot size refused | unregistered (rustfs/gateway#1173) |
//! | `select_operations_as_legacy_rustfs` | `x-id` first, two operation keys ordered by RustFS's table | "paths, keys and addressing as legacy" (`route/legacy_rustfs.rs`) |
//! | `sign_base64_payload_digests_as_hex` | a base64 payload digest signed as its hex | "signature verification as legacy" (GW-SIG, item 3) |
//! | `sign_presigned_payloads_as_unsigned` | every presigned request signed over `UNSIGNED-PAYLOAD` | "presigned payload digest not covered by the signature" |
//! | `slash_policy(SlashPolicy::RustfsLegacy)` | leading slashes of a key folded | "paths, keys and addressing as legacy" (`slash.rs`) |
//! | `url_encode_listings_like_rustfs` | `encoding-type=url` echoed as sent, only some members encoded | "listing echoes `encoding-type`, encodes some members" |
//! | `write_responses_as_rustfs` | members in RustFS's order, no line end after the declaration, no namespace on a payload root | unregistered (rustfs/gateway#1078) |
//! | `framework_governor_rates` (every layer unlimited) | no pre-authentication limit on any layer | "failed signatures and anonymous requests unlimited" |
//! | floor: `delegate_anonymous_to_authorizer_after_listing_in_the_posture_report` | every request decided by policy, anonymous ones included | unregistered (ADR-0021) |
//! | floor: `enable_sigv2_presigned_compatibility` | SigV2 presigned URLs accepted | unregistered (rustfs/gateway#913) |
//! | floor: `with_presigned_expiry_rule(LegacyRustfs)` | `X-Amz-Expires` as a `u32` with `0`, SigV2 `Expires` without the seven-day ceiling | "`X-Amz-Expires` spellings, SigV2 links to 9999" |
//! | floor: `admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report` | a presigned URL on every standard operation, never on a privileged one | unregistered (rustfs/gateway#1052) |
//! | floor: `recognize_signatures_as_legacy_rustfs` | a query or form is signed only when it carries the signature | "signature verification as legacy" (GW-SIG, item 9) |
//!
//! Authenticator half, `SigV4Authenticator::rustfs_profile`:
//!
//! | Switch | Legacy RustFS behaviour kept | #2684 entry |
//! | --- | --- | --- |
//! | `accept_any_signing_region` | any region of the grammar verified | unregistered (ADR-0023) |
//! | `accept_empty_signing_region` | an empty scope region verified | "empty signing region verified" |
//! | `refuse_unreadable_signing_regions_after_verification` | a region outside the grammar refused after the signature, `InvalidRequest` | "region outside the grammar verified, then refused" |
//! | `accept_signing_regions_of_any_length` | no ceiling on the region's length | "no region length ceiling" |
//! | `verify_paths_as_legacy_rustfs` | the path decoded once for signing, malformed percent literal, the raw candidate by the native rule | unregistered (rustfs/gateway#1314, #1315) |
//! | `accept_legacy_rustfs_signing_services` | `s3`, `sts` and `s3tables` verified on every operation, others `501` | "signature verification as legacy" (GW-SIG, items 1–2) |
//! | `answer_credential_scope_refusals_as_legacy_rustfs` | a scope date or region refusal in RustFS's code and words | "signature verification as legacy" (GW-SIG, item 6) |
//! | `read_signed_headers_as_legacy_rustfs` | `SignedHeaders` read verbatim, refusals in RustFS's words | "signature verification as legacy" (GW-SIG, items 7–8) |
//!
//! # Why one method and not a configuration file
//!
//! A re-pin of the gateway changes what the profile does only through this file and the modules
//! it names: the diff of a re-pin is the diff of the preset, and the posture golden
//! (`tests/golden/rustfs-profile-posture.txt`) goes red when the assembled result moves. A switch
//! the launcher chained by hand and the bridge forgot was the failure this replaces
//! (rustfs/backlog#2734).

use std::collections::BTreeSet;
use std::time::Duration;

use rustfs_gateway_sig::PresignedExpiryRule;
use rustfs_gateway_types::{KeyFloor, PathSplit, SlashPolicy};

use super::ServiceBuilder;
use crate::ext::{GovernorRates, Rate, SigV4Authenticator};
use crate::{LegacyRustfsCors, UnreadBodyDrain};

/// How long the RustFS profile waits for an unread HTTP/1 body behind an early answer: legacy
/// RustFS's body idle timeout, 300 seconds (rustfs/rustfs#7019).
const UNREAD_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// The framework governor's rates in the RustFS profile: no limit on any layer.
///
/// Legacy RustFS applies no pre-authentication limit of its own. Its optional per-client limit
/// (`RUSTFS_API_RATE_LIMIT_*`, off by default) is a host layer in front of both stacks, so the
/// framework's layers must not refuse anything legacy RustFS answers (rustfs/gateway#1067): every
/// layer is lifted with [`Rate::unlimited`], which admits without counting, keeps no address entry,
/// and is named in the start-up posture. The address table keeps its shipped bound; it is memory,
/// not a rate, and an unlimited per-client layer never fills it.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS verifies every signature it is sent, with no
/// bound on how many failed verifications or credential lookups one caller can force, and serves
/// anonymous requests with no pre-authentication bound either. That leaves forged-signature floods
/// limited only by CPU. The intended behaviour is a bounded `credential_lookup` class (a verified
/// request already returns its charge, so the bound would only count failed and in-flight work)
/// with its refill above `per_ip`'s, taken from RustFS configuration.
fn rustfs_governor_rates() -> GovernorRates {
    let unlimited = Rate::unlimited();
    GovernorRates {
        aggregate: unlimited,
        per_ip: unlimited,
        credential_lookup: unlimited,
        cors_preflight: unlimited,
        unauthenticated: unlimited,
        tracked_clients: GovernorRates::default().tracked_clients,
    }
}

impl ServiceBuilder {
    /// Applies the RustFS profile: every legacy RustFS reading the module table names, onto the
    /// security floor and the governor rates this builder already holds, and nothing the host owns.
    ///
    /// Idempotent. A floor set before it keeps its skew window and custom schemes. The three
    /// readings that carry a value are written by the preset with RustFS's defaults — no fallback
    /// CORS origins, a 300-second unread-body drain, every governor layer unlimited — so a host
    /// that wants its own writes them after it, through
    /// [`ServiceBuilder::answer_cors_as_legacy_rustfs`],
    /// [`ServiceBuilder::drain_unread_request_bodies`] and
    /// [`ServiceBuilder::framework_governor_rates`]; one written before it is replaced. The
    /// credentials go through [`SigV4Authenticator::rustfs_profile`], the other half of the same
    /// preset, since an authenticator is the host's instance.
    ///
    /// The start-up `PROFILE_POSTURE` line names every builder-held reading this turned on, read
    /// back from the assembled state; `SECURITY_POSTURE`, `PRESIGNED_EXPIRY_POSTURE` and
    /// `NAMING_POSTURE` name the floor, the lifetime rule and the naming readings as before.
    #[must_use]
    pub fn rustfs_profile(mut self) -> Self {
        // Onto the floor the host set, not over it: the five legacy readings, with the host's skew
        // window and custom schemes left alone.
        let floor = core::mem::take(&mut self.floor);
        self.floor = floor
            // An anonymous request reaches the authorizer instead of being refused per operation
            // (ADR-0021): RustFS decides every request by policy, and a public bucket policy is how a
            // suite grants the public a read. RustFS also accepts SigV2 presigned URLs (#913).
            .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
            .enable_sigv2_presigned_compatibility()
            // RustFS reads a presigned lifetime its own way: `X-Amz-Expires` as a Rust `u32` with
            // `0` allowed, SigV2 `Expires` with no seven-day ceiling (rustfs/rustfs#5368).
            .with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs)
            // RustFS verifies a presigned URL on every standard operation and authorizes it as it
            // authorizes a header signature (rustfs/gateway#1052).
            .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
            // And it reads a query string or a form as signed only when it carries the signature;
            // the rest is anonymous (rustfs/gateway#1130).
            .recognize_signatures_as_legacy_rustfs();
        self.framework_governor_rates(rustfs_governor_rates())
            // RustFS requires an integrity claim on no request body (rustfs/backlog#1677, R5); a
            // claim that is sent is still compared.
            .accept_all_checksum_omissions()
            // RustFS lowers an oversized `max-keys` to a thousand rather than refusing it.
            .clamp_oversized_max_keys()
            // RustFS encodes a listing under `encoding-type=url` its own way (rustfs/gateway#1059).
            .url_encode_listings_like_rustfs()
            // RustFS's transport gate refuses the target's and the copy source's customer key over
            // cleartext before routing, in its own words (rustfs/gateway#1349); whether TLS is
            // required at all is the host's `sse_config`.
            .refuse_plaintext_customer_keys_before_routing()
            // RustFS refuses an anonymous aws-chunked upload rather than decoding it (#1060).
            .leave_anonymous_streaming_payloads_undecoded()
            // RustFS signs every presigned request over `UNSIGNED-PAYLOAD` (rustfs/rustfs#2379),
            // and a base64 header-signed digest as its hex (rustfs/gateway#1130).
            .sign_presigned_payloads_as_unsigned()
            .sign_base64_payload_digests_as_hex()
            // RustFS refuses a header signature, and a presigned URL, before its credential lookup
            // in its own order and words (rustfs/gateway#1130).
            .answer_header_signatures_as_legacy_rustfs()
            .answer_presigned_urls_as_legacy_rustfs()
            // RustFS answers an unreadable or mismatched request checksum with `BadDigest`
            // (rustfs/gateway#1057), a refused HEAD with no Content-Length, and a `304` with its
            // object's headers on a `GET` only (rustfs/gateway#1120).
            .answer_checksum_failures_with_bad_digest()
            .answer_head_refusals_without_content_length()
            .answer_not_modified_with_legacy_rustfs_headers()
            // RustFS ignores a checksum header naming an algorithm it does not know, and reads
            // checksum declarations as its storage reader does (rustfs/gateway#1349).
            .ignore_unknown_checksum_algorithms()
            .read_checksums_as_legacy_rustfs()
            // RustFS reads a request document against its shape, `MalformedXML` otherwise
            // (rustfs/gateway#1078).
            .read_request_documents_as_rustfs()
            // RustFS never compares the signed digest of a bodyless request, nor reads the body it
            // carries (rustfs/gateway#1099, #1173); and refuses a buffered write it cannot size.
            .accept_mismatched_payload_digests_without_a_body()
            .leave_bodies_of_bodyless_operations_unread()
            .refuse_unsized_buffered_bodies_as_legacy_rustfs()
            // RustFS decodes aws-chunked framing with no bound on chunk count or share, bounds a
            // claimed route's body at 1 MiB, and buffers every body it decodes up to 20 MiB
            // (rustfs/gateway#1173).
            .read_aws_chunks_as_legacy_rustfs()
            .bound_claimed_route_bodies_as_legacy_rustfs()
            .bound_buffered_bodies_as_legacy_rustfs()
            // RustFS, built with MinIO support, reads a bare `Enabled` body (rustfs/backlog#1677, R6).
            .accept_minio_body_literals()
            // RustFS refuses a swapped SigV4 algorithm token, an unreadable SigV4 header and an
            // unsigned `x-amz-*` header before it routes (GHSA-xm99, GHSA-g8w9; rustfs/gateway#1120).
            .refuse_unsigned_amz_headers_before_routing()
            // RustFS words body refusals, its two credential refusals and every denial itself
            // (rustfs/gateway#1099, #1120, #1349).
            .answer_body_refusals_with_legacy_rustfs_sentences()
            .answer_credential_refusals_with_legacy_rustfs_sentences()
            .answer_denials_with_legacy_rustfs_sentence()
            // RustFS folds the slashes of a key only when the key starts with one (#1101).
            .slash_policy(SlashPolicy::RustfsLegacy)
            // RustFS stores an upload the transport ended empty without `Content-Length` as an
            // empty object (rustfs/rustfs#6849).
            .accept_empty_uploads_without_content_length()
            // RustFS reads a conditional date in one spelling and refuses the rest
            // (rustfs/backlog#1677, R14).
            .refuse_unreadable_date_conditions()
            // RustFS refuses an `x-amz-checksum-algorithm` sent twice and an `x-amz-trailer` naming
            // two checksums with its own codes (rustfs/gateway#1349).
            .read_checksum_declarations_as_legacy_rustfs()
            // RustFS writes a response document in its own layout (rustfs/gateway#1078).
            .write_responses_as_rustfs()
            // RustFS reads an HTTP/1 body its answer left unread and closes the connection behind
            // it, bounded by its 300-second body idle timeout (rustfs/rustfs#7019).
            .drain_unread_request_bodies(UnreadBodyDrain::with_idle_timeout(UNREAD_BODY_IDLE_TIMEOUT))
            // RustFS's protocol front hands its storage every key up to 1024 bytes (#1107), decodes
            // the whole path before it splits the bucket (#1115), and takes an `x-id` as the
            // operation (#1127).
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
            .address_paths_as_legacy_rustfs()
            .select_operations_as_legacy_rustfs()
            // RustFS answers CORS itself, in a layer in front of its S3 stack, with no
            // `RUSTFS_CORS_ALLOWED_ORIGINS` fallback as it runs by default (rustfs/gateway#1120).
            .answer_cors_as_legacy_rustfs(LegacyRustfsCors::with_fallback_origins(None))
            // RustFS reads a browser upload form with its legacy grammar (rustfs/backlog#1677, R8).
            .legacy_rustfs_post_forms()
            // RustFS answers a policy write `204`, every restore `200`, a policy read untyped, and a
            // HeadBucket without a region its handler left unnamed (rustfs/gateway#1148).
            .answer_heads_as_legacy_rustfs()
            // RustFS reads an optional header whose one line is empty as absent (rustfs/gateway#1087).
            .read_empty_headers_as_absent()
            // RustFS names an answer's request with one UUID in `x-amz-request-id` and
            // `x-request-id`, writes no `x-amz-id-2` (ruling R10).
            .identify_requests_as_legacy_rustfs()
            // RustFS asks a `HEAD`, tag or ACL request naming a version its unversioned action, and
            // the base `s3:PutObject` alone for a tagging or ACL header (GHSA-3ppv).
            .authorize_versions_as_legacy_rustfs()
            .authorize_header_permissions_as_legacy_rustfs()
    }

    /// Every legacy RustFS reading this builder would assemble, named by the method that turns it
    /// on, read from the builder's state.
    ///
    /// The operation-selection reading lives in the router and is named by `crate::startup_report`
    /// once the router is built; everything else is here.
    pub(crate) fn legacy_switches(&self) -> BTreeSet<&'static str> {
        let mut switches = BTreeSet::new();
        self.view_policy.legacy_switches(&mut switches);
        let held_by_the_builder = [
            (!self.decode_anonymous_framing, "leave_anonymous_streaming_payloads_undecoded"),
            (self.legacy_cors.is_some(), "answer_cors_as_legacy_rustfs"),
            (
                self.names.key_floor() == KeyFloor::RustfsLegacy,
                "accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report",
            ),
            (self.names.path_split() == PathSplit::RustfsLegacy, "address_paths_as_legacy_rustfs"),
            (self.names.slash_policy() == SlashPolicy::RustfsLegacy, "slash_policy"),
        ];
        switches.extend(held_by_the_builder.into_iter().filter_map(|(on, name)| on.then_some(name)));
        switches
    }
}

impl SigV4Authenticator {
    /// Applies the authenticator half of the RustFS profile: every legacy RustFS reading of a
    /// credential scope, a signed path and `SignedHeaders` the module table names, onto an
    /// authenticator the host built over its own credentials and regions.
    ///
    /// Idempotent. [`ServiceBuilder::rustfs_profile`] is the other half; neither applies the other.
    #[must_use]
    pub fn rustfs_profile(self) -> Self {
        self
            // RustFS verifies a signature whatever region its scope names, an empty one included
            // (its replication client signs with one): ADR-0023's any-region grammar plus the empty
            // region, rustfs/backlog#1677; it refuses a region outside its grammar only after the
            // signature, with `InvalidRequest` (rustfs/gateway#1075); at any length.
            .accept_any_signing_region()
            .accept_empty_signing_region()
            .refuse_unreadable_signing_regions_after_verification()
            .accept_signing_regions_of_any_length()
            // Path escapes decode once for signing, malformed percent stays literal, and the raw
            // candidate follows the native rule (#1314, #1315).
            .verify_paths_as_legacy_rustfs()
            // It verifies an `s3`, `sts` or `s3tables` scope on every operation, answers any other
            // service with its `501`, and words a scope date or region refusal itself
            // (rustfs/gateway#1130).
            .accept_legacy_rustfs_signing_services()
            .answer_credential_scope_refusals_as_legacy_rustfs()
            // It reads `SignedHeaders` verbatim, and answers a list that does not cover what it
            // must in its own words (rustfs/gateway#1130).
            .read_signed_headers_as_legacy_rustfs()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rustfs_gateway_sig::{PresignedExpiryRule, RegionSet, SecurityFloor, SkewWindow};
    use rustfs_gateway_types::SlashPolicy;

    use super::ServiceBuilder;
    use crate::{Credentials, GovernorRates, LegacyRustfsCors, SigV4Authenticator, StaticCredentials, UnreadBodyDrain};

    type Switch = fn(ServiceBuilder) -> ServiceBuilder;

    /// Every builder-held legacy reading, by the method that turns it on. The router-held one,
    /// `select_operations_as_legacy_rustfs`, is observed on an assembled service instead
    /// (`tests/rustfs_profile.rs`).
    const SWITCHES: &[(&str, Switch)] = &[
        ("accept_all_checksum_omissions", ServiceBuilder::accept_all_checksum_omissions),
        (
            "accept_empty_uploads_without_content_length",
            ServiceBuilder::accept_empty_uploads_without_content_length,
        ),
        (
            "accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report",
            ServiceBuilder::accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report,
        ),
        ("accept_minio_body_literals", ServiceBuilder::accept_minio_body_literals),
        (
            "accept_mismatched_payload_digests_without_a_body",
            ServiceBuilder::accept_mismatched_payload_digests_without_a_body,
        ),
        ("address_paths_as_legacy_rustfs", ServiceBuilder::address_paths_as_legacy_rustfs),
        (
            "answer_body_refusals_with_legacy_rustfs_sentences",
            ServiceBuilder::answer_body_refusals_with_legacy_rustfs_sentences,
        ),
        (
            "answer_checksum_failures_with_bad_digest",
            ServiceBuilder::answer_checksum_failures_with_bad_digest,
        ),
        ("answer_cors_as_legacy_rustfs", |builder| {
            builder.answer_cors_as_legacy_rustfs(LegacyRustfsCors::with_fallback_origins(None))
        }),
        (
            "answer_credential_refusals_with_legacy_rustfs_sentences",
            ServiceBuilder::answer_credential_refusals_with_legacy_rustfs_sentences,
        ),
        (
            "answer_denials_with_legacy_rustfs_sentence",
            ServiceBuilder::answer_denials_with_legacy_rustfs_sentence,
        ),
        (
            "answer_head_refusals_without_content_length",
            ServiceBuilder::answer_head_refusals_without_content_length,
        ),
        (
            "answer_header_signatures_as_legacy_rustfs",
            ServiceBuilder::answer_header_signatures_as_legacy_rustfs,
        ),
        ("answer_heads_as_legacy_rustfs", ServiceBuilder::answer_heads_as_legacy_rustfs),
        (
            "answer_not_modified_with_legacy_rustfs_headers",
            ServiceBuilder::answer_not_modified_with_legacy_rustfs_headers,
        ),
        (
            "answer_presigned_urls_as_legacy_rustfs",
            ServiceBuilder::answer_presigned_urls_as_legacy_rustfs,
        ),
        (
            "authorize_header_permissions_as_legacy_rustfs",
            ServiceBuilder::authorize_header_permissions_as_legacy_rustfs,
        ),
        ("authorize_versions_as_legacy_rustfs", ServiceBuilder::authorize_versions_as_legacy_rustfs),
        (
            "bound_buffered_bodies_as_legacy_rustfs",
            ServiceBuilder::bound_buffered_bodies_as_legacy_rustfs,
        ),
        (
            "bound_claimed_route_bodies_as_legacy_rustfs",
            ServiceBuilder::bound_claimed_route_bodies_as_legacy_rustfs,
        ),
        ("clamp_oversized_max_keys", ServiceBuilder::clamp_oversized_max_keys),
        ("drain_unread_request_bodies", |builder| {
            builder.drain_unread_request_bodies(UnreadBodyDrain::with_idle_timeout(Duration::from_secs(300)))
        }),
        ("identify_requests_as_legacy_rustfs", ServiceBuilder::identify_requests_as_legacy_rustfs),
        ("ignore_unknown_checksum_algorithms", ServiceBuilder::ignore_unknown_checksum_algorithms),
        (
            "leave_anonymous_streaming_payloads_undecoded",
            ServiceBuilder::leave_anonymous_streaming_payloads_undecoded,
        ),
        (
            "leave_bodies_of_bodyless_operations_unread",
            ServiceBuilder::leave_bodies_of_bodyless_operations_unread,
        ),
        ("legacy_rustfs_post_forms", ServiceBuilder::legacy_rustfs_post_forms),
        ("read_aws_chunks_as_legacy_rustfs", ServiceBuilder::read_aws_chunks_as_legacy_rustfs),
        (
            "read_checksum_declarations_as_legacy_rustfs",
            ServiceBuilder::read_checksum_declarations_as_legacy_rustfs,
        ),
        ("read_checksums_as_legacy_rustfs", ServiceBuilder::read_checksums_as_legacy_rustfs),
        ("read_empty_headers_as_absent", ServiceBuilder::read_empty_headers_as_absent),
        ("read_request_documents_as_rustfs", ServiceBuilder::read_request_documents_as_rustfs),
        (
            "refuse_plaintext_customer_keys_before_routing",
            ServiceBuilder::refuse_plaintext_customer_keys_before_routing,
        ),
        ("refuse_unreadable_date_conditions", ServiceBuilder::refuse_unreadable_date_conditions),
        (
            "refuse_unsigned_amz_headers_before_routing",
            ServiceBuilder::refuse_unsigned_amz_headers_before_routing,
        ),
        (
            "refuse_unsized_buffered_bodies_as_legacy_rustfs",
            ServiceBuilder::refuse_unsized_buffered_bodies_as_legacy_rustfs,
        ),
        ("sign_base64_payload_digests_as_hex", ServiceBuilder::sign_base64_payload_digests_as_hex),
        ("sign_presigned_payloads_as_unsigned", ServiceBuilder::sign_presigned_payloads_as_unsigned),
        ("slash_policy", |builder| builder.slash_policy(SlashPolicy::RustfsLegacy)),
        ("url_encode_listings_like_rustfs", ServiceBuilder::url_encode_listings_like_rustfs),
        ("write_responses_as_rustfs", ServiceBuilder::write_responses_as_rustfs),
    ];

    /// Negative — a builder nobody touched runs no legacy reading, and the census says so.
    #[test]
    fn n_a_default_builder_names_no_legacy_reading() {
        assert!(ServiceBuilder::new().legacy_switches().is_empty());
    }

    /// Each switch alone is named by itself and by nothing else: the census reads every field, and
    /// no two switches are read from the same field.
    #[test]
    fn each_switch_alone_is_named_by_itself_and_by_nothing_else() {
        for (name, switch) in SWITCHES {
            let named: Vec<&'static str> = switch(ServiceBuilder::new()).legacy_switches().into_iter().collect();
            assert_eq!(named, vec![*name], "{name}");
        }
    }

    /// Negative — a non-legacy value of the one valued switch is not a legacy reading: the AWS
    /// slash rule and the collapsing one both leave the census empty.
    #[test]
    fn n_another_slash_policy_is_not_the_legacy_reading() {
        for slash in [SlashPolicy::AwsPreserve, SlashPolicy::Collapse] {
            assert!(ServiceBuilder::new().slash_policy(slash).legacy_switches().is_empty(), "{slash:?}");
        }
    }

    // ── the preset ─────────────────────────────────────────────────────────────────────────────

    /// The preset turns on exactly the documented builder-held readings — every entry of
    /// [`SWITCHES`], and nothing the table does not name.
    #[test]
    fn the_preset_turns_on_exactly_the_documented_switches() {
        let expected: Vec<&'static str> = SWITCHES.iter().map(|(name, _)| *name).collect();
        let named: Vec<&'static str> = ServiceBuilder::new().rustfs_profile().legacy_switches().into_iter().collect();
        assert_eq!(named, expected);
    }

    /// The floor the preset leaves is the explicit five-switch chain, applied onto the floor the
    /// deployment set before it: a narrowed skew window survives the preset.
    #[test]
    fn the_preset_applies_the_floor_switches_onto_the_floor_it_was_given() {
        let skew = SkewWindow::new(Duration::from_secs(30), Duration::from_secs(30));
        let explicit = SecurityFloor::new()
            .with_skew_window(skew)
            .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
            .enable_sigv2_presigned_compatibility()
            .with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs)
            .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
            .recognize_signatures_as_legacy_rustfs();
        let preset = ServiceBuilder::new()
            .security_floor(SecurityFloor::new().with_skew_window(skew))
            .rustfs_profile();
        assert_eq!(format!("{:?}", preset.floor), format!("{explicit:?}"));
        // Negative — the default floor reads differently on every one of the five switches.
        assert_ne!(
            format!("{:?}", preset.floor),
            format!("{:?}", SecurityFloor::new().with_skew_window(skew))
        );
    }

    /// Negative — every framework governor layer is lifted, not sized, and the address table keeps
    /// its shipped bound: it is memory, not a rate.
    #[test]
    fn n_the_preset_lifts_every_framework_governor_layer_and_keeps_the_address_table() {
        let rates = ServiceBuilder::new().rustfs_profile().governor_rates;
        for rate in [
            rates.aggregate,
            rates.per_ip,
            rates.credential_lookup,
            rates.cors_preflight,
            rates.unauthenticated,
        ] {
            assert!(rate.admits_everything(), "{rate:?}");
        }
        assert_eq!(rates.tracked_clients, GovernorRates::default().tracked_clients);
    }

    fn authenticator() -> SigV4Authenticator {
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid key id")));
        SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"))
    }

    /// The authenticator preset is the explicit eight-switch chain, switch for switch, and differs
    /// from the untouched authenticator on every one of them.
    #[test]
    fn the_authenticator_preset_is_the_explicit_chain() {
        let explicit = authenticator()
            .accept_any_signing_region()
            .accept_empty_signing_region()
            .refuse_unreadable_signing_regions_after_verification()
            .accept_signing_regions_of_any_length()
            .verify_paths_as_legacy_rustfs()
            .accept_legacy_rustfs_signing_services()
            .answer_credential_scope_refusals_as_legacy_rustfs()
            .read_signed_headers_as_legacy_rustfs();
        let preset = authenticator().rustfs_profile();
        assert_eq!(format!("{preset:?}"), format!("{explicit:?}"));
        let untouched = format!("{:?}", authenticator());
        assert_ne!(format!("{preset:?}"), untouched);
        for switch in [
            "accepts_any_signing_region: true",
            "accepts_empty_signing_region: true",
            "verifies_unreadable_signing_regions: true",
            "reads_signing_regions_of_any_length: true",
            "accepts_legacy_rustfs_signing_services: true",
            "answers_scope_refusals_as_legacy_rustfs: true",
            "verifies_paths_as_legacy_rustfs: true",
            "reads_signed_headers_as_legacy_rustfs: true",
        ] {
            assert!(format!("{preset:?}").contains(switch), "{switch}: {preset:?}");
            assert!(!untouched.contains(switch), "{switch}: {untouched}");
        }
    }

    /// Applying the preset twice is applying it once: no switch toggles, nothing accumulates.
    #[test]
    fn the_preset_is_idempotent() {
        let once = ServiceBuilder::new().rustfs_profile();
        let twice = ServiceBuilder::new().rustfs_profile().rustfs_profile();
        assert_eq!(once.legacy_switches(), twice.legacy_switches());
        assert_eq!(format!("{:?}", once.floor), format!("{:?}", twice.floor));
        assert_eq!(once.governor_rates, twice.governor_rates);
    }
}
