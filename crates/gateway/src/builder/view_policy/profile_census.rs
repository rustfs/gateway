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

//! The census of the legacy RustFS readings a [`ViewPolicy`] holds, for the `PROFILE_POSTURE`
//! start-up line (rustfs/backlog#2751).
//!
//! Responsible for: naming each reading the policy's state selects, by the `ServiceBuilder` method
//! that turns it on — read from the fields, so a switch the preset forgot and a switch set by hand
//! are reported the same way.
//! NOT responsible for: the readings the builder holds outside the policy (`super::super::rustfs_profile`),
//! the router's operation selection (`crate::startup_report`), or rendering the line
//! (`crate::profile_posture`).
//! Upstream: `super::ViewPolicy`. Downstream: `super::super::rustfs_profile`.

use std::collections::BTreeSet;

use rustfs_gateway_core::DocumentReading;

use super::ViewPolicy;
use super::header_signatures::HeaderRefusals;
use super::presigned_urls::PresignedRefusals;
use crate::builder::bodyless_bodies::BodylessBodies;
use crate::builder::bodyless_digest::BodylessDigest;
use crate::builder::buffered_ceiling::BufferedCeiling;
use crate::builder::buffered_lengths::BufferedLengths;
use crate::builder::claimed_bodies::ClaimedBodies;
use crate::builder::credential_sentences::CredentialSentences;
use crate::builder::denial_sentences::DenialSentences;
use crate::builder::legacy_chunks::ChunkReading;
use crate::builder::legacy_heads::AnswerHeads;
use crate::builder::legacy_sentences::BodySentences;
use crate::builder::not_modified_headers::NotModifiedHeaders;
use crate::builder::plaintext_customer_keys::PlaintextCustomerKeys;
use crate::builder::sigv4_header_guard::SigV4HeaderGuard;
use crate::builder::version_actions::VersionActions;
use crate::integrity::IntegrityCodes;
use crate::trace::Identification;

impl ViewPolicy {
    /// Adds the name of every legacy reading this policy's state selects to `into`.
    pub(crate) fn legacy_switches(&self, into: &mut BTreeSet<&'static str>) {
        let readings: [(bool, &'static str); 36] = [
            (self.checksum_waiver.waives_every_operation(), "accept_all_checksum_omissions"),
            (self.empty_uploads_without_length, "accept_empty_uploads_without_content_length"),
            (self.body_literals, "accept_minio_body_literals"),
            (
                self.bodyless_digest == BodylessDigest::Ignored,
                "accept_mismatched_payload_digests_without_a_body",
            ),
            (
                self.body_sentences == BodySentences::LegacyRustfs,
                "answer_body_refusals_with_legacy_rustfs_sentences",
            ),
            (self.integrity_codes == IntegrityCodes::RustFs, "answer_checksum_failures_with_bad_digest"),
            (
                self.credential_sentences == CredentialSentences::LegacyRustfs,
                "answer_credential_refusals_with_legacy_rustfs_sentences",
            ),
            (
                self.denial_sentences == DenialSentences::LegacyRustfs,
                "answer_denials_with_legacy_rustfs_sentence",
            ),
            (self.head_refusals_without_length, "answer_head_refusals_without_content_length"),
            (
                self.header_signatures == HeaderRefusals::LegacyRustfs,
                "answer_header_signatures_as_legacy_rustfs",
            ),
            (self.answer_heads == AnswerHeads::LegacyRustfs, "answer_heads_as_legacy_rustfs"),
            (
                self.not_modified_headers == NotModifiedHeaders::LegacyRustfs,
                "answer_not_modified_with_legacy_rustfs_headers",
            ),
            (
                self.presigned_urls == PresignedRefusals::LegacyRustfs,
                "answer_presigned_urls_as_legacy_rustfs",
            ),
            (self.waive_rustfs_header_permissions, "authorize_header_permissions_as_legacy_rustfs"),
            (
                self.version_actions == VersionActions::LegacyRustfs,
                "authorize_versions_as_legacy_rustfs",
            ),
            (
                self.buffered_ceiling == BufferedCeiling::LegacyRustfs,
                "bound_buffered_bodies_as_legacy_rustfs",
            ),
            (
                self.claimed_bodies == ClaimedBodies::LegacyRustfs,
                "bound_claimed_route_bodies_as_legacy_rustfs",
            ),
            (self.clamp_max_keys, "clamp_oversized_max_keys"),
            (self.unread_body_drain.is_some(), "drain_unread_request_bodies"),
            (self.identification == Identification::LegacyRustfs, "identify_requests_as_legacy_rustfs"),
            (self.unknown_checksum_algorithms_ignored, "ignore_unknown_checksum_algorithms"),
            (
                self.bodyless_bodies == BodylessBodies::Unread,
                "leave_bodies_of_bodyless_operations_unread",
            ),
            (self.post_forms.is_legacy_rustfs(), "legacy_rustfs_post_forms"),
            (self.chunk_reading == ChunkReading::LegacyRustfs, "read_aws_chunks_as_legacy_rustfs"),
            (self.legacy_checksum_declarations, "read_checksum_declarations_as_legacy_rustfs"),
            (self.legacy_checksums, "read_checksums_as_legacy_rustfs"),
            (self.empty_headers_absent, "read_empty_headers_as_absent"),
            (self.document_reading == DocumentReading::RustFs, "read_request_documents_as_rustfs"),
            (
                self.plaintext_customer_keys == PlaintextCustomerKeys::BeforeRouting,
                "refuse_plaintext_customer_keys_before_routing",
            ),
            (self.strict_date_conditions, "refuse_unreadable_date_conditions"),
            (
                self.sigv4_header_guard == SigV4HeaderGuard::LegacyRustfs,
                "refuse_unsigned_amz_headers_before_routing",
            ),
            (
                self.buffered_lengths == BufferedLengths::LegacyRustfs,
                "refuse_unsized_buffered_bodies_as_legacy_rustfs",
            ),
            (self.base64_digests_as_hex, "sign_base64_payload_digests_as_hex"),
            (self.presigned_payload_unsigned, "sign_presigned_payloads_as_unsigned"),
            (self.rustfs_listings, "url_encode_listings_like_rustfs"),
            (self.rustfs_response_layout, "write_responses_as_rustfs"),
        ];
        into.extend(readings.into_iter().filter_map(|(on, name)| on.then_some(name)));
    }
}
