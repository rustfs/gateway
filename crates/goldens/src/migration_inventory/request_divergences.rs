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

//! Decided request divergences: every behaviour the rustfs/backlog#1762 differential pins between
//! the gateway and the pinned s3s (the stack RustFS serves today), each with its migration ruling.
//!
//! Responsible for: one entry per pinned divergence — what AWS documents, what s3s does, what the
//! gateway does, what a RustFS client would notice, the ruling, and the issue that owns any code
//! follow-up — and for refusing a register that has drifted from its tests. Every entry names a
//! test that carries its id, and every test in a named-divergence section carries an id that has an
//! entry, so a divergence cannot be pinned without a ruling or ruled without a pin.
//! NOT responsible for: observing the divergences (the named tests in `operation_diff` drive both
//! stacks), persisted-byte refusals (the parent module), or implementing a follow-up.
//! Upstream: the named tests in `operation_diff/put_object/divergences.rs`,
//! `operation_diff/context/put_object.rs`, `operation_diff/context/get_bucket_location.rs`,
//! `operation_diff/put_bucket_versioning.rs`, `operation_diff/context/error_parity/divergences.rs`
//! and `operation_diff/context/body_parity/divergences.rs`.
//! Downstream: `corpus-report`, and the RustFS adapter work
//! of rustfs/backlog#1752.
//!
//! # The default the rulings follow
//!
//! A refusal that exists for safety stays (`..` segments, two integrity claims). A behaviour RustFS
//! clients observably depend on is aligned, or given a RustFS profile when the AWS answer should
//! stay the default for everyone else. Where AWS and s3s disagree and no RustFS client depends on
//! the difference, the gateway's AWS-derived answer stands.

use core::fmt;

/// What the migration does about one divergence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceRuling {
    /// The gateway's answer stands for every deployment.
    KeepGateway,
    /// The gateway, or the RustFS adapter in front of the RustFS handlers, gives the answer RustFS
    /// gives today.
    AlignS3s,
    /// The gateway moves to what AWS documents.
    AlignAws,
    /// The AWS answer stays the default; a RustFS dialect profile gives RustFS's answer.
    RustfsProfile,
}

impl DivergenceRuling {
    /// Every ruling, in report order.
    pub const ALL: [Self; 4] = [Self::KeepGateway, Self::AlignS3s, Self::AlignAws, Self::RustfsProfile];

    /// Stable report label.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::KeepGateway => "keep-gateway",
            Self::AlignS3s => "align-s3s",
            Self::AlignAws => "align-aws",
            Self::RustfsProfile => "rustfs-profile",
        }
    }
}

/// Where the code a ruling needs stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceFollowUp {
    /// The ruling needs no code.
    None,
    /// The code landed; this conformance case and the pinned test hold it.
    Landed(&'static str),
    /// The code is owned by this open issue.
    Open(&'static str),
}

/// One pinned divergence and its ruling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestDivergence {
    /// Stable id, `rd-<put|ctx|loc|cfg|err|body>-NNNN` — the PutObject decode, a request context, the
    /// GetBucketLocation context, a bucket configuration write, or an error document; the pinned
    /// test's doc carries it as `Ruling: `id``.
    pub id: &'static str,
    /// Operation the request addresses.
    pub operation: &'static str,
    /// The request shape that diverges.
    pub request: &'static str,
    /// What AWS documents for it.
    pub aws: &'static str,
    /// Where AWS (or the RFC S3 follows) says so.
    pub aws_evidence: &'static str,
    /// What the pinned s3s — RustFS today — does.
    pub s3s: &'static str,
    /// What the gateway does.
    pub gateway: &'static str,
    /// What a RustFS client would notice if the gateway answer shipped unchanged.
    pub client_impact: &'static str,
    /// The decision.
    pub ruling: DivergenceRuling,
    /// Where the code the decision needs stands.
    pub follow_up: DivergenceFollowUp,
    /// Pinned test source, relative to `crates/goldens/src`.
    pub test_file: &'static str,
    /// Pinned test function.
    pub test: &'static str,
}

const PUT_DECODE: &str = "operation_diff/put_object/divergences.rs";
const PUT_CONTEXT: &str = "operation_diff/context/put_object.rs";
const LOCATION_CONTEXT: &str = "operation_diff/context/get_bucket_location.rs";
const CONFIG_DECODE: &str = "operation_diff/put_bucket_versioning.rs";
const ERROR_PARITY: &str = "operation_diff/context/error_parity/divergences.rs";
const BODY_PARITY: &str = "operation_diff/context/body_parity/divergences.rs";

/// The files whose named-divergence sections the register is checked against.
const PINNED_TEST_FILES: [&str; 6] = [
    PUT_DECODE,
    PUT_CONTEXT,
    LOCATION_CONTEXT,
    CONFIG_DECODE,
    ERROR_PARITY,
    BODY_PARITY,
];

const API_PUT_OBJECT: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html";
const API_GET_BUCKET_LOCATION: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html";
const ERROR_RESPONSES: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html";
const M1_ADAPTER: &str = "https://github.com/rustfs/backlog/issues/1752";

/// Every decided request divergence.
const OPERATION_DIVERGENCES: [RequestDivergence; 20] = [
    RequestDivergence {
        id: "rd-put-0001",
        operation: "PutObject",
        request: "no Content-Type header",
        aws: "the object is stored with the S3 default media type, binary/octet-stream",
        aws_evidence: API_PUT_OBJECT,
        s3s: "content_type is None",
        gateway: "content_type is None, as on s3s; the S3 default is written on the read, by the GetObject and HeadObject encoders \
                  when the backend names no type (q-content-0008). Until rustfs/gateway#749 the decoder filled it on the write",
        client_impact: "none once the decode agrees: RustFS derives a type from the key extension when none is sent \
                        (options.rs detect_content_type_from_object_name), so a.png still reads back as image/png; \
                        a backend that stores no type still answers binary/octet-stream",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-object-0058"),
        test_file: PUT_DECODE,
        test: "an_absent_content_type_is_left_absent_by_both_stacks",
    },
    RequestDivergence {
        id: "rd-put-0002",
        operation: "PutObject",
        request: "x-amz-sdk-checksum-algorithm naming the algorithm",
        aws: "the model binds ChecksumAlgorithm to x-amz-sdk-checksum-algorithm",
        aws_evidence: API_PUT_OBJECT,
        s3s: "reads x-amz-checksum-algorithm or infers it from x-amz-trailer, so the SDK header yields no algorithm",
        gateway: "reads x-amz-sdk-checksum-algorithm, as the model says",
        client_impact: "RustFS only uses the algorithm to pick the trailer checksum to apply, and SDKs send the matching header or trailer, \
                        so a well-formed SDK upload is stored the same way",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_DECODE,
        test: "the_sdk_checksum_algorithm_header_is_read_by_the_gateway_and_not_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0003",
        operation: "PutObject",
        request: "no Content-Length on a plain body (Transfer-Encoding: chunked included)",
        aws: "answers 411 MissingContentLength; an aws-chunked upload may omit Content-Length under a transfer coding \
              and states the object size in x-amz-decoded-content-length, mandatory in every streaming mode (sigv4-streaming)",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html",
        s3s: "takes the length from an exact body size hint (the in-process fixture has one); over a chunked transport it stays absent. \
              A STREAMING-* body needs x-amz-decoded-content-length instead, holds the decoded count to it and reports it as the length",
        gateway: "411 MissingContentLength for a plain body (q-length-0007). An aws-chunked body under Transfer-Encoding: chunked or \
                  HTTP/2 without Content-Length is accepted with its decoded length as the only ceiling, refused on any \
                  decoded-count mismatch, refused without the decoded length, and decoded with ContentLength = the decoded length \
                  (rustfs/gateway#750)",
        client_impact: "over a real chunked transport RustFS already refuses a plain PUT with no length (400 UnexpectedContent), so the \
                        client sees the AWS code rather than a new refusal; botocore's trailer upload over TLS (chunked, no \
                        Content-Length) is accepted as RustFS accepts it",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Landed("c-chunked-0002"),
        test_file: PUT_DECODE,
        test: "a_put_without_content_length_is_refused_by_the_gateway_and_backfilled_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0004",
        operation: "PutObject",
        request: "an Expires value that is not a date",
        aws: "Expires is modelled as a timestamp, and stored values that are not dates exist (q-timestamp-0005)",
        aws_evidence: API_PUT_OBJECT,
        s3s: "9c4690d8 answers 400 before the handler. f3e17541, the revision RustFS main links, holds Expires as text and hands it to \
              the handler, whose put body answers 400 InvalidArgument \"Invalid Expires header\" (rustfs/src/app/object/shared.rs \
              parse_expires_header)",
        gateway: "keeps the value opaque; the 9c4690d8 seam refuses it by member name (expires), the f3e17541 seam carries the text \
                  to the RustFS body unchanged",
        client_impact: "RustFS stores Expires as a timestamp and cannot hold the text, so its clients already get a 400 for it; through \
                        the f3e17541 seam the RustFS body still gives that 400, provided the M1 adapter maps its InvalidArgument \
                        to 400 rather than a 500",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(M1_ADAPTER),
        test_file: PUT_DECODE,
        test: "an_expires_that_is_not_a_date_is_kept_by_the_gateway_and_refused_only_by_the_baseline_s3s",
    },
    RequestDivergence {
        id: "rd-put-0005",
        operation: "PutObject",
        request: "two x-amz-checksum-* headers",
        aws: "one checksum header per request",
        aws_evidence: API_PUT_OBJECT,
        s3s: "hands every checksum member to the handler",
        gateway: "refused before the body is read (q-checksum-0006)",
        client_impact: "two integrity claims are refused instead of one being verified and the other dropped; no well-behaved client sends two",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_DECODE,
        test: "two_checksum_headers_are_refused_by_the_gateway_and_kept_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0006",
        operation: "PutObject",
        request: "an x-amz-checksum-sha512, -md5 or -xxhash* header",
        aws: "supports SHA-512, MD5, XXHash3, XXHash64 and XXHash128 checksums since 2026-04",
        aws_evidence: "https://aws.amazon.com/about-aws/whats-new/2026/04/s3-five-additional-checksum-algorithms/",
        s3s: "hands the value to the handler; RustFS verifies and stores it",
        gateway: "binds the value into ChecksumSpec like the other five algorithms, verifies it against the body, and the \
                  compat conversion hands it to the same s3s member",
        client_impact: "none: both stacks hand the handler the same checksum member",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Landed("c-checksum-0003"),
        test_file: PUT_DECODE,
        test: "a_checksum_algorithm_added_in_2026_04_is_handed_over_by_both_stacks",
    },
    RequestDivergence {
        id: "rd-put-0007",
        operation: "PutObject",
        request: "?versionId= on the PUT (MinIO extension)",
        aws: "PutObject takes no versionId; the service mints version ids",
        aws_evidence: API_PUT_OBJECT,
        s3s: "reads it into version_id for every caller; the RustFS handler passes it to the store",
        gateway: "PutObject has no member and drops the query. With the replication dialect installed \
                  (rustfs-gateway-dialect-minio replication_dialect) the request routes to minio:PutObjectReplica, authorised as \
                  s3:ReplicateObject and s3:PutObject on the key and never presigned, which carries it to the handler",
        client_impact: "a RustFS deployment installs the dialect, so replicas keep the source version id; a caller without \
                        s3:ReplicateObject is refused with 403 there, and ignored everywhere else. The source-version-id header \
                        fallback arrives on an ordinary PutObject and stays with the adapter's replication-header authorisation",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-object-0059"),
        test_file: PUT_DECODE,
        test: "a_put_version_id_reaches_the_app_body_only_through_the_replica_write",
    },
    RequestDivergence {
        id: "rd-put-0008",
        operation: "PutObject",
        request: "a key with a .. segment",
        aws: "keys are opaque, so a .. segment is a legal key",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html",
        s3s: "hands the key to the handler unchanged; the RustFS store behind it then refuses a . or .. segment (and a // run) on \
              every put, get, delete, copy and multipart entry (ecstore check_*_args through is_valid_object_prefix), so RustFS \
              never stored such a key",
        gateway: "the object-key floor refuses it with InvalidArgument, split on / and \\, for every operation that names the key: \
                  GET, HEAD, DELETE, PUT, multipart, a DeleteObjects body key and a copy source, on every profile. A . segment, \
                  an empty segment and one leading / stay legal; a leading // is refused as UNC. Reads and deletes get no \
                  migration carve-out",
        client_impact: "none for stored data: RustFS cannot hold a .. key, so no object becomes unreachable, and a RustFS-profile \
                        read or delete carve-out would reopen the traversal floor for a key class that is provably empty. Keys \
                        the gateway refuses that RustFS does store (a C0, DEL or C1 control other than NUL, LF and CR; a leading \
                        backslash; a drive root such as C:/; a literal %2F, %5C or %2E%2E) are listed before the switch by the \
                        RustFS admin key inventory, GET /rustfs/admin/v3/gateway-key-inventory, and copied to a safe key \
                        through the legacy stack",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Landed("c-naming-0029"),
        test_file: PUT_DECODE,
        test: "a_dot_dot_key_segment_is_refused_by_the_gateway_and_kept_by_s3s",
    },
    RequestDivergence {
        id: "rd-put-0009",
        operation: "PutObject",
        request: "x-amz-object-lock-event-hold: ON (with or without the duration headers)",
        aws: "the 2026-09-17 model adds ObjectLockEventHold and its Days/Years duration to PutObject, CopyObject and \
              CreateMultipartUpload; the hold is applied by the service and reported on GetObject/HeadObject",
        aws_evidence: API_PUT_OBJECT,
        s3s: "every pinned revision predates the member: the header is not bound, the handler sees no hold and the \
              RustFS store applies none",
        gateway: "binds the three members from the model; the seam refuses to convert an input naming any of them, \
                  so the RustFS adapter answers 400 instead of storing an object without the hold it was told to keep",
        client_impact: "a client asking for an event hold is refused rather than left believing its object is held; no SDK \
                        sends the header unless the caller sets it. The refusal lifts when an s3s re-pin carries the member \
                        and the RustFS store applies it",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/815"),
        test_file: PUT_DECODE,
        test: "an_object_lock_event_hold_is_refused_by_the_seam_and_unseen_by_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0001",
        operation: "PutObject",
        request: "Host photos.s3.eu-west-1.<configured domain>",
        aws: "<bucket>.s3.<region>.<domain> is the regional virtual-hosted form: bucket photos, region eu-west-1",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
        s3s: "strips only the base domain: bucket photos.s3.eu-west-1, no region",
        gateway: "bucket photos, host region eu-west-1",
        client_impact: "only clients addressing the regional form under a configured domain see a change, and they get the AWS answer; \
                        a dotted bucket literally named like that stays reachable path-style",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_a_regional_virtual_host_names_a_different_bucket_and_region",
    },
    RequestDivergence {
        id: "rd-ctx-0002",
        operation: "PutObject",
        request: "a header value that is not UTF-8",
        aws: "HTTP allows obs-text octets in a field value; S3 ignores headers it does not define",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9110#section-5.5",
        s3s: "passes the raw value to the handler",
        gateway: "the text header view still skips it, but the handler request context publishes every accepted line (iter_raw, \
                  ADR-0022), so a request an adapter converts from the handler context carries it byte for byte: zero diff",
        client_impact: "RustFS reads raw headers directly (MIME fallback, SSE-C fallback, replication and x-rustfs-* controls); \
                        the production adapter must build its header map from the handler context, never from the text view",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(M1_ADAPTER),
        test_file: PUT_CONTEXT,
        test: "divergence_a_non_utf8_header_value_reaches_both_handlers",
    },
    RequestDivergence {
        id: "rd-ctx-0003",
        operation: "PutObject",
        request: "an extension installed by the transport",
        aws: "no wire behaviour: an extension is in-process state",
        aws_evidence: "https://github.com/rustfs/gateway/pull/748",
        s3s: "passes it to the handler",
        gateway: "the handler context retains transport values behind typed read-only access; the adapter copies its known types: zero diff",
        client_impact: "RustFS needs RemoteAddr, RequestContext and ReqInfo from the transport and fails closed without ReqInfo",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Open(M1_ADAPTER),
        test_file: PUT_CONTEXT,
        test: "divergence_a_transport_extension_reaches_both_handlers",
    },
    RequestDivergence {
        id: "rd-ctx-0004",
        operation: "PutObject",
        request: "an absolute-form request target",
        aws: "a server accepts absolute-form, and its authority stands in for Host",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9112#section-3.2.2",
        s3s: "the handler's URI keeps the authority",
        gateway: "the converted URI is path and query only",
        client_impact: "RustFS takes the host from the Host header and reads the URI authority only as a fallback (multipart Location), \
                        and the Host header is always present on HTTP/1.1, so handlers see the same object and host",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_an_absolute_form_target_keeps_its_authority_only_on_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0005",
        operation: "PutObject",
        request: "a bare trailing ?",
        aws: "an empty query and no query are distinct URIs, and S3 gives the empty one no meaning of its own",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc3986#section-3.4",
        s3s: "query Some(\"\")",
        gateway: "no query",
        client_impact: "RustFS looks query parameters up by name and an empty query has none, so no handler decision changes",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: PUT_CONTEXT,
        test: "divergence_an_empty_query_marker_is_kept_only_by_s3s",
    },
    RequestDivergence {
        id: "rd-ctx-0006",
        operation: "PutObject",
        request: "two lines for one x-amz-meta-* key, in any case",
        aws: "documents that same-name metadata headers are combined into one comma-separated value",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html",
        s3s: "400 InvalidRequest before the handler",
        gateway: "400 InvalidRequest at wire acceptance (DuplicateMetadataHeader); it used to keep the last line and drop the first silently",
        client_impact: "the same answer RustFS gives today; a client relying on the AWS join is refused visibly instead of losing a value",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Landed("c-object-0057"),
        test_file: PUT_CONTEXT,
        test: "divergence_repeated_metadata_lines_are_refused_by_both_stacks",
    },
    RequestDivergence {
        id: "rd-loc-0001",
        operation: "GetBucketLocation",
        request: "any request answered with an XML body",
        aws: "the XML declaration is followed by a line break before the root element",
        aws_evidence: API_GET_BUCKET_LOCATION,
        s3s: "writes the declaration and the root element with nothing between them",
        gateway: "writes the declaration and a line break, byte for byte what S3 sends (rustfs_gateway_xml::DECLARATION)",
        client_impact: "none: the line break is insignificant whitespace in the XML prolog, and every SDK and XML parser reads both \
                        documents identically; only a byte-exact comparison of bodies sees it",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: LOCATION_CONTEXT,
        test: "the_xml_declaration_is_followed_by_a_line_break_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-loc-0002",
        operation: "GetBucketLocation",
        request: "a known access key with a signature that does not match",
        aws: "403 SignatureDoesNotMatch; InvalidAccessKeyId is reserved for a key that does not exist",
        aws_evidence: ERROR_RESPONSES,
        s3s: "403 SignatureDoesNotMatch",
        gateway: "403 SignatureDoesNotMatch. Until rustfs/backlog#1752 render::from_auth collapsed it into InvalidAccessKeyId, \
                  contradicting docs/security-model.md, which keeps the two codes distinct and relies on timing parity \
                  and the credential rate limit against enumeration",
        client_impact: "SDKs branch on the code: SignatureDoesNotMatch means a wrong secret or a clock or signing bug, \
                        InvalidAccessKeyId a missing key, and several refresh credentials or stop retrying on the latter",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Landed("c-cred-0009"),
        test_file: LOCATION_CONTEXT,
        test: "a_forged_signature_on_a_known_key_is_signature_does_not_match_on_both_stacks",
    },
    RequestDivergence {
        id: "rd-loc-0003",
        operation: "GetBucketLocation",
        request: "an access key that does not exist",
        aws: "403 InvalidAccessKeyId with a prose message that SDKs do not parse",
        aws_evidence: ERROR_RESPONSES,
        s3s: "403 with the code and message the auth provider returns: RustFS IAMAuth answers InvalidAccessKeyId with a sentence \
              of its own (rustfs/src/auth.rs); the s3s SimpleAuth the pin runs answers NotSignedUp",
        gateway: "403 InvalidAccessKeyId with the constant message it gives every credential rejection \
                  (\"the request was not authenticated\")",
        client_impact: "none: clients branch on the code, not the message, and the code agrees; the gateway sentence names no \
                        credential and is never copied from AWS prose",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: LOCATION_CONTEXT,
        test: "an_unknown_access_key_is_invalid_access_key_id_on_the_gateway_and_the_auth_providers_answer_on_s3s",
    },
    RequestDivergence {
        id: "rd-loc-0004",
        operation: "GetBucketLocation",
        request: "a SigV4 credential scope naming a region the deployment does not serve",
        aws: "400 AuthorizationHeaderMalformed naming the region to use",
        aws_evidence: ERROR_RESPONSES,
        s3s: "verifies the signature for any region: expected_region is unset by default, and RustFS never sets it",
        gateway: "400 AuthorizationHeaderMalformed with the configured region by default (ADR-0009, c-bkt-0030); with \
                  SigV4Authenticator::accept_any_signing_region (ADR-0023) any region in the configured-name grammar is \
                  verified like s3s does",
        client_impact: "RustFS clients commonly sign with us-east-1 or an operator label whatever the server is set to; without the \
                        profile every such request would become a 400",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-location-0005"),
        test_file: LOCATION_CONTEXT,
        test: "a_scope_region_the_gateway_does_not_serve_is_verified_only_under_the_rustfs_profile",
    },
    RequestDivergence {
        id: "rd-cfg-0001",
        operation: "PutBucketVersioning",
        request: "a body that is the bare text Enabled instead of a VersioningConfiguration document (the MinIO body literal)",
        aws: "the request body is the VersioningConfiguration XML document that carries Status",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html",
        s3s: "built with its minio feature, as RustFS builds it, reads a body whose ASCII-trimmed bytes are exactly Enabled as \
              Status Enabled (http::take_body_literal) and hands it to the handler; every other body, a bare Suspended \
              included, is read as XML and refused",
        gateway: "400 MalformedXML before the handler: body_literal is false for this operation, so the body must be the \
                  document (c-bucketconfig-0060, decided in rustfs/gateway#715)",
        client_impact: "a client sending the bare literal gets 400 where RustFS answered 200 and turned versioning on. None has \
                        been found: minio-go and mc marshal the XML document, MinIO's own server reads the body only as XML, \
                        and s3s-project/s3s#612 names no client. If one appears, the literal is added through overlay, IR \
                        and codec, never as a handler branch",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::Landed("c-bucketconfig-0060"),
        test_file: CONFIG_DECODE,
        test: "a_bare_enabled_versioning_body_is_refused_by_the_gateway_and_accepted_by_s3s",
    },
];

/// Every pinned divergence, in id order as written: the operation, context and configuration
/// slices above, then the error-response slice (`errors`) and the signed-body slice (`body`).
pub const REQUEST_DIVERGENCES: [RequestDivergence; 40] = concat(
    concat::<20, 10, 30>(OPERATION_DIVERGENCES, errors::ERROR_DIVERGENCES),
    body::BODY_DIVERGENCES,
);

/// `first` then `second`, at compile time; the declared length must be their sum.
const fn concat<const A: usize, const B: usize, const C: usize>(
    first: [RequestDivergence; A],
    second: [RequestDivergence; B],
) -> [RequestDivergence; C] {
    assert!(A > 0 && A + B == C, "the register is the sum of its slices");
    let mut out = [first[0]; C];
    let mut index = 0;
    while index < C {
        out[index] = if index < A { first[index] } else { second[index - A] };
        index += 1;
    }
    out
}

/// A register entry that does not hold as written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestDivergenceError {
    /// The id is not `rd-<put|ctx|loc|cfg|err|body>-NNNN`.
    MalformedId(&'static str),
    /// Two entries share an id.
    DuplicateId(&'static str),
    /// A descriptive field is empty.
    MissingText {
        /// Entry.
        id: &'static str,
        /// Field.
        field: &'static str,
    },
    /// The AWS evidence is not a URL.
    EvidenceNotUrl(&'static str),
    /// A ruling that changes behaviour names no follow-up, so nothing owns the change.
    UnownedChange(&'static str),
    /// A follow-up is neither a rustfs issue URL nor a conformance case id.
    MalformedFollowUp(&'static str),
    /// The pinned test lives outside the files the register is checked against.
    UnknownTestFile(&'static str),
}

impl fmt::Display for RequestDivergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedId(id) => write!(formatter, "{id} is not an rd-<put|ctx|loc|cfg|err|body>-NNNN id"),
            Self::DuplicateId(id) => write!(formatter, "{id} appears twice"),
            Self::MissingText { id, field } => write!(formatter, "{id} leaves {field} empty"),
            Self::EvidenceNotUrl(id) => write!(formatter, "{id} cites AWS evidence that is not a URL"),
            Self::UnownedChange(id) => write!(formatter, "{id} changes behaviour but names no follow-up"),
            Self::MalformedFollowUp(id) => write!(formatter, "{id} names a follow-up that is neither an issue nor a case"),
            Self::UnknownTestFile(id) => write!(formatter, "{id} pins a test outside the checked files"),
        }
    }
}

impl std::error::Error for RequestDivergenceError {}

/// The validated register.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestDivergenceReport {
    entries: &'static [RequestDivergence],
}

impl RequestDivergenceReport {
    /// The entries, in id order as written.
    #[must_use]
    pub const fn entries(&self) -> &'static [RequestDivergence] {
        self.entries
    }

    /// Renders the register: one summary line, then one line per ruling.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("request divergences: rulings={}", self.entries.len());
        for ruling in DivergenceRuling::ALL {
            let count = self.entries.iter().filter(|entry| entry.ruling == ruling).count();
            out.push_str(&format!(" {}={count}", ruling.slug()));
        }
        let open = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.follow_up, DivergenceFollowUp::Open(_)))
            .count();
        let landed = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.follow_up, DivergenceFollowUp::Landed(_)))
            .count();
        out.push_str(&format!(" open-follow-ups={open} landed={landed}\n"));
        for entry in self.entries {
            let follow_up = match entry.follow_up {
                DivergenceFollowUp::None => "none",
                DivergenceFollowUp::Landed(case) | DivergenceFollowUp::Open(case) => case,
            };
            out.push_str(&format!(
                "divergence {} operation={} ruling={} follow-up={follow_up} test={}::{}\n",
                entry.id,
                entry.operation,
                entry.ruling.slug(),
                entry.test_file,
                entry.test,
            ));
        }
        out
    }
}

/// Validates [`REQUEST_DIVERGENCES`].
///
/// # Errors
///
/// The first [`RequestDivergenceError`] an entry raises.
pub fn build_request_divergences() -> Result<RequestDivergenceReport, RequestDivergenceError> {
    check_register(&REQUEST_DIVERGENCES)?;
    Ok(RequestDivergenceReport {
        entries: &REQUEST_DIVERGENCES,
    })
}

fn check_register(entries: &[RequestDivergence]) -> Result<(), RequestDivergenceError> {
    for (index, entry) in entries.iter().enumerate() {
        if !well_formed_id(entry.id) {
            return Err(RequestDivergenceError::MalformedId(entry.id));
        }
        if entries[..index].iter().any(|earlier| earlier.id == entry.id) {
            return Err(RequestDivergenceError::DuplicateId(entry.id));
        }
        for (field, text) in [
            ("operation", entry.operation),
            ("request", entry.request),
            ("aws", entry.aws),
            ("s3s", entry.s3s),
            ("gateway", entry.gateway),
            ("client_impact", entry.client_impact),
            ("test", entry.test),
        ] {
            if text.trim().is_empty() {
                return Err(RequestDivergenceError::MissingText { id: entry.id, field });
            }
        }
        if !entry.aws_evidence.starts_with("https://") {
            return Err(RequestDivergenceError::EvidenceNotUrl(entry.id));
        }
        match entry.follow_up {
            DivergenceFollowUp::None if entry.ruling != DivergenceRuling::KeepGateway => {
                return Err(RequestDivergenceError::UnownedChange(entry.id));
            }
            DivergenceFollowUp::Open(url) if !is_issue_url(url) => {
                return Err(RequestDivergenceError::MalformedFollowUp(entry.id));
            }
            DivergenceFollowUp::Landed(case) if !is_case_id(case) => {
                return Err(RequestDivergenceError::MalformedFollowUp(entry.id));
            }
            _ => {}
        }
        if !PINNED_TEST_FILES.contains(&entry.test_file) {
            return Err(RequestDivergenceError::UnknownTestFile(entry.id));
        }
    }
    Ok(())
}

fn well_formed_id(id: &str) -> bool {
    let Some(number) = ["rd-put-", "rd-ctx-", "rd-loc-", "rd-cfg-", "rd-err-", "rd-body-"]
        .iter()
        .find_map(|prefix| id.strip_prefix(prefix))
    else {
        return false;
    };
    number.len() == 4 && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_issue_url(url: &str) -> bool {
    [
        "https://github.com/rustfs/gateway/issues/",
        "https://github.com/rustfs/backlog/issues/",
    ]
    .iter()
    .any(|prefix| {
        url.strip_prefix(prefix)
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn is_case_id(case: &str) -> bool {
    case.strip_prefix("c-")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(domain, number)| {
            !domain.is_empty() && number.len() == 4 && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

mod body;
mod errors;

#[cfg(test)]
mod tests;
