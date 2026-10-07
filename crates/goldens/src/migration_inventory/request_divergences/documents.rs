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

//! The request-document slice of the request-divergence register: what the RustFS profile's
//! document reading (rustfs/gateway#1078) still answers differently from legacy RustFS.
//!
//! Responsible for: `rd-doc-0001`..`0004` and `rd-doc-0006`..`0008`, each with its ruling and its
//! pinned test in `operation_diff/request_documents/divergences.rs` (`rd-doc-0005`, an empty list
//! wrapper, is retired: the gateway carries it now; so is `rd-doc-0009`, an empty required
//! `Status`, which the RustFS reading hands to RustFS's handler as legacy RustFS does). Every one
//! is a refusal where legacy RustFS reads the document: two security refusals the reading keeps,
//! and five values the gateway cannot carry exactly, refused rather than handed over or stored
//! differently. `parity` in the same
//! directory requires every difference it measures across every perturbation of every request
//! document to fall in exactly one of them.
//! NOT responsible for: the register's validation and rendering (the parent module) or the other
//! slices.
//! Upstream: the parent module's types. Downstream: the parent's `REQUEST_DIVERGENCES`.

use super::{DOCUMENT_DECODE, DivergenceFollowUp, DivergenceRuling, RequestDivergence};

const XML_REFERENCE: &str = "https://www.w3.org/TR/xml/";
const API_TAGGING: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_Tag.html";
const API_LIFECYCLE_EXPIRATION: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleExpiration.html";
const API_OBJECT_LOCK: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLockConfiguration.html";
const API_DELETE_OBJECTS: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html";
const API_S3_LOCATION: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3Location.html";

pub(super) const DOCUMENT_DIVERGENCES: [RequestDivergence; 7] = [
    RequestDivergence {
        id: "rd-doc-0001",
        operation: "every operation with an XML request document",
        request: "a document with a DOCTYPE declaration in its prolog",
        aws: "a request document is XML 1.0; S3 documents no DTD and no entity beyond the predefined five",
        aws_evidence: XML_REFERENCE,
        s3s: "the legacy stack skips the declaration and reads the document (an entity it declares is still refused when \
              referenced)",
        gateway: "400 MalformedXML under the RustFS profile as under the tree reading: the entity-expansion entry point is \
                  refused rather than trusted to a parser dependency",
        client_impact: "a client sending a DOCTYPE gets 400 where RustFS answered 200; no S3 SDK or tool is known to send one",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "a_doctype_is_refused_by_the_gateway_and_skipped_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0002",
        operation: "every operation with an XML request document",
        request: "a value holding a character XML 1.0 cannot represent (a C0 control other than tab, newline, carriage return)",
        aws: "such a character is not an XML Char; a document holding one is not well formed",
        aws_evidence: XML_REFERENCE,
        s3s: "the legacy stack reads and stores the character, and every later read of that configuration writes a document no \
              conforming XML parser reads",
        gateway: "400 MalformedXML: the reader refuses the character, so nothing is stored that the answer to the next read \
                  could not carry",
        client_impact: "a client whose document holds such a character gets 400 where RustFS answered 200 and then could not \
                        read its own configuration back",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "a_character_xml_cannot_represent_is_refused_by_the_gateway_and_stored_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0003",
        operation: "PutBucketTagging, PutObjectTagging, PutBucketLifecycleConfiguration, PutBucketReplication, \
                    CompleteMultipartUpload",
        request: "a Tag without its Key or its Value, or a completed Part without its PartNumber",
        aws: "Key and Value are required members of a Tag; PartNumber identifies a completed part",
        aws_evidence: API_TAGGING,
        s3s: "the legacy stack reads each as absent; RustFS then stores a key-only or value-only bucket tag, refuses an \
              object tag with 400 InvalidTag, and treats a part without a number as part 0 and refuses it with InvalidPart",
        gateway: "400 MalformedXML: the model requires the member and the gateway's member has no absent spelling, so the \
                  document is refused rather than handed over with an invented value",
        client_impact: "a bucket-tagging client sending a key-only or value-only tag gets 400 where RustFS stored it; the other \
                        documents were refused by RustFS too, with another code",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "an_absent_member_the_model_requires_is_refused_by_the_gateway_and_read_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0004",
        operation: "PutBucketLifecycleConfiguration, PutObjectRetention, CompleteMultipartUpload, DeleteObjects",
        request: "a date with a non-zero UTC offset, or an entity tag no gateway tag can hold (empty, or holding a quote)",
        aws: "lifecycle dates are midnight UTC and a retention date is an ISO 8601 instant; an entity tag is a quoted string",
        aws_evidence: API_LIFECYCLE_EXPIRATION,
        s3s: "the legacy stack keeps the offset — RustFS stores a retention date with it, and writes a lifecycle date's local \
              digits followed by Z — and reads any printable text as a strong entity tag",
        gateway: "400 InvalidArgument: the gateway's timestamp is a UTC instant and its entity tag refuses a quote, so the value \
                  is refused rather than stored differently",
        client_impact: "a client sending an offset date gets 400 where RustFS stored a shifted or offset-bearing date; a part or \
                        object named by such a tag was refused by RustFS later",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "a_value_the_gateway_cannot_carry_is_refused_by_the_gateway_and_read_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0006",
        operation: "PutObjectLockConfiguration, RestoreObject",
        request: "an empty body",
        aws: "the document is the request payload",
        aws_evidence: API_OBJECT_LOCK,
        s3s: "the legacy stack reads the document as optional and hands none over; RustFS then answers 400 InvalidArgument for \
              the object-lock configuration and 400 MalformedXML for the restore",
        gateway: "400 InvalidArgument for the object-lock configuration and 400 MalformedXML for the restore, before any \
                  handler: the model requires the document, and each refusal carries the code RustFS's handler answers",
        client_impact: "the same status and code, and nothing is written either way; a check RustFS makes between reading the \
                        document and its handler (the bucket's existence, access) is not reached, so its answer is not given \
                        first",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "an_empty_body_the_model_requires_is_refused_by_the_gateway_and_handed_over_absent_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0007",
        operation: "DeleteObjects, PutBucketWebsite",
        request: "a key in the document that the gateway's name policy refuses: empty, or holding a control character",
        aws: "an object key is UTF-8 text of 1 to 1024 bytes",
        aws_evidence: API_DELETE_OBJECTS,
        s3s: "the legacy stack reads any text as the key and RustFS answers per key",
        gateway: "400 InvalidArgument for the whole request: body keys pass the deployment's name policy, the same one a path \
                  key passes",
        client_impact: "a batch delete naming such a key is refused whole where RustFS answered per key; the RustFS profile's \
                        key policy is rustfs/gateway#1107's, and body keys follow it",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/1107"),
        test_file: DOCUMENT_DECODE,
        test: "a_body_key_the_name_policy_refuses_is_refused_by_the_gateway_and_read_by_the_legacy_stack",
    },
    RequestDivergence {
        id: "rd-doc-0008",
        operation: "RestoreObject",
        request: "an OutputLocation BucketName that is not a valid bucket name",
        aws: "BucketName names the bucket the restore result is written to",
        aws_evidence: API_S3_LOCATION,
        s3s: "the legacy stack reads any text; RustFS then refuses the output location itself (400 InvalidRequest, or 501 \
              NotImplemented for a SELECT restore)",
        gateway: "400 InvalidArgument at decode: the member is a bucket name",
        client_impact: "a restore RustFS refused is refused with another code; nothing is written either way",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: DOCUMENT_DECODE,
        test: "an_invalid_output_bucket_name_is_refused_by_the_gateway_and_read_by_the_legacy_stack",
    },
];
