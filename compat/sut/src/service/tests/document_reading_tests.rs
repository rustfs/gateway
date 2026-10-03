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

//! Request documents as the RustFS-profile launcher reads them (rustfs/gateway#1078), and what
//! each answer leaves in storage.
//!
//! Responsible for: the document reading legacy RustFS applies, observed end to end — an element a
//! nested structure does not know, a repeated member, a member name spelled with a prefix and a
//! value its grammar does not read each refused with `400 MalformedXML` and nothing stored,
//! replaced or deleted; an element the document's root does not know, and one inside a wrapped
//! list, skipped as legacy RustFS skips them; a leading-digits integer read as legacy RustFS
//! reads it; and an empty body answered as legacy RustFS answers it — `MissingRequestBodyError`
//! where the document is required, `MalformedXML` for a multipart completion, and the lifecycle
//! handler's `InvalidArgument` — with nothing stored.
//! NOT responsible for: proving each answer is legacy RustFS's (the `request_documents` parity
//! battery in `crates/goldens` does, over every perturbation of every request document) or the
//! tree reading other deployments keep (the conformance corpus).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const LIFECYCLE_KEPT: &str = "<LifecycleConfiguration><Rule><ID>kept</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_KEPT_MD5: &str = "s+9wqHS/8Aos1/UG8IJFIg==";
const LIFECYCLE_UNKNOWN_IN_RULE: &str = "<LifecycleConfiguration><Rule><ID>refused</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><FutureKnob>on</FutureKnob><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_UNKNOWN_IN_RULE_MD5: &str = "iWC5dUUQb1IzbLsXnWiUCg==";
const LIFECYCLE_REPEATED_STATUS: &str = "<LifecycleConfiguration><Rule><ID>refused</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_REPEATED_STATUS_MD5: &str = "F2fCcC8pzHccOIQobF7ERw==";
const LIFECYCLE_UNREADABLE_DAYS: &str = "<LifecycleConfiguration><Rule><ID>refused</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>thirty</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_UNREADABLE_DAYS_MD5: &str = "vAMrljizmrYyhj/vfKS+xg==";
const LIFECYCLE_UNREADABLE_BOOLEAN: &str = "<LifecycleConfiguration><Rule><ID>refused</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>True</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_UNREADABLE_BOOLEAN_MD5: &str = "XLkg4JCDl9Al+EgVQ8J7jg==";
const LIFECYCLE_PREFIXED_STATUS: &str = "<LifecycleConfiguration xmlns:s3=\"urn:s3\"><Rule><ID>refused</ID><Filter><Prefix>logs/</Prefix></Filter><s3:Status>Enabled</s3:Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_PREFIXED_STATUS_MD5: &str = "CLRG1lkksBVBF30VnzFfMQ==";
const LIFECYCLE_UNKNOWN_AT_ROOT: &str = "<LifecycleConfiguration><FutureKnob>on</FutureKnob><Rule><ID>root-unknown</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_UNKNOWN_AT_ROOT_MD5: &str = "KubQWadq/k84cZRB51lmig==";
const LIFECYCLE_LEADING_DIGITS: &str = "<LifecycleConfiguration><Rule><ID>leading-digits</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>7days</Days></Expiration></Rule></LifecycleConfiguration>";
const LIFECYCLE_LEADING_DIGITS_MD5: &str = "1f5zcuGhKA1OvoOemR/+Aw==";

const TAGGING_KEPT: &str = "<Tagging><TagSet><Tag><Key>kept</Key><Value>v</Value></Tag></TagSet></Tagging>";
const TAGGING_KEPT_MD5: &str = "YU6djLYOjZWvoo7kFyCFWA==";
const TAGGING_REPEATED_TAG_SET: &str = "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet><TagSet><Tag><Key>b</Key><Value>2</Value></Tag></TagSet></Tagging>";
const TAGGING_REPEATED_TAG_SET_MD5: &str = "DwF4nwoBg4QQcaNWt9zpNA==";
const TAGGING_UNKNOWN_IN_TAG: &str =
    "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value><FutureKnob>on</FutureKnob></Tag></TagSet></Tagging>";
const TAGGING_UNKNOWN_IN_TAG_MD5: &str = "NrnYnSL3HvSivpxA7wg52A==";
const TAGGING_UNKNOWN_IN_TAG_SET: &str =
    "<Tagging><TagSet><FutureKnob>on</FutureKnob><Tag><Key>entry-skipped</Key><Value>v</Value></Tag></TagSet></Tagging>";
const TAGGING_UNKNOWN_IN_TAG_SET_MD5: &str = "napr/X6jDGUSyNEAWZycyg==";

const DELETE_UNKNOWN_IN_OBJECT: &str = "<Delete><Object><Key>kept</Key><FutureKnob>on</FutureKnob></Object></Delete>";
const DELETE_UNKNOWN_IN_OBJECT_MD5: &str = "7LsJdepLCjhfp5QnF0sj9w==";
const DELETE_REPEATED_KEY: &str = "<Delete><Object><Key>kept</Key><Key>other</Key></Object></Delete>";
const DELETE_REPEATED_KEY_MD5: &str = "VK6S5Dr4ea/XRh1thNShgw==";
const DELETE_UNREADABLE_QUIET: &str = "<Delete><Quiet>yes</Quiet><Object><Key>kept</Key></Object></Delete>";
const DELETE_UNREADABLE_QUIET_MD5: &str = "uJm8XdkytuQrVb2yvxVwow==";
const DELETE_UNKNOWN_AT_ROOT: &str = "<Delete><FutureKnob>on</FutureKnob><Object><Key>kept</Key></Object></Delete>";
const DELETE_UNKNOWN_AT_ROOT_MD5: &str = "w59+ZXWucyfPgtdSr3BNkQ==";

const ACL_WITHOUT_TYPE: &str = "<AccessControlPolicy><Owner><ID>s3gate-main</ID></Owner><AccessControlList><Grant><Grantee><ID>refused-grantee</ID></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";
const ACL_WITHOUT_TYPE_MD5: &str = "wMpbk15GKyGviFti7LNwAg==";
const ACL_OTHER_PREFIX: &str = "<AccessControlPolicy><Owner><ID>s3gate-main</ID></Owner><AccessControlList><Grant><Grantee xmlns:x=\"http://www.w3.org/2001/XMLSchema-instance\" x:type=\"CanonicalUser\"><ID>refused-grantee</ID></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";
const ACL_OTHER_PREFIX_MD5: &str = "k0fZr7VDgG2zkPpk2J2XdA==";

const EMPTY_MD5: &str = "1B2M2Y8AsgTpgAmY7PhCfg==";
const VERSIONING_ENABLED: &str = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
const VERSIONING_ENABLED_MD5: &str = "8qj8HSeDu3APPMQZVG06WQ==";

async fn send(service: &S3Service, method: http::Method, target: &str, document: &'static str, md5: &str) -> WireResponse {
    exchange(
        service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            method,
            target,
            Bytes::from_static(document.as_bytes()),
            &[("content-md5", md5)],
        ),
    )
    .await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

async fn bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/documents", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn refused_as_malformed(response: &WireResponse, what: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{what}: {body}");
    assert!(body.contains("<Code>MalformedXML</Code>"), "{what}: {body}");
}

fn accepted(response: &WireResponse, what: &str) {
    assert_eq!(response.status(), 200, "{what}: {}", body_of(response));
}

/// Negative — inside a lifecycle rule, an unknown element, a repeated `Status`, a prefixed `Status`
/// (legacy RustFS compares the name as spelled), an unreadable integer and an unreadable boolean
/// are each `400 MalformedXML`, and the stored configuration is still the one written before them.
#[tokio::test]
async fn n_a_lifecycle_rule_legacy_rustfs_refuses_is_malformed_and_replaces_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(&service, http::Method::PUT, "/documents?lifecycle", LIFECYCLE_KEPT, LIFECYCLE_KEPT_MD5).await,
        "the kept configuration",
    );

    for (document, md5) in [
        (LIFECYCLE_UNKNOWN_IN_RULE, LIFECYCLE_UNKNOWN_IN_RULE_MD5),
        (LIFECYCLE_REPEATED_STATUS, LIFECYCLE_REPEATED_STATUS_MD5),
        (LIFECYCLE_PREFIXED_STATUS, LIFECYCLE_PREFIXED_STATUS_MD5),
        (LIFECYCLE_UNREADABLE_DAYS, LIFECYCLE_UNREADABLE_DAYS_MD5),
        (LIFECYCLE_UNREADABLE_BOOLEAN, LIFECYCLE_UNREADABLE_BOOLEAN_MD5),
    ] {
        refused_as_malformed(&send(&service, http::Method::PUT, "/documents?lifecycle", document, md5).await, document);
    }

    let read = get(&service, "/documents?lifecycle").await;
    let body = body_of(&read);
    assert_eq!(read.status(), 200, "{body}");
    assert!(body.contains("<ID>kept</ID>"), "{body}");
    assert!(!body.contains("<ID>refused</ID>"), "a refused document reached storage: {body}");
}

/// Negative — no lifecycle configuration is stored where none was when the only one sent is refused.
#[tokio::test]
async fn n_a_refused_first_lifecycle_configuration_stores_none() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    refused_as_malformed(
        &send(
            &service,
            http::Method::PUT,
            "/documents?lifecycle",
            LIFECYCLE_UNKNOWN_IN_RULE,
            LIFECYCLE_UNKNOWN_IN_RULE_MD5,
        )
        .await,
        "an unknown element in the rule",
    );
    let read = get(&service, "/documents?lifecycle").await;
    assert_eq!(read.status(), 404, "{}", body_of(&read));
}

/// Positive — an element the document's root does not know is skipped, as legacy RustFS skips it,
/// and the rest of the document is stored.
#[tokio::test]
async fn an_unknown_element_under_the_root_is_skipped_and_the_document_stored() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(
            &service,
            http::Method::PUT,
            "/documents?lifecycle",
            LIFECYCLE_UNKNOWN_AT_ROOT,
            LIFECYCLE_UNKNOWN_AT_ROOT_MD5,
        )
        .await,
        "an unknown element under the root",
    );
    let body = body_of(&get(&service, "/documents?lifecycle").await);
    assert!(body.contains("<ID>root-unknown</ID>"), "{body}");
    assert!(!body.contains("FutureKnob"), "{body}");
}

/// Positive — Legacy-compat (rustfs/backlog#2684): an integer is read from its leading digits, as
/// legacy RustFS reads it, so `7days` is stored as `7`.
#[tokio::test]
async fn an_integer_is_read_from_its_leading_digits_as_legacy_rustfs_reads_it() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(
            &service,
            http::Method::PUT,
            "/documents?lifecycle",
            LIFECYCLE_LEADING_DIGITS,
            LIFECYCLE_LEADING_DIGITS_MD5,
        )
        .await,
        "leading digits",
    );
    let body = body_of(&get(&service, "/documents?lifecycle").await);
    assert!(body.contains("<Days>7</Days>"), "{body}");
}

/// Negative — a repeated `TagSet` and an unknown element inside a `Tag` are `400 MalformedXML`,
/// and the stored tag set is still the one written before them.
#[tokio::test]
async fn n_a_tag_set_legacy_rustfs_refuses_is_malformed_and_replaces_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(&service, http::Method::PUT, "/documents?tagging", TAGGING_KEPT, TAGGING_KEPT_MD5).await,
        "the kept tag set",
    );
    for (document, md5) in [
        (TAGGING_REPEATED_TAG_SET, TAGGING_REPEATED_TAG_SET_MD5),
        (TAGGING_UNKNOWN_IN_TAG, TAGGING_UNKNOWN_IN_TAG_MD5),
    ] {
        refused_as_malformed(&send(&service, http::Method::PUT, "/documents?tagging", document, md5).await, document);
    }
    let body = body_of(&get(&service, "/documents?tagging").await);
    assert!(body.contains("<Key>kept</Key>"), "{body}");
    assert!(!body.contains("<Key>a</Key>") && !body.contains("<Key>b</Key>"), "{body}");
}

/// Positive — an element inside a wrapped list that is not the list's entry is skipped, as legacy
/// RustFS skips it, and the entries are stored.
#[tokio::test]
async fn an_unknown_element_inside_a_wrapped_list_is_skipped_and_the_entries_stored() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(
            &service,
            http::Method::PUT,
            "/documents?tagging",
            TAGGING_UNKNOWN_IN_TAG_SET,
            TAGGING_UNKNOWN_IN_TAG_SET_MD5,
        )
        .await,
        "an unknown element inside the tag set",
    );
    let body = body_of(&get(&service, "/documents?tagging").await);
    assert!(body.contains("<Key>entry-skipped</Key>"), "{body}");
}

/// Negative — a batch delete whose object carries an unknown element or a second `Key`, or whose
/// `Quiet` is not a boolean legacy RustFS reads, is `400 MalformedXML` and deletes nothing: the
/// object is still there, byte for byte.
#[tokio::test]
async fn n_a_batch_delete_legacy_rustfs_refuses_is_malformed_and_deletes_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/documents/kept", Bytes::from_static(b"hello"))).await;
    accepted(&stored, "the object");

    for (document, md5) in [
        (DELETE_UNKNOWN_IN_OBJECT, DELETE_UNKNOWN_IN_OBJECT_MD5),
        (DELETE_REPEATED_KEY, DELETE_REPEATED_KEY_MD5),
        (DELETE_UNREADABLE_QUIET, DELETE_UNREADABLE_QUIET_MD5),
    ] {
        refused_as_malformed(&send(&service, http::Method::POST, "/documents?delete", document, md5).await, document);
        let read = get(&service, "/documents/kept").await;
        assert_eq!(read.status(), 200, "{document} deleted the object");
        assert_eq!(body_of(&read), "hello", "{document}");
    }
}

/// Positive — an element the batch delete's root does not know is skipped, as legacy RustFS skips
/// it, and the named object is deleted.
#[tokio::test]
async fn an_unknown_element_under_the_delete_root_is_skipped_and_the_object_deleted() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    let stored = exchange(&service, as_main(http::Method::PUT, "/documents/kept", Bytes::from_static(b"hello"))).await;
    accepted(&stored, "the object");

    let deleted = send(
        &service,
        http::Method::POST,
        "/documents?delete",
        DELETE_UNKNOWN_AT_ROOT,
        DELETE_UNKNOWN_AT_ROOT_MD5,
    )
    .await;
    accepted(&deleted, "an unknown element under the root");
    assert!(body_of(&deleted).contains("<Deleted><Key>kept</Key>"), "{}", body_of(&deleted));
    assert_eq!(get(&service, "/documents/kept").await.status(), 404);
}

/// Negative — a grant whose grantee carries no literal `xsi:type` (none at all, or the schema
/// instance namespace under another prefix) is `400 MalformedXML`, as legacy RustFS refuses it,
/// and the bucket's ACL is left as it was.
#[tokio::test]
async fn n_a_grantee_without_the_literal_type_attribute_is_malformed_and_grants_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    for (document, md5) in [
        (ACL_WITHOUT_TYPE, ACL_WITHOUT_TYPE_MD5),
        (ACL_OTHER_PREFIX, ACL_OTHER_PREFIX_MD5),
    ] {
        refused_as_malformed(&send(&service, http::Method::PUT, "/documents?acl", document, md5).await, document);
    }
    let read = get(&service, "/documents?acl").await;
    let body = body_of(&read);
    assert_eq!(read.status(), 200, "{body}");
    assert!(!body.contains("refused-grantee"), "a refused grant reached storage: {body}");
}

// ── an empty body ─────────────────────────────────────────────────────────────────────────────

/// `body` without the per-request ids an error document carries.
fn without_request_ids(body: &str) -> String {
    let mut out = body.to_owned();
    for element in ["RequestId", "HostId"] {
        let (open, close) = (format!("<{element}>"), format!("</{element}>"));
        if let Some((head, rest)) = out.split_once(&open)
            && let Some((_, tail)) = rest.split_once(&close)
        {
            out = format!("{head}{tail}");
        }
    }
    out
}

/// What every read-back an empty-body write could have changed answers: the bucket's
/// configurations, the object's tag set and the listing.
async fn read_backs(service: &S3Service) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    for target in [
        "/documents?cors",
        "/documents?encryption",
        "/documents?publicAccessBlock",
        "/documents?tagging",
        "/documents?versioning",
        "/documents?lifecycle",
        "/documents/key?tagging",
        "/documents",
    ] {
        let read = get(service, target).await;
        out.push((read.status().as_u16(), without_request_ids(&body_of(&read))));
    }
    out
}

/// Negative — an empty body where legacy RustFS requires the document is `400
/// MissingRequestBodyError`, the legacy stack's answer before any handler runs, on every such
/// write this launcher serves (a batch delete, the CORS, encryption, public-access-block, tagging
/// and versioning configurations, and an object's tag set), and none of them stores, replaces or
/// deletes anything.
#[tokio::test]
async fn n_an_empty_required_document_is_a_missing_body_and_changes_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &exchange(&service, as_main(http::Method::PUT, "/documents/key", Bytes::from_static(b"x"))).await,
        "the object",
    );
    accepted(
        &send(&service, http::Method::PUT, "/documents?tagging", TAGGING_KEPT, TAGGING_KEPT_MD5).await,
        "the kept tag set",
    );
    accepted(
        &send(&service, http::Method::PUT, "/documents/key?tagging", TAGGING_KEPT, TAGGING_KEPT_MD5).await,
        "the kept object tag set",
    );
    accepted(
        &send(
            &service,
            http::Method::PUT,
            "/documents?versioning",
            VERSIONING_ENABLED,
            VERSIONING_ENABLED_MD5,
        )
        .await,
        "versioning",
    );
    let before = read_backs(&service).await;
    for (method, target) in [
        (http::Method::POST, "/documents?delete"),
        (http::Method::PUT, "/documents?cors"),
        (http::Method::PUT, "/documents?encryption"),
        (http::Method::PUT, "/documents?publicAccessBlock"),
        (http::Method::PUT, "/documents?tagging"),
        (http::Method::PUT, "/documents?versioning"),
        (http::Method::PUT, "/documents/key?tagging"),
    ] {
        let response = send(&service, method, target, "", EMPTY_MD5).await;
        let body = body_of(&response);
        assert_eq!(response.status(), 400, "{target}: {body}");
        assert!(body.contains("<Code>MissingRequestBodyError</Code>"), "{target}: {body}");
    }
    assert_eq!(read_backs(&service).await, before, "an empty body changed storage");
}

/// Negative — an empty multipart completion is `400 MalformedXML`, as the legacy stack reads it,
/// and the upload stays open with no object written.
#[tokio::test]
async fn n_an_empty_multipart_completion_is_malformed_and_completes_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    let created = exchange(&service, as_main(http::Method::POST, "/documents/parts?uploads", Bytes::new())).await;
    let created = body_of(&created);
    let upload_id = created
        .split_once("<UploadId>")
        .and_then(|(_, rest)| rest.split_once("</UploadId>"))
        .map(|(id, _)| id.to_owned())
        .unwrap_or_else(|| panic!("no upload id: {created}"));
    let target = format!("/documents/parts?uploadId={upload_id}");
    let response = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::POST,
            &target,
            Bytes::new(),
            &[("content-md5", EMPTY_MD5)],
        ),
    )
    .await;
    refused_as_malformed(&response, "an empty completion");
    let uploads = body_of(&get(&service, "/documents?uploads").await);
    assert!(uploads.contains(&upload_id), "the upload closed: {uploads}");
    assert_eq!(get(&service, "/documents/parts").await.status(), 404, "an object was written");
}

/// Negative — Legacy-compat (rustfs/backlog#2684): an empty lifecycle write is `400
/// InvalidArgument` with legacy RustFS's "Invalid argument." — legacy RustFS reads the document
/// as optional and its handler refuses none — and the stored configuration stays.
#[tokio::test]
async fn n_an_empty_lifecycle_write_is_the_handlers_invalid_argument_and_replaces_nothing() {
    let root = TestRoot::new();
    let service = bucket(&root).await;
    accepted(
        &send(&service, http::Method::PUT, "/documents?lifecycle", LIFECYCLE_KEPT, LIFECYCLE_KEPT_MD5).await,
        "the kept configuration",
    );
    let response = send(&service, http::Method::PUT, "/documents?lifecycle", "", EMPTY_MD5).await;
    let body = body_of(&response);
    assert_eq!(response.status(), 400, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert!(body.contains("<Message>Invalid argument.</Message>"), "{body}");
    let read = get(&service, "/documents?lifecycle").await;
    assert!(body_of(&read).contains("<ID>kept</ID>"), "{}", body_of(&read));
}
