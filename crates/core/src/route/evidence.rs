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

//! The AWS references every shadowing declaration cites, one constant per operation.
//!
//! Responsible for: the evidence URL constants of [`super::shadowing`]'s declaration table —
//! each one AWS's own page for the operation, with a one-sentence self-written summary of what
//! the page establishes about its selector. Split out of `shadowing.rs` when the declaration
//! table outgrew the 800-line file ceiling: the table is the reviewed content, and these are its
//! footnotes.
//! NOT responsible for: any declaration, policy or check — `shadowing.rs` owns those — and no
//! upstream prose: every summary here is written by this project.
//! Upstream: nothing. Downstream: `super::shadowing`, the only reader.

/// AWS's own reference for the server-side object copy.
pub(super) const COPY_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html \
     — a copy is a PUT to the destination key whose source is named by a header, and which carries no request body.";

/// AWS's own reference for the part copy.
pub(super) const UPLOAD_PART_COPY_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html \
     — a part copy is a part upload whose bytes come from a source object named by a header rather than from the body.";

/// AWS's own reference for the CORS document read.
pub(super) const GET_BUCKET_CORS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html \
     — GetBucketCors is selected by the ?cors subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the lifecycle document read.
pub(super) const GET_BUCKET_LIFECYCLE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html \
     — GetBucketLifecycleConfiguration is selected by the ?lifecycle subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the lifecycle document write.
pub(super) const PUT_BUCKET_LIFECYCLE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html \
     — PutBucketLifecycleConfiguration is selected by the ?lifecycle subresource on a bucket PUT and replaces the stored lifecycle document.";

/// AWS's own reference for the lifecycle document delete.
pub(super) const DELETE_BUCKET_LIFECYCLE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html \
     — DeleteBucketLifecycle is selected by the ?lifecycle subresource on a bucket DELETE and removes only the lifecycle document.";

/// AWS's own reference for the encryption document read.
pub(super) const GET_BUCKET_ENCRYPTION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html \
     — GetBucketEncryption is selected by the ?encryption subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the encryption document write.
pub(super) const PUT_BUCKET_ENCRYPTION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html \
     — PutBucketEncryption is selected by the ?encryption subresource on a bucket PUT and replaces the stored encryption document.";

/// AWS's own reference for the encryption document delete.
pub(super) const DELETE_BUCKET_ENCRYPTION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html \
     — DeleteBucketEncryption is selected by the ?encryption subresource on a bucket DELETE and removes only the encryption document.";

/// AWS's own reference for the replication document read.
pub(super) const GET_BUCKET_REPLICATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketReplication.html \
     — GetBucketReplication is selected by the ?replication subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the replication document write.
pub(super) const PUT_BUCKET_REPLICATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html \
     — PutBucketReplication is selected by the ?replication subresource on a bucket PUT and replaces the stored replication document.";

/// AWS's own reference for the replication document delete.
pub(super) const DELETE_BUCKET_REPLICATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html \
     — DeleteBucketReplication is selected by the ?replication subresource on a bucket DELETE and removes only the replication document.";

/// AWS's own reference for the bucket access-control read.
pub(super) const GET_BUCKET_ACL_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html \
     — GetBucketAcl is selected by the ?acl subresource on a bucket GET and answers with the access control policy document.";

/// AWS's own reference for the bucket access-control write.
pub(super) const PUT_BUCKET_ACL_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html \
     — PutBucketAcl is selected by the ?acl subresource on a bucket PUT and replaces the access control policy, from the body or from the ACL headers.";

/// AWS's own reference for the object access-control read.
pub(super) const GET_OBJECT_ACL_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html \
     — an ACL read is a GET to the object key carrying the ?acl subresource, and it answers with the access control policy rather than with the object.";

/// AWS's own reference for the object access-control write.
pub(super) const PUT_OBJECT_ACL_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAcl.html \
     — an ACL write is a PUT to the object key carrying the ?acl subresource, and its body is an AccessControlPolicy rather than object data.";

/// AWS's own reference for the operation selected by the `?location` subresource.
pub(super) const LOCATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html \
     — GetBucketLocation is selected by the ?location subresource alone and takes no other query input.";

/// AWS's own reference for the version listing.
pub(super) const VERSIONS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html \
     — ListObjectVersions is selected by the ?versions subresource and ignores query keys it does not define.";

/// AWS's own reference for the first key listing.
pub(super) const LIST_V1_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html \
     — ListObjects is what a GET on a bucket means when no other subresource claimed it, so it pins no query key.";

/// AWS's own reference for the second key listing.
pub(super) const LIST_V2_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html \
     — ListObjectsV2 is selected by list-type=2 and treats unrecognised query keys as inert.";

/// AWS's own reference for the in-progress upload listing.
pub(super) const UPLOADS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html \
     — ListMultipartUploads is selected by the ?uploads subresource and defines no other selector.";

/// AWS's own reference for the part upload.
pub(super) const UPLOAD_PART_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html \
     — a part upload is a PUT to the object key carrying the part number and the upload id as query parameters.";

/// AWS's own reference for the plain object write.
pub(super) const PUT_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html \
     — a plain object write is the same method and path with neither of those parameters.";

/// AWS's own reference for the completion of an upload.
pub(super) const COMPLETE_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html \
     — completion is a POST to the object key carrying the upload id.";

/// AWS's own reference for the initiation of an upload.
pub(super) const CREATE_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html \
     — initiation is a POST to the object key carrying the ?uploads subresource and no upload id.";

/// AWS's own reference for discarding an upload.
pub(super) const ABORT_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html \
     — an abort is a DELETE to the object key carrying the upload id as a query parameter.";

/// AWS's own reference for the plain object delete.
pub(super) const DELETE_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html \
     — an object delete is the same method and path with no upload id.";

/// AWS's own reference for the part listing.
pub(super) const LIST_PARTS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html \
     — a part listing is a GET to the object key carrying the upload id as a query parameter.";

/// AWS's own reference for the attributes read.
pub(super) const OBJECT_ATTRIBUTES_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html \
     — an attributes read is a GET to the object key carrying the ?attributes subresource, and it answers with metadata rather than with the object.";

/// AWS's own reference for the tag-set read.
pub(super) const GET_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html \
     — a tag-set read is a GET to the object key carrying the ?tagging subresource, and it answers with the tag set rather than with the object.";

/// AWS's own reference for the bucket-scope tag-set read.
pub(super) const GET_BUCKET_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html \
     — a bucket tag-set read is a GET on the bucket carrying the ?tagging subresource, and it defines no other selector.";

/// AWS's own reference for the bucket-scope tag-set replacement.
pub(super) const PUT_BUCKET_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html \
     — a bucket tag-set write is a PUT on the bucket carrying the ?tagging subresource, and its body is the tagging document.";

/// AWS's own reference for the bucket-scope tag-set removal.
pub(super) const DELETE_BUCKET_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html \
     — a bucket tag-set removal is a DELETE on the bucket carrying the ?tagging subresource, and it leaves the bucket in place.";

/// AWS's own reference for the CORS document write.
pub(super) const PUT_BUCKET_CORS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html \
     — a CORS configuration write is a PUT on the bucket carrying the ?cors subresource, and its body is the configuration document.";

/// AWS's own reference for the CORS document removal.
pub(super) const DELETE_BUCKET_CORS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html \
     — a CORS configuration removal is a DELETE on the bucket carrying the ?cors subresource.";

/// AWS's own reference for the tag-set replacement.
pub(super) const PUT_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html \
     — a tag-set write is a PUT to the object key carrying the ?tagging subresource, and its body is a tagging document rather than object data.";

/// AWS's own reference for the tag-set removal.
pub(super) const DELETE_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html \
     — a tag-set removal is a DELETE to the object key carrying the ?tagging subresource, and it leaves the object in place.";

/// AWS's own reference for the plain object read.
pub(super) const GET_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html \
     — an object read is the same method and path with no upload id.";

/// AWS's own reference for the bucket lock-configuration read.
pub(super) const GET_OBJECT_LOCK_CONFIGURATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html \
     — the lock-configuration read is a GET on the bucket carrying the ?object-lock subresource, and it defines no other selector.";

/// AWS's own reference for the bucket lock-configuration write.
pub(super) const PUT_OBJECT_LOCK_CONFIGURATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLockConfiguration.html \
     — the lock-configuration write is a PUT on the bucket carrying the ?object-lock subresource, and its body is the lock document.";

/// AWS's own reference for the retention read.
pub(super) const GET_OBJECT_RETENTION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html \
     — a retention read is a GET to the object key carrying the ?retention subresource, and it answers with the retention document rather than with the object.";

/// AWS's own reference for the retention write.
pub(super) const PUT_OBJECT_RETENTION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html \
     — a retention write is a PUT to the object key carrying the ?retention subresource, and its body is a Retention document rather than object data.";

/// AWS's own reference for the legal-hold read.
pub(super) const GET_OBJECT_LEGAL_HOLD_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLegalHold.html \
     — a legal-hold read is a GET to the object key carrying the ?legal-hold subresource, and it answers with the hold status rather than with the object.";

/// AWS's own reference for the legal-hold write.
pub(super) const PUT_OBJECT_LEGAL_HOLD_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLegalHold.html \
     — a legal-hold write is a PUT to the object key carrying the ?legal-hold subresource, and its body is a LegalHold document rather than object data.";

/// AWS's own reference for the archive retrieval.
pub(super) const RESTORE_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html \
     — a restore is a POST to the object key carrying the ?restore subresource, and its body is a RestoreRequest document rather than object data.";

/// AWS's own reference for the select query.
pub(super) const SELECT_OBJECT_CONTENT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_SelectObjectContent.html \
     — a select is a POST to the object key carrying ?select together with select-type=2, and it answers with a framed event stream rather than a document.";
/// AWS's own reference for the `GetBucketAccelerateConfiguration` operation.
pub(super) const GET_BUCKET_ACCELERATE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAccelerateConfiguration.html \
     — GetBucketAccelerateConfiguration is selected by the ?accelerate subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the `PutBucketAccelerateConfiguration` operation.
pub(super) const PUT_BUCKET_ACCELERATE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html \
     — PutBucketAccelerateConfiguration is selected by the ?accelerate subresource on a bucket PUT and replaces the stored acceleration document.";

/// AWS's own reference for the `GetBucketLogging` operation.
pub(super) const GET_BUCKET_LOGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html \
     — GetBucketLogging is selected by the ?logging subresource alone and answers with the stored logging document.";

/// AWS's own reference for the `PutBucketLogging` operation.
pub(super) const PUT_BUCKET_LOGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html \
     — PutBucketLogging is selected by the ?logging subresource on a bucket PUT and replaces the stored logging document.";

/// AWS's own reference for the `GetBucketNotificationConfiguration` operation.
pub(super) const GET_BUCKET_NOTIFICATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotificationConfiguration.html \
     — GetBucketNotificationConfiguration is selected by the ?notification subresource alone and answers with the stored notification document.";

/// AWS's own reference for the `PutBucketNotificationConfiguration` operation.
pub(super) const PUT_BUCKET_NOTIFICATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html \
     — PutBucketNotificationConfiguration is selected by the ?notification subresource on a bucket PUT and replaces the stored notification document.";

/// AWS's own reference for the `GetBucketPolicy` operation.
pub(super) const GET_BUCKET_POLICY_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html \
     — GetBucketPolicy is selected by the ?policy subresource alone and answers with the stored policy document as JSON.";

/// AWS's own reference for the `PutBucketPolicy` operation.
pub(super) const PUT_BUCKET_POLICY_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html \
     — PutBucketPolicy is selected by the ?policy subresource on a bucket PUT and replaces the stored policy document.";

/// AWS's own reference for the `DeleteBucketPolicy` operation.
pub(super) const DELETE_BUCKET_POLICY_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html \
     — DeleteBucketPolicy is selected by the ?policy subresource on a bucket DELETE and removes only the policy document.";

/// AWS's own reference for the `GetBucketPolicyStatus` operation.
pub(super) const GET_BUCKET_POLICY_STATUS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html \
     — GetBucketPolicyStatus is selected by the ?policyStatus subresource, which is a different key from ?policy and answers a different document.";

/// AWS's own reference for the `GetPublicAccessBlock` operation.
pub(super) const GET_PUBLIC_ACCESS_BLOCK_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html \
     — GetPublicAccessBlock is selected by the ?publicAccessBlock subresource alone and answers with the four stored switches.";

/// AWS's own reference for the `PutPublicAccessBlock` operation.
pub(super) const PUT_PUBLIC_ACCESS_BLOCK_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html \
     — PutPublicAccessBlock is selected by the ?publicAccessBlock subresource on a bucket PUT and replaces the four stored switches.";

/// AWS's own reference for the `DeletePublicAccessBlock` operation.
pub(super) const DELETE_PUBLIC_ACCESS_BLOCK_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html \
     — DeletePublicAccessBlock is selected by the ?publicAccessBlock subresource on a bucket DELETE and removes only those switches.";

/// AWS's own reference for the `GetBucketRequestPayment` operation.
pub(super) const GET_BUCKET_REQUEST_PAYMENT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketRequestPayment.html \
     — GetBucketRequestPayment is selected by the ?requestPayment subresource alone and answers with the stored payer.";

/// AWS's own reference for the `PutBucketRequestPayment` operation.
pub(super) const PUT_BUCKET_REQUEST_PAYMENT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketRequestPayment.html \
     — PutBucketRequestPayment is selected by the ?requestPayment subresource on a bucket PUT and replaces the stored payer.";

/// AWS's own reference for the `GetBucketVersioning` operation.
pub(super) const GET_BUCKET_VERSIONING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html \
     — GetBucketVersioning is selected by the ?versioning subresource alone and answers with the stored versioning state.";

/// AWS's own reference for the `PutBucketVersioning` operation.
pub(super) const PUT_BUCKET_VERSIONING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html \
     — PutBucketVersioning is selected by the ?versioning subresource on a bucket PUT and replaces the stored versioning state.";

/// AWS's own reference for the `GetBucketWebsite` operation.
pub(super) const GET_BUCKET_WEBSITE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html \
     — GetBucketWebsite is selected by the ?website subresource alone and answers with the stored website document.";

/// AWS's own reference for the `PutBucketWebsite` operation.
pub(super) const PUT_BUCKET_WEBSITE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html \
     — PutBucketWebsite is selected by the ?website subresource on a bucket PUT and replaces the stored website document.";

/// AWS's own reference for the `DeleteBucketWebsite` operation.
pub(super) const DELETE_BUCKET_WEBSITE_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketWebsite.html \
     — DeleteBucketWebsite is selected by the ?website subresource on a bucket DELETE and removes only the website document.";
